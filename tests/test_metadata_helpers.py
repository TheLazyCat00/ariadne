"""Tests for the small metadata-side helpers: payload candidates, framework
filtering, .NET-magic detection, and raw-string extraction."""
import os, sys, tempfile, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from calltree_backends.dotnet_il import (
    _raw_strings, _is_dotnet_cli_file, _dotnet_is_framework_or_runtime_assembly,
    _dotnet_payload_candidates,
)

FAILS = []
def check(cond, msg):
    if not cond: FAILS.append(msg); print("  FAIL:", msg)
    else: print("  ok  :", msg)


def test_raw_strings_extracts_ascii_and_utf16():
    # ASCII run
    data = b"\x00\x00hello world\x00\x00short\x00"
    s = _raw_strings(data, minlen=4)
    check("hello world" in s, "ascii string extracted")
    check("short" in s, "second ascii string extracted")

    # UTF-16LE run: 'OK' = O\0 K\0
    utf16 = "License accepted welcome".encode("utf-16-le")
    data2 = b"\x01\x02" + utf16 + b"\x00\x01"
    s2 = _raw_strings(data2, minlen=4)
    check(any("License accepted welcome" in x for x in s2),
          "utf-16le string surfaced (got %r)" % s2)


def test_raw_strings_min_length_respected():
    s = _raw_strings(b"ab\x00cdef\x00gh", minlen=4)
    check("cdef" in s, "len>=4 included")
    check("ab" not in s, "len<4 excluded")


def test_is_dotnet_cli_file_detects_bsjb():
    # A blob with the uppercase BSJB (.NET metadata) marker should be flagged
    # as CLI-ish. Regression: prior to a one-line fix, this used a lowercase
    # `b"bsjb" in data` check that NEVER matched the real magic (which is
    # always uppercase in the spec), silently breaking payload discovery for
    # every real .NET assembly that happened not to import mscoree.dll.
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"\x00" * 1024 + b"BSJB" + b"\x01\x02\x03\x04")
        p = f.name
    try:
        check(_is_dotnet_cli_file(p), "file with BSJB magic detected as .NET CLI")
    finally:
        os.unlink(p)


def test_is_dotnet_cli_file_detects_mscoree_import():
    # An apphost-style PE that does not carry BSJB itself but imports
    # mscoree.dll should still be picked up by the case-insensitive branch.
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"MZ" + b"\x00" * 500 + b"mscoree.dll\x00" + b"\x00" * 200)
        p = f.name
    try:
        check(_is_dotnet_cli_file(p), "file importing mscoree.dll detected as .NET CLI")
    finally:
        os.unlink(p)


def test_is_dotnet_cli_file_rejects_random():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"\x7fELF" + b"\x00" * 1024)
        p = f.name
    try:
        check(not _is_dotnet_cli_file(p), "ELF-like file not detected as CLI")
    finally:
        os.unlink(p)


def test_is_dotnet_cli_file_missing_file_safe():
    # read_file_prefix swallows errors and returns b""; should be False.
    check(not _is_dotnet_cli_file("/nonexistent/path/xyz123.exe"),
          "missing file returns False (no crash)")


def test_framework_assembly_filter_known_names():
    check(_dotnet_is_framework_or_runtime_assembly("/x/System.Runtime.dll"),
          "System.Runtime.dll filtered as framework")
    check(_dotnet_is_framework_or_runtime_assembly("/x/Microsoft.AspNetCore.dll"),
          "Microsoft.* filtered as framework")
    check(_dotnet_is_framework_or_runtime_assembly("/x/coreclr.dll"),
          "coreclr.dll filtered as runtime")
    check(not _dotnet_is_framework_or_runtime_assembly("/x/MyApp.dll"),
          "MyApp.dll is not framework")


def test_framework_filter_respects_app_primary():
    # Even with a System.* name, if it IS the app primary, we keep it.
    check(not _dotnet_is_framework_or_runtime_assembly("/x/System.MyShim.dll", app_primary="/x/System.MyShim.dll"),
          "explicit app primary not filtered even with system.* prefix")


def test_payload_candidates_prefers_basename_dll():
    """basename.dll alongside the apphost EXE should sort first."""
    with tempfile.TemporaryDirectory() as d:
        host = os.path.join(d, "MyApp.exe")
        primary = os.path.join(d, "MyApp.dll")
        other = os.path.join(d, "MyLib.dll")
        # Apphost: not CLI. Payloads: minimal BSJB stub so detection passes.
        with open(host, "wb") as f:
            f.write(b"MZ" + b"\x00" * 64)
        with open(primary, "wb") as f:
            f.write(b"BSJB" + b"\x00" * 512)
        with open(other, "wb") as f:
            f.write(b"BSJB" + b"\x00" * 512)
        cands = _dotnet_payload_candidates(host, rt={})
        check(primary in cands, "primary .dll discovered: %r" % cands)
        check(other in cands, "other .dll also discovered: %r" % cands)
        check(cands[0] == primary, "primary sorted first, got %r" % cands)


def test_payload_candidates_explicit_overrides_filter():
    """If the user passes --il-assembly explicitly, even a framework-named DLL
    should be selected."""
    with tempfile.TemporaryDirectory() as d:
        host = os.path.join(d, "MyApp.exe")
        sysdll = os.path.join(d, "System.Custom.dll")
        with open(host, "wb") as f:
            f.write(b"MZ" + b"\x00" * 64)
        with open(sysdll, "wb") as f:
            f.write(b"BSJB" + b"\x00" * 512)
        cands = _dotnet_payload_candidates(host, rt={}, explicit=sysdll)
        check(sysdll in cands, "explicit framework-named dll selected: %r" % cands)
        # And without explicit, it would be filtered out:
        cands2 = _dotnet_payload_candidates(host, rt={})
        check(sysdll not in cands2, "without explicit, filtered: %r" % cands2)


def main():
    fns = [test_raw_strings_extracts_ascii_and_utf16, test_raw_strings_min_length_respected,
           test_is_dotnet_cli_file_detects_bsjb, test_is_dotnet_cli_file_detects_mscoree_import,
           test_is_dotnet_cli_file_rejects_random,
           test_is_dotnet_cli_file_missing_file_safe, test_framework_assembly_filter_known_names,
           test_framework_filter_respects_app_primary, test_payload_candidates_prefers_basename_dll,
           test_payload_candidates_explicit_overrides_filter]
    for fn in fns:
        print("\n--", fn.__name__); fn()
    if FAILS:
        print("\nMETA: %d failure(s)" % len(FAILS))
        for f in FAILS: print("  -", f)
        return 1
    print("\nMETA: all OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
