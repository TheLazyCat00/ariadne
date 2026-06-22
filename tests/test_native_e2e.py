"""End-to-end native backend tests. Skipped when angr/gcc isn't available.

These compile the bundled native fixtures and run main.py against them in each
mode (advise / plan-patch / patch / runtime-report), asserting that the tool
exits cleanly and produces the expected sections in stdout.
"""
import os, sys, subprocess, tempfile, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAILS = []
SKIPS = []


def check(cond, msg):
    if not cond: FAILS.append(msg); print("  FAIL:", msg)
    else: print("  ok  :", msg)


def have(cmd): return shutil.which(cmd) is not None

def try_import(mod):
    try:
        __import__(mod); return True
    except Exception: return False


def compile_fixture(src, out):
    p = subprocess.run(["gcc", src, "-o", out, "-O0", "-no-pie"],
                       capture_output=True, text=True)
    return p.returncode == 0


def run_ariadne(args, timeout=240):
    cmd = [sys.executable, os.path.join(ROOT, "main.py")] + args
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def test_advise_runs_on_native_flag():
    src = os.path.join(ROOT, "fixtures", "native_flag", "flag_native.c")
    with tempfile.TemporaryDirectory() as d:
        b = os.path.join(d, "flag_native")
        if not compile_fixture(src, b):
            SKIPS.append("gcc compile failed"); print("  skip: gcc failed"); return
        rc, out, err = run_ariadne([b, "--mode", "advise"])
        check(rc == 0, "advise exit 0, got %r; stderr=%s" % (rc, err[-200:]))
        check("CALL-TREE OBJECTS" in out, "CALL-TREE OBJECTS section present")
        check("GATE BY DOMINANCE" in out, "GATE BY DOMINANCE section present")


def test_plan_patch_runs_on_native_flag():
    src = os.path.join(ROOT, "fixtures", "native_flag", "flag_native.c")
    with tempfile.TemporaryDirectory() as d:
        b = os.path.join(d, "flag_native")
        if not compile_fixture(src, b):
            SKIPS.append("gcc compile failed"); print("  skip: gcc failed"); return
        rc, out, err = run_ariadne([b, "--mode", "plan-patch"])
        check(rc == 0, "plan-patch exit 0, got %r" % rc)
        check("PATCH PLAN" in out, "PATCH PLAN section present")
        check("preview only" in out, "preview-only footer present")


def test_patch_writes_to_out_path():
    src = os.path.join(ROOT, "fixtures", "native_flag", "flag_native.c")
    with tempfile.TemporaryDirectory() as d:
        b = os.path.join(d, "flag_native")
        out_path = os.path.join(d, "flag_native.patched")
        if not compile_fixture(src, b):
            SKIPS.append("gcc compile failed"); print("  skip: gcc failed"); return
        rc, out, err = run_ariadne([b, "--mode", "patch", "--out", out_path])
        check(rc == 0, "patch exit 0, got %r" % rc)
        check(os.path.exists(out_path), "patched file written at --out path")
        # Length-preserving: in-place x86 patch should keep file size.
        check(os.path.getsize(out_path) == os.path.getsize(b),
              "patched binary same size as original")
        check(os.path.getsize(b) > 0, "original is non-empty")


def main():
    if not have("gcc"):
        print("SKIP all native_e2e tests: gcc not available"); return 0
    if not try_import("angr"):
        print("SKIP all native_e2e tests: angr not installed"); return 0
    fns = [test_advise_runs_on_native_flag, test_plan_patch_runs_on_native_flag,
           test_patch_writes_to_out_path]
    for fn in fns:
        print("\n--", fn.__name__); fn()
    if FAILS:
        print("\nNATIVE-E2E: %d failure(s)" % len(FAILS))
        for f in FAILS: print("  -", f)
        return 1
    print("\nNATIVE-E2E: all OK (%d skip)" % len(SKIPS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
