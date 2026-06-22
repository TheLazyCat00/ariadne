"""CLI argument validation tests for main.py. These do not require angr (the
import is lazy and we never reach it because validation rejects bad inputs)."""
import os, sys, tempfile, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FAILS = []
def check(cond, msg):
    if not cond: FAILS.append(msg); print("  FAIL:", msg)
    else: print("  ok  :", msg)


def run(args, env=None):
    cmd = [sys.executable, os.path.join(ROOT, "main.py")] + args
    p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    return p.returncode, p.stdout, p.stderr


def test_help_works_without_angr():
    """--help must not trigger any heavy imports and must exit 0."""
    rc, out, err = run(["--help"])
    check(rc == 0, "--help exit 0, got %r; err=%s" % (rc, err))
    check("ariadne" in out, "--help mentions program name")
    check("--mode" in out, "--help mentions --mode")
    check("--frontend" in out, "--help mentions --frontend")


def test_empty_target_path_rejected():
    rc, out, err = run([""])
    check(rc == 2, "empty target path exits 2, got %r" % rc)
    check("no target binary" in err, "stderr mentions empty target: %r" % err)


def test_missing_target_path_rejected():
    rc, out, err = run(["/this/does/not/exist.exe"])
    check(rc == 2, "missing target path exits 2, got %r" % rc)
    check("not found" in err, "stderr mentions not found: %r" % err)


def test_directory_target_rejected():
    with tempfile.TemporaryDirectory() as d:
        rc, out, err = run([d])
        check(rc == 2, "directory as target exits 2, got %r" % rc)
        check("not a regular file" in err, "stderr mentions non-regular file: %r" % err)


def test_no_positional_argument_errors():
    rc, out, err = run([])
    # argparse error exit code is 2.
    check(rc == 2, "missing positional exits 2, got %r" % rc)


def main():
    for fn in [test_help_works_without_angr, test_empty_target_path_rejected,
               test_missing_target_path_rejected, test_directory_target_rejected,
               test_no_positional_argument_errors]:
        print("\n--", fn.__name__); fn()
    if FAILS:
        print("\nCLI: %d failure(s)" % len(FAILS))
        for f in FAILS: print("  -", f)
        return 1
    print("\nCLI: all OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
