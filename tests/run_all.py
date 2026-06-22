#!/usr/bin/env python3
"""Discover and run every tests/test_*.py module in sequence. Each module is
expected to exit 0 on success, nonzero on failure. Prints a final summary."""
import os, sys, subprocess, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def main():
    tests = sorted(f for f in os.listdir(HERE)
                   if f.startswith("test_") and f.endswith(".py"))
    results = []
    total_start = time.time()
    for t in tests:
        path = os.path.join(HERE, t)
        print("\n" + "#" * 66)
        print("# " + t)
        print("#" * 66)
        t0 = time.time()
        p = subprocess.run([sys.executable, path], cwd=ROOT)
        dt = time.time() - t0
        results.append((t, p.returncode, dt))

    print("\n" + "=" * 66)
    print(" TEST SUMMARY  ({:.2f}s total)".format(time.time() - total_start))
    print("=" * 66)
    failed = 0
    for t, rc, dt in results:
        tag = "PASS" if rc == 0 else "FAIL"
        if rc != 0: failed += 1
        print("  {:4s}  {:>6.2f}s  {}".format(tag, dt, t))
    print("=" * 66)
    if failed:
        print("  {} of {} test modules FAILED".format(failed, len(results)))
        return 1
    print("  all {} test modules passed".format(len(results)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
