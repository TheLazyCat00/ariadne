#!/usr/bin/env python3
"""Ariadne - native angr + runtime frontend router.

Native ELF/PE targets are analyzed with the angr backend. Runtime-hosted targets
(currently .NET apphosts / managed PE) are routed to a specialized runtime
frontend so the tool analyzes application IL instead of bootstrap code.
"""
from __future__ import annotations

import argparse
import os
import sys

# Workspace-local backend package.
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from calltree_backends.dotnet_il import DotNetILFrontend, select_runtime_frontend
from calltree_backends.frontend import AnalyzerFrontend, AnalyzerOptions


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="ariadne")
    ap.add_argument("binary")
    ap.add_argument("--mode", choices=["advise", "solve", "plan-patch", "patch", "runtime-report"], default="advise",
                    help="advise=report; plan-patch=preview the branches patch would flip (writes nothing); patch=write them")
    ap.add_argument("--out", default=None)
    ap.add_argument(
        "--frontend",
        choices=["auto", "native-angr", "dotnet-il"],
        default="auto",
        help="analysis frontend: auto routes .NET to IL and native targets to angr",
    )
    ap.add_argument("--il-assembly", default=None, help="managed .NET assembly to analyze when using the dotnet-il frontend")
    ap.add_argument("--method", default=None, help="backend-neutral method/function regex or native address filter")
    ap.add_argument("--il-dump", action="store_true", help="dump decoded IL for matching managed methods")
    ap.add_argument("--force-low-confidence", action="store_true", help="allow solve/patch even when the dominance gate looks like noise")
    ap.add_argument("--force-native-runtime", action="store_true", help="run native solve/patch even when the binary appears to be a runtime host")
    return ap


def _select_runtime_frontend(frontend: str, runtime_kind: str, binary: str, rt: dict,
                             options: AnalyzerOptions) -> AnalyzerFrontend | None:
    """Pick the runtime/managed frontend for this target, or None for native."""
    if frontend == "dotnet-il":
        return DotNetILFrontend(binary, rt, options=options)
    if frontend == "auto" and runtime_kind != "native":
        return select_runtime_frontend(runtime_kind, binary, rt, options=options)
    return None


def _run_mode(frontend: AnalyzerFrontend, mode: str, out: str | None) -> None:
    """Dispatch a mode to a frontend's shared interface."""
    if mode == "solve":
        frontend.solve()
    elif mode == "patch":
        frontend.patch(out)
    elif mode == "plan-patch":
        frontend.plan_patch()
    else:  # advise
        frontend.report()


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)
    options = AnalyzerOptions.from_args(args)

    # argparse accepts an empty string for a required positional, so an unset
    # shell variable (`ariadne "$BINARY"`) reaches us as "". Validate up front
    # with a clear message instead of crashing deep inside angr's loader.
    target = args.binary
    if not target or not target.strip():
        print("ariadne: error: no target binary given (empty path)", file=sys.stderr)
        return 2
    if not os.path.isfile(target):
        print("ariadne: error: target binary not found: %r" % target, file=sys.stderr)
        return 2

    # Import angr-backed native code lazily so `--help` and pure metadata tooling
    # do not initialize angr/unicorn unless a target is actually analyzed.
    from calltree_backends.native_angr import NativeAngrFrontend, print_runtime_report

    native = NativeAngrFrontend(args.binary, options=options)
    native.header(args.mode)
    native.print_objects()

    rt = native.runtime_info()
    runtime_kind = rt.get("kind", "native")
    runtime_host = runtime_kind != "native"
    runtime_frontend = _select_runtime_frontend(args.frontend, runtime_kind, args.binary, rt, options)

    if runtime_host or args.mode == "runtime-report" or args.frontend == "dotnet-il":
        print_runtime_report(rt)

    if args.mode == "runtime-report":
        if runtime_frontend:
            runtime_frontend.report()
        print()
        return 0

    # Managed/runtime frontend takes precedence unless the user explicitly asks
    # for native angr. This keeps .NET apphost/CoreCLR bootstrap branches out of
    # the native solver by default.
    if runtime_frontend and args.frontend != "native-angr":
        _run_mode(runtime_frontend, args.mode, args.out)
        print()
        return 0

    if runtime_host and args.mode in ("solve", "patch") and not options.force_native_runtime:
        print("  refusing to %s the native CFG because this looks like a %s runtime host;" % (args.mode, runtime_kind))
        print("  the native call tree is probably bootstrap/runtime code, not the app logic.")
        print("  Use --frontend auto/dotnet-il for managed analysis, or rerun with")
        print("  --force-native-runtime only for authorized runtime-level research.")
        print()
        return 1

    _run_mode(native, args.mode, args.out)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
