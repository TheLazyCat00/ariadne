#!/usr/bin/env python3
"""calltree_triage - native angr + runtime frontend router.

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
from calltree_backends.frontend import AnalyzerOptions

def hr(t): print("\n"+"="*66+"\n  "+t+"\n"+"="*66)


def _runtime_frontend_cls(frontend: str, runtime_kind: str, binary: str, rt: dict, options: AnalyzerOptions):
    if frontend == "dotnet-il":
        return DotNetILFrontend(binary, rt, options=options)
    if frontend == "auto" and runtime_kind != "native":
        return select_runtime_frontend(runtime_kind, binary, rt, options=options)
    return None

def build_arg_parser():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--mode", choices=["advise", "solve", "patch", "runtime-report"], default="advise")
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
    ap.add_argument("--il-plan-patch", action="store_true", help="print a non-destructive IL branch rewrite plan")
    ap.add_argument("--write-patch", action="store_true", help="write a patched copy")
    ap.add_argument("--return-patch", action="store_true", help="patch/plan a function or method return override")
    ap.add_argument("--patch-return", choices=["auto","true","false","zero","one"], default="auto", help="return value for --return-patch; auto infers from win/lose paths")
    # Compatibility aliases kept for existing scripts; prefer the shared flags above.
    ap.add_argument("--il-method", default=None, help=argparse.SUPPRESS)
    ap.add_argument("--il-write-patch", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--il-patch-return", choices=["auto","true","false"], default="auto", help=argparse.SUPPRESS)
    ap.add_argument("--native-function", default=None, help=argparse.SUPPRESS)
    ap.add_argument("--native-return-patch", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--native-patch-return", choices=["auto","zero","one"], default="auto", help=argparse.SUPPRESS)
    ap.add_argument("--force-low-confidence", action="store_true", help="allow solve/patch even when the dominance gate looks like noise")
    ap.add_argument("--force-native-runtime", action="store_true", help="run native solve/patch even when the binary appears to be a runtime host")
    return ap


def main(argv=None):
    args = build_arg_parser().parse_args(argv)

    options = AnalyzerOptions.from_args(args)

    # Import angr-backed native code lazily so `--help` and pure metadata tooling
    # do not initialize angr/unicorn unless a target is actually analyzed.
    from calltree_backends.native_angr import NativeAngrFrontend, print_runtime_report

    native = NativeAngrFrontend(args.binary, options=options)
    native.header(args.mode)
    native.print_objects()

    rt = native.runtime_info()
    runtime_kind = rt.get("kind", "native")
    runtime_host = runtime_kind != "native"
    runtime_frontend = _runtime_frontend_cls(args.frontend, runtime_kind, args.binary, rt, options)

    if runtime_host or args.mode == "runtime-report" or args.frontend == "dotnet-il":
        print_runtime_report(rt)

    if runtime_frontend and args.mode == "runtime-report":
        runtime_frontend.report()
        print()
        return 0
    if args.mode == "runtime-report":
        print()
        return 0

    # Managed/runtime frontend takes precedence unless the user explicitly asks
    # for native angr. This keeps .NET apphost/CoreCLR bootstrap branches out of
    # the native solver by default.
    if runtime_frontend and args.frontend != "native-angr":
        if args.mode == "advise":
            runtime_frontend.report()
        elif args.mode == "solve":
            runtime_frontend.solve()
        elif args.mode == "patch":
            runtime_frontend.patch(args.out)
        print()
        return 0

    if runtime_host and args.mode in ("solve", "patch") and not options.force_native_runtime:
        print("  refusing to %s the native CFG because this looks like a %s runtime host;" % (args.mode, runtime_kind))
        print("  the native call tree is probably bootstrap/runtime code, not the app logic.")
        print("  Use --frontend auto/dotnet-il for managed analysis, or rerun with")
        print("  --force-native-runtime only for authorized runtime-level research.")
        print()
        return 1

    if args.mode == "advise":
        native.report()
    elif args.mode == "solve":
        native.solve()
    elif args.mode == "patch":
        native.patch(out_arg=args.out)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
