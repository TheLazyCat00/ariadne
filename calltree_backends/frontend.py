"""Shared frontend contract and normalized analyzer options."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AnalyzerOptions:
    method_filter: str | None = None
    return_patch: bool = False
    patch_return: str = "auto"
    write_patch: bool = False
    il_assembly: str | None = None
    il_dump: bool = False
    il_plan_patch: bool = False
    force_low_confidence: bool = False
    force_native_runtime: bool = False

    @classmethod
    def from_args(cls, args) -> "AnalyzerOptions":
        return cls(
            method_filter=args.method,
            return_patch=bool(args.return_patch),
            patch_return=args.patch_return,
            write_patch=bool(args.write_patch),
            il_assembly=args.il_assembly,
            il_dump=bool(args.il_dump),
            il_plan_patch=bool(args.il_plan_patch),
            force_low_confidence=bool(args.force_low_confidence),
            force_native_runtime=bool(args.force_native_runtime),
        )

    @property
    def il_return(self) -> str:
        if self.patch_return in ("true", "false"):
            return self.patch_return
        if self.patch_return in ("zero", "one"):
            return "true" if self.patch_return == "one" else "false"
        return "auto"

    @property
    def native_return(self) -> str:
        if self.patch_return in ("zero", "one"):
            return self.patch_return
        if self.patch_return in ("true", "false"):
            return "one" if self.patch_return == "true" else "zero"
        return "auto"


class AnalyzerFrontend:
    """Documentation-only protocol for concrete analyzer frontends."""

    def report(self) -> bool:
        raise NotImplementedError

    def solve(self) -> bool:
        raise NotImplementedError

    def patch(self, out_arg=None) -> bool:
        raise NotImplementedError
