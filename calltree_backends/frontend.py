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
        method_filter = getattr(args, "method", None) or getattr(args, "il_method", None) or getattr(args, "native_function", None)
        patch_return = getattr(args, "patch_return", "auto")
        if patch_return == "auto":
            patch_return = getattr(args, "il_patch_return", "auto")
        if patch_return == "auto":
            patch_return = getattr(args, "native_patch_return", "auto")

        return cls(
            method_filter=method_filter,
            return_patch=bool(getattr(args, "return_patch", False) or getattr(args, "native_return_patch", False)),
            patch_return=patch_return,
            write_patch=bool(getattr(args, "write_patch", False) or getattr(args, "il_write_patch", False)),
            il_assembly=getattr(args, "il_assembly", None),
            il_dump=bool(getattr(args, "il_dump", False)),
            il_plan_patch=bool(getattr(args, "il_plan_patch", False)),
            force_low_confidence=bool(getattr(args, "force_low_confidence", False)),
            force_native_runtime=bool(getattr(args, "force_native_runtime", False)),
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
