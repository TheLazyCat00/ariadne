"""Shared frontend contract and normalized analyzer options."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AnalyzerOptions:
    method_filter: str | None = None
    il_assembly: str | None = None
    il_dump: bool = False
    force_low_confidence: bool = False
    force_native_runtime: bool = False

    @classmethod
    def from_args(cls, args) -> "AnalyzerOptions":
        return cls(
            method_filter=args.method,
            il_assembly=args.il_assembly,
            il_dump=bool(args.il_dump),
            force_low_confidence=bool(args.force_low_confidence),
            force_native_runtime=bool(args.force_native_runtime),
        )


class AnalyzerFrontend:
    """Documentation-only protocol for concrete analyzer frontends."""

    def report(self) -> bool:
        raise NotImplementedError

    def solve(self) -> bool:
        raise NotImplementedError

    def plan_patch(self) -> bool:
        """Non-destructive preview of what patch() would write."""
        raise NotImplementedError

    def patch(self, out_arg=None) -> bool:
        raise NotImplementedError
