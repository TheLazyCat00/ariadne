"""Backend-neutral gate model shared by the native and .NET frontends.

The *recovery* of a gate (typed-local def-use on IL vs dominance on a native CFG)
and the *writing* of a patch (IL bytes vs x86 branch forcing) are backend-specific
and stay in each backend. What is genuinely identical -- and therefore lives here
-- is the policy and the reporting:

  * how a gate's two sides are weighed by how much code each blocks (significance);
  * which side is the licensed/win side;
  * the vocabulary of a gate candidate (tainted? source? flows through a helper we
    must NOT patch? what gets forced, and to what constant?);
  * the exact plan/preview text, so both backends print parity output.

This keeps the two frontends "at the same level" without pretending native has
typed booleans it does not.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class GateCandidate:
    """One gatekeeping decision recovered by a backend, in neutral terms."""
    backend: str                              # "native" | "dotnet"
    unit: str                                 # method / function the gate lives in
    kind: str                                 # "typed-local" | "inlined" | "dominance"
    gate_locator: str                         # e.g. "local 1" or "je @ 0x4011ad"
    gate_sites: List[str] = field(default_factory=list)   # the shared branch sites
    tainted: bool = False                     # condition derives from an external source
    source: Optional[str] = None              # the source it is tainted by
    flows_through: List[str] = field(default_factory=list)  # helpers we do NOT patch
    licensed_side: Optional[str] = None       # human label of the win side
    win_strings: List[str] = field(default_factory=list)
    significance: Optional[float] = None       # fraction of unit/program code blocked
    patch_target: str = ""                    # what a patch would force / neutralize
    force_value: Optional[str] = None         # resolved constant, or None if deferred
    notes: List[str] = field(default_factory=list)


def significance(blocked: int, total: int) -> float:
    """Fraction of code the gated side unlocks, relative to the whole unit. This is
    the 'how much does each side block relative to the total' signal, normalized so
    native (CFG blocks) and .NET (reachable IL slice) report comparable numbers."""
    total = total or 1
    return max(0.0, min(1.0, blocked / float(total)))


def pick_licensed(score_a: float, label_a: str, score_b: float, label_b: str):
    """Pick the licensed side as the one unblocking more code / carrying win logic.
    Returns (label, won_by_margin)."""
    if score_a >= score_b:
        return label_a, score_a - score_b
    return label_b, score_b - score_a


def _fmt_pct(x: Optional[float]) -> str:
    return "n/a" if x is None else "%d%%" % round(100 * x)


def render_plan(title: str, candidates: List[GateCandidate], plan_only: bool = True) -> bool:
    """Uniform, non-destructive plan/preview printer for either backend.
    Returns True iff at least one candidate was rendered."""
    print()
    print("=" * 66)
    print("  " + title)
    print("=" * 66)
    if not candidates:
        print("  no source-tainted, gate-only condition isolated")
        return False
    for c in candidates:
        print("  %s: gate = %s  [%s, %s]"
              % (c.unit, c.gate_locator, c.kind,
                 "source-tainted" if c.tainted else "taint UNCONFIRMED"))
        if c.source:
            print("    tainted by   : %s" % c.source)
        if c.gate_sites:
            print("    gate sites   : %s" % ", ".join(c.gate_sites))
        if c.significance is not None:
            print("    blocks       : %s of unit code on the locked side" % _fmt_pct(c.significance))
        if c.flows_through:
            print("    flows through: %s (helper is NOT patched; only the gate's own value)"
                  % ", ".join(c.flows_through))
        if c.licensed_side:
            msg = "    licensed side: %s" % c.licensed_side
            if c.win_strings:
                msg += "  (win strings: %s)" % ", ".join(repr(w) for w in c.win_strings[:2])
            print(msg)
        print("    patch target : %s" % (c.patch_target or "(unresolved)"))
        if c.force_value is not None:
            print("    force value  : %s" % c.force_value)
        for n in c.notes:
            print("    note         : %s" % n)
    if plan_only:
        print("  status: preview only; no bytes written.")
    return True
