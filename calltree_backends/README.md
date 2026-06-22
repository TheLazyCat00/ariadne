# Analyzer Backend Modules

This directory starts the split from the original monolithic `calltree_triage_new.py`, now wrapped by `main.py` into separate analyzer backends.

Current modules:

- `dotnet_il.py` — managed .NET/CLI metadata and IL frontend. It handles assembly discovery, raw/metadata string extraction, full ECMA-335 CIL decoding, method filtering, IL dumps, constraint-shape reporting, a bounded symbolic IL executor, and an in-place branch-flip patch writer that mirrors the native backend (neutralize failure-only conditional branches toward the win side, stack-balanced via `pop`+`nop`). `--mode plan-patch` previews the flips non-destructively (the native backend implements the same mode).
- `frontend.py` - shared analyzer option normalization and frontend contract.
- `outcomes.py` — shared win/lose string heuristics used by native and IL frontends as semantic anchors.
- `gates.py` — shared, dependency-free gate model: the `GateCandidate` dataclass, the "code blocked relative to total" significance scoring, and the single `render_plan` printer. This is the identical *policy and reporting* layer; both backends lower their own findings into `GateCandidate`s and render them the same way.

## Tainted-gate analysis (shared vs backend-specific)

Both backends expose a tainted-gate plan (in `--mode plan-patch`) that finds the gatekeeping condition, confirms it derives from an external source, and reports what a patch would force. The split is deliberate:

```text
SHARED (gates.py)          GateCandidate, significance(), pick_licensed(), render_plan()
.NET-specific (dotnet_il)  typed-local def-use + bool-typing, inlined-gate detection,
                           helper-aware force-constant resolution (a small IL evaluator
                           run on {0,1} through overloaded helpers like Flip), and the
                           length-preserving IL def-site writer (nop pad + ldc.i4.<const>)
native-specific (native)   dominance gate recovery + dominator-chain taint qualification
                           (a source-API call site must dominate the gate), and x86
                           branch forcing
```

Native has no typed booleans (C/C++ name-mangling makes the .NET overload trick moot), so it stays branch-level — captured in the shared model as `force_value=None`. The .NET path can instead force a single boolean local's definition so one byte-safe write opens every gate that shares it, without ever patching an overloaded helper the value merely flows through.

The native angr backend now lives in `native_angr.py`; both shipped backends consume `AnalyzerOptions` and expose `report()`, `solve()`, `plan_patch()`, and `patch()`. The old upload wrapper has been removed; use `main.py`.

Shared interface and flag model:

```python
class AnalyzerFrontend:
    def report(self) -> bool: ...
    def solve(self) -> bool: ...
    def plan_patch(self) -> bool: ...   # report + non-destructive patch preview
    def patch(self, out_arg=None) -> bool: ...
```

Common CLI flags are normalized by `main.py` before dispatch:

```text
--method               -> IL method filter or native function filter/address (narrows solve/advise/patch)
--out                  -> path for the patched copy
--force-low-confidence -> allow solve/patch past the low-confidence gate guard
```

The patch-related modes are identical on both backends and escalate cleanly:
`advise` (report) -> `plan-patch` (report + preview the branches patch would
flip, writes nothing) -> `patch` (report + write those flips toward the win
side; the original is left untouched).

Routing policy:

```text
native ELF/PE            -> native_angr frontend (dominance/outcome-sink branch flips)
.NET apphost/managed PE  -> dotnet_il frontend
future JVM/Python/JS/etc -> dedicated runtime frontend
```
