# Analyzer Backend Modules

This directory starts the split from the original monolithic `calltree_triage_new.py`, now wrapped by `main.py` into separate analyzer backends.

Current modules:

- `dotnet_il.py` — managed .NET/CLI metadata and IL frontend. It handles assembly discovery, raw/metadata string extraction, CIL decoding, method filtering, IL dumps, constraint-shape reporting, a bounded symbolic IL executor, dry-run patch plans, bool return-value inference from IL win/lose paths and caller branch use, and method-body replacement for owned/generated samples.
- `frontend.py` - shared analyzer option normalization and frontend contract.
- `outcomes.py` — shared win/lose string heuristics used by native and IL frontends as semantic anchors.

The native angr backend now lives in `native_angr.py`; both shipped backends consume `AnalyzerOptions` and expose `report()`, `solve()`, and `patch()`. The old upload wrapper has been removed; use `main.py`.

Shared interface and flag model:

```python
class AnalyzerFrontend:
    def report(self) -> bool: ...
    def solve(self) -> bool: ...
    def patch(self, out_arg=None) -> bool: ...
```

Common CLI flags are normalized by `main.py` before dispatch:

```text
--method          -> IL method filter or native function filter/address
--return-patch    -> return override patch/plan where supported
--patch-return    -> auto/explicit return value
--write-patch     -> write artifact
```

Routing policy:

```text
native ELF/PE            -> native_angr frontend (dominance gates return-stub inference)
.NET apphost/managed PE  -> dotnet_il frontend
future JVM/Python/JS/etc -> dedicated runtime frontend
```
