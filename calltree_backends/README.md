# Analyzer Backend Modules

This directory starts the split from the original monolithic `calltree_triage_new.py`, now wrapped by `main.py` into separate analyzer backends.

Current modules:

- `dotnet_il.py` — managed .NET/CLI metadata and IL frontend. It handles assembly discovery, raw/metadata string extraction, CIL decoding, method filtering, IL dumps, constraint-shape reporting, and non-destructive IL patch plans.
- `fixture.py` — fixture-manifest loading and SHA-256 verification for authorized lab samples.

The native angr backend now lives in `native_angr.py`; `uploads/calltree_triage_new.py` remains only as a backward-compatible wrapper.

Intended long-term interface:

```python
class AnalyzerFrontend:
    def report(self) -> bool: ...
    def solve(self) -> bool: ...
    def patch(self, out_arg=None) -> bool: ...
```

Routing policy:

```text
native ELF/PE            -> native_angr frontend
.NET apphost/managed PE  -> dotnet_il frontend
future JVM/Python/JS/etc -> dedicated runtime frontend
```
