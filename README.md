# Ariadne

Research-oriented program-analysis tooling for native binaries and runtime-hosted
applications.

The tool routes targets to the appropriate frontend:

```text
native ELF/PE            -> angr call-tree backend
.NET apphost/managed PE  -> .NET IL frontend
future runtimes          -> dedicated frontend modules
```

See [`RESEARCH_INTENT.md`](RESEARCH_INTENT.md) for the project’s intended use and
ethical boundaries. This project is intended for
authorized research, education, defensive auditing, and owned/CTF/lab applications.
It is not intended for piracy, unauthorized license circumvention, or patched
third-party software distribution.

## Layout

```text
main.py                             # main CLI entrypoint
calltree_backends/
  native_angr.py                    # native angr backend
  dotnet_il.py                      # .NET IL frontend
  frontend.py                       # shared frontend options/interface
  outcomes.py                       # shared win/lose string heuristics
  gates.py                          # shared gate model + plan renderer (parity layer)
fixtures/                           # owned crackme fixtures for both backends
tests/                             # synthetic-IL regression tests (no SDK required)
```

## Install dependencies

Core native backend:

```bash
python -m pip install angr networkx
```

.NET IL metadata/frontend solver:

```bash
python -m pip install dnfile z3-solver
```

## Usage

Native or auto-routed analysis:

```bash
python main.py ./target --mode advise
python main.py ./target --mode solve
python main.py ./target --mode patch --out target.patched
```

Runtime report:

```bash
python main.py ./app.exe --mode runtime-report
```

.NET IL analysis:

```bash
python main.py ./App.exe \
  --frontend dotnet-il \
  --il-assembly ./App.dll \
  --mode solve \
  --method '(License|Trial|Activation|Product|Key|Check)'
```

Dump IL and preview the patch plan (writes nothing):

```bash
python main.py ./App.dll \
  --frontend dotnet-il \
  --mode plan-patch \
  --method CheckLabKey \
  --il-dump
```

The patch-related modes form an escalation that is identical on both backends:

```text
--mode advise       report only
--mode plan-patch   report + preview exactly which branches patch would flip (writes nothing)
--mode patch        report + write those flips toward the win side (original left untouched)
```

Other shared flags:

```text
--method REGEX_OR_ADDR       backend-neutral method/function selector (narrows solve/advise/patch)
--out PATH                   where to write the patched copy
--force-low-confidence       allow solve/patch even when the gate looks like noise
```

## License

GPL-3.0. See [`LICENSE`](LICENSE).
