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

Dump IL and print a non-destructive patch plan:

```bash
python main.py ./App.dll \
  --frontend dotnet-il \
  --mode advise \
  --method CheckLabKey \
  --il-dump \
  --il-plan-patch
```

Shared patch flags:

```text
--method REGEX_OR_ADDR       backend-neutral method/function selector
--return-patch               patch/plan a function or method return override
--patch-return auto|...      infer by default, or force true/false/zero/one
--write-patch                actually write a patched copy
```

All flags are backend-neutral and shared across the native and IL frontends. Without `--write-patch`, patch-capable backends print dry-run plans where possible.

## License

GPL-3.0. See [`LICENSE`](LICENSE).
