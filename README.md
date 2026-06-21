# Ariadne

Research-oriented program-analysis tooling for native binaries and runtime-hosted
applications.

The tool routes targets to the appropriate frontend:

```text
native ELF/PE            -> angr call-tree backend
.NET apphost/managed PE  -> .NET IL frontend
future runtimes          -> dedicated frontend modules
```

See [`RESEARCH_INTENT.md`](RESEARCH_INTENT.md) for the project’s intended use,
ethical boundaries, and fixture-manifest model. This project is intended for
authorized research, education, defensive auditing, and owned/CTF/lab fixtures.
It is not intended for piracy, unauthorized license circumvention, or patched
third-party software distribution.

## Layout

```text
main.py                             # main CLI entrypoint
calltree_backends/
  native_angr.py                    # native angr backend
  dotnet_il.py                      # .NET IL frontend
  fixture.py                        # fixture manifest verification
fixtures/dotnet_il_gate_demo/       # owned/generated .NET IL test fixture
uploads/calltree_triage_new.py      # compatibility wrapper for old filename
```

## Install dependencies

Core native backend:

```bash
python -m pip install angr networkx
```

.NET IL metadata frontend:

```bash
python -m pip install dnfile
```

The .NET demo fixture requires a local .NET SDK only if you want to build it:

```bash
dotnet --version
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
  --il-method '(License|Trial|Activation|Product|Key|Check)'
```

Dump IL and print a non-destructive patch plan:

```bash
python main.py ./App.dll \
  --frontend dotnet-il \
  --mode advise \
  --il-method CheckLabKey \
  --il-dump \
  --il-plan-patch
```

## Fixture workflow

Build the owned .NET IL fixture:

```bash
cd fixtures/dotnet_il_gate_demo
dotnet build -c Release
python create_manifest.py
```

Then run from the repository root:

```bash
python main.py \
  fixtures/dotnet_il_gate_demo/bin/Release/net8.0/GateDemo.dll \
  --frontend dotnet-il \
  --mode solve \
  --il-method CheckLabKey \
  --fixture-manifest fixtures/dotnet_il_gate_demo/fixture.manifest.json
```

Patch mode for .NET IL is currently dry-run only: it emits an IL branch rewrite
plan and does not write a modified assembly.

## License

GPL-3.0. See [`LICENSE`](LICENSE).
