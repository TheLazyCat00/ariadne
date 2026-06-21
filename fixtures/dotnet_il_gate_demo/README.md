# Owned .NET IL Gate Demo Fixture

This fixture is a small, generated .NET application intended for testing the project’s managed-code frontend safely.

It is not third-party commercial software. It contains an intentionally simple gate in `CheckLabKey` so the analyzer can exercise:

- `Console.ReadLine` / argv input,
- `String.IsNullOrEmpty`,
- length checks,
- `StartsWith`,
- `EndsWith`,
- a tiny XOR/char transform,
- direct equality against a constant,
- success/failure strings,
- IL branch-plan reporting.

Expected lab key:

```text
LAB-IL-2026-OK
```

## Build

```bash
dotnet build -c Release
python create_manifest.py
```

This creates:

```text
fixture.manifest.json
```

with the SHA-256 of the built `GateDemo.dll`.

## Analyze with the project tool

From the workspace root:

```bash
python main.py \
  fixtures/dotnet_il_gate_demo/bin/Release/net8.0/GateDemo.dll \
  --frontend dotnet-il \
  --mode solve \
  --il-method CheckLabKey \
  --fixture-manifest fixtures/dotnet_il_gate_demo/fixture.manifest.json
```

Dump IL and print a dry-run patch plan:

```bash
python main.py \
  fixtures/dotnet_il_gate_demo/bin/Release/net8.0/GateDemo.dll \
  --frontend dotnet-il \
  --mode advise \
  --il-method CheckLabKey \
  --il-dump \
  --il-plan-patch \
  --fixture-manifest fixtures/dotnet_il_gate_demo/fixture.manifest.json
```

Patch mode is intentionally non-destructive in the public tool:

```bash
python main.py \
  fixtures/dotnet_il_gate_demo/bin/Release/net8.0/GateDemo.dll \
  --frontend dotnet-il \
  --mode patch \
  --il-method CheckLabKey \
  --fixture-manifest fixtures/dotnet_il_gate_demo/fixture.manifest.json
```

It prints a dry-run IL branch rewrite plan rather than writing a modified assembly.
