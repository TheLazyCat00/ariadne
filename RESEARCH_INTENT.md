# Ariadne Responsible Research Intent and Use Policy

## Project purpose

This project explores program-analysis techniques for understanding how software gates, validation paths, and input-dependent control flow are represented in native binaries and managed runtimes such as .NET IL.

The goals are:

- to improve public understanding of reverse engineering, binary analysis, and managed-code analysis;
- to support legitimate security research, education, interoperability research, malware analysis, and defensive auditing;
- to evaluate analysis techniques such as CFG recovery, source/sink discovery, symbolic execution, taint-style reasoning, and non-destructive patch planning;
- to build reproducible research fixtures for comparing native and managed-code analysis approaches.

This project is **not** intended to enable software piracy, unauthorized license circumvention, unauthorized access, or misuse against third-party systems.

## Ethical stance

Reverse engineering tools are dual-use. The same ideas that help defenders understand malware, validate license-system robustness, audit client-side trust assumptions, or teach program analysis can also be abused. This project takes the position that research can be valuable while still requiring clear boundaries.

The maintainers and contributors explicitly reject use of this project for:

- bypassing payment, licensing, trial, entitlement, or subscription mechanisms in software you are not authorized to test;
- distributing patched commercial software;
- producing or distributing keys, cracks, loaders, or bypass artifacts for third-party software;
- violating software licenses, laws, contracts, or terms of service;
- unauthorized access to systems, services, accounts, or protected functionality.

## Authorized-use scope

Acceptable uses include:

- binaries, assemblies, or applications you wrote yourself;
- internal software where you have explicit written authorization to perform reverse engineering or security testing;
- CTFs, crackmes, educational challenges, and lab fixtures that are explicitly designed for reverse engineering;
- malware-analysis labs and defensive research environments where samples are handled safely and lawfully;
- open-source projects where the license and project policy permit the analysis being performed;
- non-destructive inspection of third-party software for compatibility, vulnerability research, or defensive review where legally permitted.

When in doubt, do not run solve or patch workflows. Use non-destructive reporting modes only, and obtain authorization first.

## Safe-default design principles

The project should prefer safe defaults:

1. **Analysis before modification**
   - Discovery, reporting, CFG construction, source/sink correlation, and constraint-shape extraction should be available before any patch-writing capability.

2. **Non-destructive managed-code patch planning**
   - For .NET IL and future managed-runtime frontends, patch mode should default to a dry-run rewrite plan rather than writing modified third-party assemblies.

3. **Runtime-aware routing**
   - Native apphosts and runtime launchers should be identified as such. Native CFG solve/patch should not be applied to bootstrap/runtime code by default.

4. **No stealth or persistence features**
   - The project must not include functionality intended to hide modifications, evade security tools, persist on systems, or bypass operational controls.

5. **Clear output labeling**
   - Symbolic candidates, dry-run patch plans, and unverified hypotheses must be labeled as such.

## Disclosure and publication guidance

If the project identifies a weakness in a real product, especially a client-side licensing or entitlement issue, contributors should consider responsible disclosure to the vendor or maintainer. Public writeups should focus on methodology and defensive lessons, and should avoid distributing bypass artifacts, patched binaries, product keys, or step-by-step circumvention instructions for third-party commercial software.

Good disclosure artifacts include:

- high-level explanation of the design weakness;
- affected versions and environment;
- non-destructive evidence;
- risk assessment;
- defensive recommendations;
- suggested mitigations, such as server-side entitlement checks, signed offline entitlements, anti-tamper hardening, audit logging, and clearer trust boundaries.

## Research roadmap within these boundaries

Allowed research directions:

- IL metadata parsing and method discovery;
- IL CFG generation;
- source/sink and outcome-string correlation;
- symbolic execution for owned or challenge fixtures;
- dry-run IL branch rewrite planning;
- regression tests on generated fixtures;
- runtime-specific frontends for .NET, JVM bytecode, Python bytecode, Electron/JavaScript bundles, and Unity/Mono/IL2CPP analysis;
- optional native-snippet helpers using angr or Triton for authorized native code fragments.

Restricted research directions unless explicitly confined to owned/authorized lab fixtures:

- automated write-capable patching of third-party license checks;
- generation of working license keys or bypass inputs for third-party products;
- distribution of patched commercial binaries;
- automation intended to defeat payment, subscription, or activation systems.

## Contributor affirmation

By contributing to or using this project, you affirm that you will use it only on targets for which you have authorization, and that you will not use it to bypass licensing, payment, access control, or entitlement checks in third-party software.

## Summary

This project exists to advance understanding of program analysis and reverse engineering in a responsible way. The intended path is:

```text
learn -> measure -> report -> defend -> improve
```

not:

```text
bypass -> pirate -> distribute -> harm
```
