"""Fixture manifest support for write-capable lab workflows.

A fixture manifest is documentation plus a lightweight guardrail: it records
which generated/owned sample is being analyzed, its expected hash, and whether
solve/patch-write experiments are allowed for that sample. It is not a legal
substitute for authorization, but it makes lab intent explicit and prevents
accidental write-capable actions on the wrong file.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclass
class FixtureCheck:
    ok: bool
    manifest_path: Optional[str]
    name: str = ""
    allow_solve: bool = False
    allow_patch_write: bool = False
    messages: Tuple[str, ...] = ()

    def describe(self) -> str:
        prefix = "OK" if self.ok else "NOT OK"
        lines = [f"fixture manifest: {prefix}"]
        if self.manifest_path:
            lines.append(f"  path: {self.manifest_path}")
        if self.name:
            lines.append(f"  name: {self.name}")
        lines.append(f"  allow_solve: {self.allow_solve}")
        lines.append(f"  allow_patch_write: {self.allow_patch_write}")
        for m in self.messages:
            lines.append(f"  - {m}")
        return "\n".join(lines)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _norm(path: str) -> str:
    return os.path.abspath(os.path.expanduser(path))


def _candidate_targets(manifest: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    # New schema: targets=[{role,path,sha256}, ...]
    for t in manifest.get("targets", []) or []:
        if isinstance(t, dict):
            yield t
    # Compatibility with the simple schema described in RESEARCH_INTENT.md.
    if manifest.get("sha256"):
        yield {"role": "assembly", "path": manifest.get("path"), "sha256": manifest.get("sha256")}
    if manifest.get("assembly_sha256"):
        yield {"role": "assembly", "path": manifest.get("assembly_path"), "sha256": manifest.get("assembly_sha256")}
    if manifest.get("binary_sha256"):
        yield {"role": "binary", "path": manifest.get("binary_path"), "sha256": manifest.get("binary_sha256")}


def verify_fixture_manifest(
    manifest_path: Optional[str],
    *,
    binary_path: Optional[str] = None,
    assembly_path: Optional[str] = None,
    require_solve: bool = False,
    require_patch_write: bool = False,
) -> FixtureCheck:
    if not manifest_path:
        return FixtureCheck(
            ok=False,
            manifest_path=None,
            messages=("no --fixture-manifest supplied",),
        )

    msgs: List[str] = []
    try:
        manifest = load_manifest(manifest_path)
    except Exception as e:
        return FixtureCheck(False, manifest_path, messages=(f"could not read manifest: {e}",))

    name = str(manifest.get("name", ""))
    allow_solve = bool(manifest.get("allow_solve", False))
    allow_patch_write = bool(manifest.get("allow_patch_write", False))
    if require_solve and not allow_solve:
        msgs.append("manifest does not allow solve workflows")
    if require_patch_write and not allow_patch_write:
        msgs.append("manifest does not allow patch-write workflows")

    # Authorization text is intentionally required to make intent explicit.
    auth = str(manifest.get("authorization", "")).strip()
    if not auth:
        msgs.append("manifest is missing a non-empty 'authorization' field")

    manifest_dir = os.path.dirname(_norm(manifest_path))
    wanted = {
        "binary": _norm(binary_path) if binary_path else None,
        "assembly": _norm(assembly_path) if assembly_path else None,
    }

    matched_any = False
    for target in _candidate_targets(manifest):
        role = str(target.get("role", "assembly")).lower()
        expected = str(target.get("sha256", "")).lower().strip()
        tpath = target.get("path")
        actual_path = None
        if role in wanted and wanted[role]:
            actual_path = wanted[role]
        elif tpath:
            actual_path = _norm(tpath if os.path.isabs(str(tpath)) else os.path.join(manifest_dir, str(tpath)))
        if not expected or not actual_path:
            continue
        if not os.path.exists(actual_path):
            msgs.append(f"{role} path does not exist: {actual_path}")
            continue
        actual = sha256_file(actual_path).lower()
        if actual != expected:
            msgs.append(f"{role} sha256 mismatch for {actual_path}: expected {expected}, got {actual}")
        else:
            matched_any = True
            msgs.append(f"{role} sha256 matched: {actual_path}")

    if not matched_any:
        msgs.append("no target hash in the manifest matched the selected binary/assembly")

    ok = matched_any and not any("mismatch" in m or "missing" in m or "does not" in m for m in msgs)
    if require_solve:
        ok = ok and allow_solve
    if require_patch_write:
        ok = ok and allow_patch_write

    return FixtureCheck(
        ok=ok,
        manifest_path=manifest_path,
        name=name,
        allow_solve=allow_solve,
        allow_patch_write=allow_patch_write,
        messages=tuple(msgs),
    )
