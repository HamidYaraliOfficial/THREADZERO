"""Security Build Pipeline: Parse -> Validate -> Analyze -> Refactor proposal -> Generate -> Test -> Package -> Sign -> Publish.
Compilation is reproducible: identical sources + compiler versions always produce byte-identical artifacts."""
from __future__ import annotations

import json
import platform
from importlib import metadata
from pathlib import Path
from typing import Any

from . import ABI_VERSION, COMPILER_VERSION, RULESET_VERSION, SCHEMAS, codegen, core
from .core import Bundle, canonical_json, sha256_hex
from .runtime import PolicyEngine
from .store import Registry, Snapshots, make_package, sign_bytes, workspace

LOCK_NAME = "threadzero.lock"


class BuildError(RuntimeError):
    def __init__(self, msg: str, analysis: dict | None = None):
        super().__init__(msg)
        self.analysis = analysis


def _dep_versions() -> dict[str, str]:
    out = {}
    for n in ("wasmtime", "cryptography", "PyYAML", "fastapi"):
        try:
            out[n] = metadata.version(n)
        except metadata.PackageNotFoundError:
            out[n] = "n/a"
    return out


def lock_document(A: dict, manifest_hash: str, bundle: Bundle) -> dict:
    return {"lockVersion": 1, "compiler": {"threadzero": COMPILER_VERSION, "core": core.core_version(), "abi": ABI_VERSION},
            "ruleset": RULESET_VERSION, "schemas": SCHEMAS, "dependencies": _dep_versions(),
            "sources": {n: sha256_hex(t) for n, t in sorted(bundle.files.items())}, "sourceHash": bundle.hash, "artifactHash": manifest_hash}


def check_lock(lock: dict, current: dict) -> list[str]:
    problems = []
    for k in ("compiler", "ruleset", "schemas"):
        if lock.get(k) != current.get(k):
            problems.append(f"{k} differs from lockfile: {lock.get(k)} != {current.get(k)}")
    return problems


def generate_artifacts(A: dict) -> dict[str, bytes | str]:
    wat = codegen.gen_wat(A)
    files: dict[str, bytes | str] = {
        "policy.wat": wat, "policy.wasm": codegen.wat_to_wasm(wat),
        "policy.json": canonical_json(codegen.gen_policy_json(A)),
        "policy.rego": codegen.gen_rego(A), "guard.js": codegen.gen_js(A), "guard.ts": codegen.gen_ts(A),
        "tests/policy_tests.json": json.dumps(A["policy"]["tests"], sort_keys=True, indent=1),
        "tests/assertions.json": json.dumps({"assertions": A["assertions"], "constraints": A["constraints"], "obligations": A["obligations"]}, sort_keys=True, indent=1),
        "security_model.json": canonical_json({k: A[k] for k in ("project", "findings", "properties", "metrics", "graph", "controlCoverage", "sourceHash")}),
    }
    files.update(codegen.gen_guards(A))
    files.update(codegen.gen_support_files())
    files["guards/tz_core_stub.py"] = "# placeholder module so tz_runtime imports resolve when compiler helpers are not shipped\n"
    return files


def compile_bundle(bundle: Bundle, *, ws: Path | None = None, sign: bool = True, key_id: str | None = None, register: bool = True,
                   run_tests: bool = True, force: bool = False, lock_path: Path | None = None, update_lock: bool = False,
                   locked: bool = False) -> dict:
    A = core.analyze_bundle(bundle)
    errors = [d for d in A["diagnostics"] if d["severity"] == "error"]
    if errors and not force:
        raise BuildError(f"{len(errors)} error(s); fix them or use --force", A)
    files = generate_artifacts(A)
    manifest = {"format": "threadzero-package/1", "project": A["project"]["name"], "version": A["project"]["version"],
                "sourceHash": A["sourceHash"], "compiler": {"threadzero": COMPILER_VERSION, "core": core.core_version(), "abi": ABI_VERSION},
                "ruleset": RULESET_VERSION, "rules": len(A["policy"]["rules"]), "wasmBytes": len(files["policy.wasm"]),
                "files": {n: sha256_hex(c) for n, c in sorted(files.items())}}
    manifest_text = canonical_json(manifest)
    manifest_hash = sha256_hex(manifest_text)
    result: dict[str, Any] = {"analysis": A, "files": files, "manifest": manifest, "manifestHash": manifest_hash,
                              "artifactId": manifest_hash[:16], "diagnostics": A["diagnostics"], "errors": len(errors)}
    # lockfile
    cur_lock = lock_document(A, manifest_hash, bundle)
    if lock_path:
        if lock_path.exists() and not update_lock:
            old = json.loads(lock_path.read_text())
            probs = check_lock(old, cur_lock)
            result["lockProblems"] = probs
            if probs and locked:
                raise BuildError("lockfile mismatch: " + "; ".join(probs), A)
            result["lockStatus"] = "drift" if probs else ("reproduced" if old.get("artifactHash") == manifest_hash else "source-changed")
        else:
            lock_path.write_text(json.dumps(cur_lock, indent=1, sort_keys=True) + "\n")
            result["lockStatus"] = "written"
    # tests
    if run_tests:
        from .testing import run_all
        engine = PolicyEngine(files["policy.wasm"], json.loads(files["policy.json"]))
        result["tests"] = run_all(A, engine, files)
    # package + sign
    entries = dict(files)
    entries["manifest.json"] = manifest_text
    if sign and ws is not None:
        entries["SIGNATURE.json"] = json.dumps(sign_bytes(ws, manifest_text.encode(), key_id), indent=1)
    package = make_package(entries)
    result["package"] = package
    if register and ws is not None:
        meta = {"project": A["project"]["name"], "version": A["project"]["version"], "sourceHash": A["sourceHash"], "compiler": manifest["compiler"],
                "rules": manifest["rules"], "wasmBytes": manifest["wasmBytes"], "signed": "SIGNATURE.json" in entries,
                "testsPassed": (result.get("tests") or {}).get("passed"), "testsFailed": (result.get("tests") or {}).get("failed")}
        result["registryEntry"] = Registry(ws).put(result["artifactId"], package, meta)
    return result


def compile_path(path: str | Path, out: str | Path | None = None, **kw: Any) -> dict:
    p = Path(path)
    bundle = core.load_project(p)
    proj_dir = (p if p.is_dir() else p.parent).resolve()
    ws = kw.pop("ws", None) or workspace(proj_dir)
    kw.setdefault("lock_path", proj_dir / LOCK_NAME)
    result = compile_bundle(bundle, ws=ws, **kw)
    if out:
        o = Path(out)
        for name, content in result["files"].items():
            f = o / name
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
        (o / "manifest.json").write_text(canonical_json(result["manifest"]))
        (o / f"{result['artifactId']}.tzpkg").write_bytes(result["package"])
    return result
