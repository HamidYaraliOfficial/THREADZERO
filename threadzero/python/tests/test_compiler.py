"""Compiler pipeline: examples, diagnostics, determinism (reproducible builds), golden artifacts, lockfile."""
import hashlib
import json
from pathlib import Path

import pytest

from conftest import EXAMPLES, ROOT, compiled
from threadzero import build, core

GOLDEN = Path(__file__).parent / "golden"


@pytest.mark.parametrize("name", EXAMPLES)
def test_examples_compile_without_errors(name):
    _, A, _, r = compiled(name)
    assert A["ok"], [d for d in A["diagnostics"] if d["severity"] == "error"]
    assert r["files"]["policy.wasm"][:4] == b"\0asm"
    assert A["policy"]["rules"] and A["policy"]["tests"]


def test_diagnostics_demo_reports_every_error_class_with_exact_lines():
    A = core.analyze(ROOT / "examples" / "diagnostics_demo" / "errors.tz")
    codes = {d["code"] for d in A["diagnostics"] if d["severity"] == "error"}
    assert {"TZ2001", "TZ2002", "TZ2003", "TZ2004", "TZ2007", "TZ2008", "TZ2009", "TZ2011", "TZ1002"} <= codes
    assert all(d["line"] > 0 for d in A["diagnostics"] if d["severity"] == "error")
    assert any(d.get("hint", "") and "did you mean" in d["hint"] for d in A["diagnostics"])


def test_errors_block_generation():
    with pytest.raises(build.BuildError):
        build.compile_bundle(core.load_project(ROOT / "examples" / "diagnostics_demo" / "errors.tz"), ws=None, sign=False, register=False)


@pytest.mark.parametrize("name", EXAMPLES[:3])
def test_compilation_is_deterministic(name):
    b = core.load_project(ROOT / "examples" / name)
    r1 = build.compile_bundle(b, ws=None, sign=False, register=False, run_tests=False)
    r2 = build.compile_bundle(core.load_project(ROOT / "examples" / name), ws=None, sign=False, register=False, run_tests=False)
    assert r1["manifestHash"] == r2["manifestHash"]
    assert r1["files"]["policy.wasm"] == r2["files"]["policy.wasm"]
    assert r1["package"] == r2["package"]


def test_import_and_template_projects(tmp_path):
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "base.tz").write_text('zone Backend trust 3 kind Backend;\nrole User;\ndata Note class Internal;\n')
    (tmp_path / "main.tz").write_text('import "lib/base.tz";\nproject "Imp" version "1";\ntemplate Svc(N) { service N in Backend { controls: [authentication]; } }\napply Svc(A);\napply Svc(B);\nflow F from A to B carries Note op Write { channel: internal; }\n')
    A = core.analyze(tmp_path)
    assert A["ok"], A["diagnostics"]
    assert {n["id"] for n in A["graph"]["nodes"]} == {"A", "B"}
    assert "lib/base.tz" in A["files"]


def test_diagnostics_map_to_imported_file(tmp_path):
    (tmp_path / "base.tz").write_text("role Ok;\nrole Ok;\n")
    (tmp_path / "main.tz").write_text('import "base.tz";\n')
    A = core.analyze(tmp_path)
    dup = [d for d in A["diagnostics"] if d["code"] == "TZ2002"]
    assert dup and dup[0]["file"] == "base.tz" and dup[0]["line"] == 2


def test_lockfile_roundtrip(tmp_path):
    (tmp_path / "main.tz").write_text((ROOT / "examples" / "secure_api" / "main.tz").read_text())
    r1 = build.compile_path(tmp_path, register=False, sign=False, run_tests=False)
    assert r1["lockStatus"] == "written" and (tmp_path / "threadzero.lock").exists()
    r2 = build.compile_path(tmp_path, register=False, sign=False, run_tests=False)
    assert r2["lockStatus"] == "reproduced"
    lock = json.loads((tmp_path / "threadzero.lock").read_text())
    lock["ruleset"] = "tz-rules-0"
    (tmp_path / "threadzero.lock").write_text(json.dumps(lock))
    with pytest.raises(build.BuildError):
        build.compile_path(tmp_path, register=False, sign=False, run_tests=False, locked=True)


@pytest.mark.parametrize("name", EXAMPLES)
def test_golden_artifacts(name):
    g = json.loads((GOLDEN / f"{name}.json").read_text())
    _, A, eng, r = compiled(name)
    sha = lambda x: hashlib.sha256(x if isinstance(x, bytes) else x.encode()).hexdigest()  # noqa: E731
    for f in ("policy.wat", "policy.json", "policy.rego", "guard.js"):
        assert sha(r["files"][f]) == g["files"][f], f"{f} changed: regenerate goldens with tests/update_golden.py if intended"
    for req in g["decisions"]:
        d = eng.authorize_slots(eng.symbols.encode(req["request"]))
        assert (d.decision, d.matched) == (req["decision"], req["matched"])
