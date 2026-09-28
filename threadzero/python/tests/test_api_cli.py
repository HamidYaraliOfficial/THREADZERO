"""End-to-end: FastAPI endpoints and CLI commands."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import ROOT

CLI = [sys.executable, "-m", "threadzero"]
ENV = {**os.environ, "PYTHONPATH": str(ROOT / "python"), "NO_COLOR": "1"}


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    os.environ["THREADZERO_HOME"] = str(tmp_path_factory.mktemp("home"))
    from fastapi.testclient import TestClient
    from threadzero.api import create_app
    return TestClient(create_app())


def cli(*args):
    return subprocess.run(CLI + list(args), capture_output=True, text=True, env=ENV, cwd=ROOT)


def test_api_health_examples_and_compile(client):
    assert client.get("/api/health").json()["ok"]
    assert len(client.get("/api/examples").json()) >= 6
    r = client.post("/api/compile", json={"example": "multi_tenant_saas"}).json()
    assert r["ok"] and r["tests"]["failed"] == 0 and any(f["name"] == "policy.wasm" for f in r["files"])
    reg = client.get("/api/registry").json()
    assert reg[0]["id"] == r["artifactId"]
    wasm = client.get(f"/api/registry/{r['artifactId']}/file", params={"name": "policy.wasm"})
    assert wasm.content[:4] == b"\0asm"
    assert client.get(f"/api/registry/{r['artifactId']}/package").status_code == 200


def test_api_compile_reports_errors_with_line_numbers(client):
    r = client.post("/api/compile", json={"example": "diagnostics_demo"}).json()
    assert not r["ok"] and any(d["severity"] == "error" and d["line"] > 0 for d in r["diagnostics"])


def test_api_simulation_boundary_and_context(client):
    req = {"subject": {"roles": ["Finance"], "mfa": True}, "data": "RefundRequest", "action": "Create", "zone": "Backend", "context": {"time": 600}}
    s = client.post("/api/simulate", json={"example": "payment_workflow", "request": req}).json()
    assert s["decision"]["decision"] == "require_approval" and s["graph"]["nodes"]
    b = client.post("/api/simulate/boundary", json={"example": "payment_workflow", "request": {"flow": {"src_zone": "Backend", "dst_zone": "ThirdParty", "controls": []}, "action": "Export", "data": "Order"}}).json()
    assert not b["flow"]["ok"] and "Missing controls" in b["explanation"]


def test_api_refactor_diff_impact_reports(client):
    src = (ROOT / "examples" / "secure_api" / "main.tz").read_text()
    a = client.post("/api/analyze", json={"source": src}).json()
    r = client.post("/api/refactor", json={"source": src, "findingId": a["findings"][0]["id"]}).json()
    assert r["candidates"]
    head = src.replace("flow AdminRead from AccountDb to AdminConsole carries Profile op Read { channel: mtls; }", "")
    imp = client.post("/api/impact", json={"base": src, "head": head}).json()
    assert imp["diff"]["findings"]["fixed"] and "regression" in imp
    rep = client.post("/api/reports", json={"source": src, "kind": "security", "format": "html"}).json()
    assert "<html" in rep["content"]


def test_api_schedule_endpoints(client):
    wins = [{"name": "Shop", "days": "daily", "from": "00:00", "to": "24:00", "tz": "Asia/Baku"}]
    ev = client.post("/api/schedule/evaluate", json={"timezone": "Asia/Baku", "windows": wins}).json()["results"][0]
    assert ev["is_open"] and ev["seconds_until_change"] is not None or ev["is_open"]
    assert "window Shop" in client.post("/api/schedule/dsl", json={"windows": wins}).json()["dsl"]
    client.put("/api/schedule", json={"timezone": "UTC", "windows": wins})
    assert client.get("/api/schedule").json()["windows"][0]["name"] == "Shop"


def test_api_host_snapshot_labs_and_logs(client):
    aid = client.post("/api/compile", json={"example": "secure_api"}).json()["artifactId"]
    assert client.post("/api/host/load-artifact", json={"artifact": aid}).json()["version"]
    d = client.post("/api/host/evaluate", json={"request": {"data": "PublicCatalog", "action": "Read"}}).json()
    assert d["decision"] == "allow"
    assert client.get("/api/decisions/verify").json()["ok"]
    assert client.post("/api/snapshots", json={"example": "secure_api", "label": "t"}).json()["id"]
    assert client.get("/api/history").json()
    assert all(x["safe"] for x in client.post("/api/faults", json={"example": "secure_api"}).json())
    assert client.post("/api/perf", json={"rules": [10], "requests": 500}).json()["rows"]
    assert client.post("/api/counterfactual", json={"variants": {"a": (ROOT / "examples/secure_api/main.tz").read_text()}}).json()["rows"]
    assert client.post("/api/ai", json={"example": "secure_api", "question": "propose a refactoring"}).json()["productionChanges"] == 0


def test_api_rejects_paths_outside_workspace(client):
    assert client.post("/api/analyze", json={"path": "../../etc/passwd"}).status_code in (403, 404, 500)


def test_cli_check_verify_compile_test_explain():
    m = str(ROOT / "examples" / "secure_api" / "main.tz")
    assert cli("check", m).returncode == 0
    assert "Confidentiality" in cli("verify", m).stdout
    out = cli("test", m, "--allow-model-failures")
    assert "passed" in out.stdout and out.returncode == 0
    assert "F-001" in cli("explain", m, "F-001").stdout
    assert cli("check", str(ROOT / "examples" / "diagnostics_demo" / "errors.tz")).returncode == 1


def test_cli_compile_package_verify_and_ci(tmp_path):
    m = tmp_path / "main.tz"
    m.write_text((ROOT / "examples" / "document_pipeline" / "main.tz").read_text())
    r = cli("compile", str(m), "-o", str(tmp_path / "out"))
    assert r.returncode == 0, r.stdout + r.stderr
    assert (tmp_path / "out" / "policy.wasm").exists() and (tmp_path / "threadzero.lock").exists()
    pkg = tmp_path / "p.tzpkg"
    assert cli("package", str(m), "-o", str(pkg)).returncode == 0
    assert "OK" in cli("verify-package", str(pkg)).stdout
    assert cli("ci", str(m), "--fail-on", "critical", "--sarif", str(tmp_path / "r.sarif")).returncode == 0
    assert json.loads((tmp_path / "r.sarif").read_text())["version"] == "2.1.0"


def test_cli_fail_on_gate_and_diff():
    pay = str(ROOT / "examples" / "payment_workflow" / "main.tz")
    assert cli("ci", pay, "--fail-on", "critical").returncode == 1        # violated assertion blocks the build
    d = cli("diff", pay, str(ROOT / "examples" / "secure_api" / "main.tz"))
    assert d.returncode == 0 and "findings:" in d.stdout


def test_cli_simulate_schedule_bench_fault():
    m = str(ROOT / "examples" / "secure_api" / "main.tz")
    s = cli("simulate", m, '{"data":"PublicCatalog","action":"Read"}')
    assert "ALLOW" in s.stdout
    assert "BusinessHours" in cli("schedule", m, "--now", "2026-09-21T10:00:00").stdout
    assert "rules" in cli("bench", "--rules", "10,50", "--requests", "500").stdout
    assert cli("fault", m).returncode == 0
