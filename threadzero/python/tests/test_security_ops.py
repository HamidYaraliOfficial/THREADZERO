"""Signing, distribution, canary, rollback, fault injection, decision log, time windows, benchmarks."""
import json
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from conftest import ROOT
from threadzero import build, core, lab, schedule
from threadzero.host import PolicyHost, distribute
from threadzero.store import DecisionLog, make_package, read_package, verify_package


@pytest.fixture
def pkg(ws):
    r = build.compile_path(ROOT / "examples" / "secure_api", ws=ws, register=True, lock_path=None, run_tests=False)
    return r, ws


def test_signed_package_verifies_and_detects_tampering(pkg):
    r, ws = pkg
    assert verify_package(r["package"])["project"] == "Secure API Architecture"
    files = read_package(r["package"])
    files["policy.wasm"] += b"\0"
    with pytest.raises(ValueError):
        verify_package(make_package(files))
    files = read_package(r["package"])
    del files["SIGNATURE.json"]
    with pytest.raises(ValueError):
        verify_package(make_package(files))


def test_untrusted_key_is_rejected(pkg):
    r, ws = pkg
    with pytest.raises(ValueError):
        verify_package(r["package"], trusted_public_keys=["00" * 32])


def test_host_load_activate_canary_rollback(pkg):
    r, ws = pkg
    h = PolicyHost(None)
    v1 = h.load(r["package"]); h.activate(v1)
    assert h.evaluate({"data": "PublicCatalog", "action": "Read"}).decision == "allow"
    v2 = h.load(r["package"])
    rep = h.canary(v2, [{"data": "PublicCatalog", "action": "Read"}, {"data": "Profile", "action": "Read", "zone": "Backend"}] * 10, promote=True)
    assert rep["changed"] == 0 and rep["withinThresholds"] and h.status()["active"] == v2
    assert h.rollback() == v1


def test_canary_detects_behaviour_change(ws):
    a = build.compile_bundle(core.load_project(ROOT / "examples" / "secure_api"), ws=ws, register=False, run_tests=False)
    src = (ROOT / "examples" / "secure_api" / "main.tz").read_text().replace("rule PublicCatalogRead: allow when data == PublicCatalog and action == Read", "rule PublicCatalogRead: deny when data == PublicCatalog and action == Read")
    b = build.compile_bundle(core.bundle_from_source(src), ws=ws, register=False, run_tests=False)
    h = PolicyHost(None)
    h.activate(h.load(a["package"]))
    vid = h.load(b["package"])
    rep = h.canary(vid, [{"data": "PublicCatalog", "action": "Read"}] * 10, max_changed_ratio=0.05)
    assert rep["changed"] == 10 and not rep["withinThresholds"]


def test_fault_injection_scenarios_all_fail_safe(pkg):
    r, ws = pkg
    res = lab.fault_injection(r["package"], ws)
    assert len(res) >= 8 and all(x["safe"] for x in res), [x for x in res if not x["safe"]]


def test_distribution_to_directory_and_dead_endpoint(pkg, tmp_path):
    r, ws = pkg
    out = distribute(r["package"], [str(tmp_path / "edge"), "http://127.0.0.1:9"], timeout=1)
    assert out[0]["ok"] and (tmp_path / "edge" / "CURRENT").exists() and not out[1]["ok"]


def test_decision_log_is_tamper_evident(tmp_path):
    from threadzero.store import workspace
    log = DecisionLog(workspace(tmp_path))
    for i in range(5):
        log.append("a1", "allow", "R", f"req{i}", ["audit"])
    assert log.verify()["ok"]
    lines = log.path.read_text().splitlines()
    rec = json.loads(lines[2]); rec["decision"] = "deny"
    lines[2] = json.dumps(rec, sort_keys=True)
    log.path.write_text("\n".join(lines) + "\n")
    assert not log.verify()["ok"] and log.verify()["broken_at"] == 3


# ---------------------------------------------------------------- schedule
def test_window_open_closed_and_countdowns():
    w = {"name": "Shop", "days": "weekdays", "from": "09:00", "to": "17:00", "tz": "Asia/Baku"}
    tz = ZoneInfo("Asia/Baku")
    op = schedule.evaluate_window(w, datetime(2026, 9, 21, 10, 0, 0, tzinfo=tz))  # Monday 10:00
    assert op["is_open"] and op["seconds_until_close"] == 7 * 3600
    cl = schedule.evaluate_window(w, datetime(2026, 9, 25, 18, 0, 0, tzinfo=tz))   # Friday 18:00 -> Monday 09:00
    assert not cl["is_open"] and cl["seconds_until_open"] == (2 * 24 + 15) * 3600 and cl["open_duration_seconds"] == 8 * 3600


def test_overnight_and_wraparound_windows():
    w = {"name": "Night", "days": ["sun"], "from": "22:00", "to": "06:00", "tz": "UTC"}
    utc = ZoneInfo("UTC")
    assert schedule.evaluate_window(w, datetime(2026, 9, 27, 23, 0, tzinfo=utc))["is_open"]        # Sunday 23:00
    r = schedule.evaluate_window(w, datetime(2026, 9, 21, 3, 0, tzinfo=utc))                        # Monday 03:00 (wrap from Sunday)
    assert r["is_open"] and r["seconds_until_close"] == 3 * 3600


def test_window_dsl_roundtrip_compiles():
    dsl = schedule.windows_to_dsl([{"name": "Desk", "days": ["mon", "wed"], "from": "08:30", "to": "12:00", "kind": "open", "label": "Desk hours"}])
    A = core.analyze('project "W" version "1";\n' + dsl + "\n")
    assert A["ok"] and A["policy"]["windows"][0]["ranges"] == [[510, 720], [3390, 3600]]


def test_windows_gate_policy_decisions():
    from conftest import compiled
    _, A, eng, _ = compiled("secure_api")
    req = lambda t: {"subject": {"roles": ["Support"], "mfa": True}, "data": "Profile", "action": "Read", "zone": "Backend", "context": {"time": t}}  # noqa: E731
    assert eng.evaluate(req(10 * 60)).decision == "allow"        # Monday 10:00
    assert eng.evaluate(req(5 * 1440 + 600)).decision == "deny"  # Saturday 10:00


# ---------------------------------------------------------------- performance
def test_benchmark_scales_and_reports_metrics():
    res = lab.benchmark([10, 200], requests=800, threads=2)
    a, b = res["rows"]
    assert b["wasmBytes"] > a["wasmBytes"] and b["avgDecisionPath"] > a["avgDecisionPath"] and a["throughputPerSec"] > 500
    assert {"p50Us", "p95Us", "p99Us", "rssMB", "cpuSeconds", "wasmMemoryKB"} <= set(a)


def test_hundred_thousand_decisions():
    res = lab.benchmark([100], requests=100_000, threads=1)
    assert res["rows"][0]["requests"] == 100_000 and res["rows"][0]["throughputPerSec"] > 1000
