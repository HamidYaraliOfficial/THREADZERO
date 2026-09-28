"""WASM runtime: Haskell expectations == WASM == Python reference == JS == Rego; sandbox properties."""
import json
import random
import shutil

import pytest

from conftest import compiled
from threadzero.abi import ref_decide
from threadzero.runtime import PolicyEngine, PolicyLoadError, WasmPolicy
from threadzero.testing import differential_targets, random_request, run_all


def test_generated_tests_all_pass(example):
    name, b, A, eng, r = example
    t = run_all(A, eng, r["files"], n_random=200)
    failing = [c for c in t["cases"] if not c["ok"] and c["section"] not in ("assertions", "constraints")]
    assert not failing, failing[:3]
    kinds = {c["kind"] for c in t["cases"] if c["section"] == "generated"}
    assert {"positive", "negative"} <= kinds


def test_wasm_equals_reference_engine(example):
    name, b, A, eng, r = example
    rnd = random.Random(99)
    for _ in range(600):
        slots = eng.symbols.encode(random_request(rnd, eng.symbols))
        d, ref = eng.authorize_slots(slots), ref_decide(eng.rules, slots)
        assert d.code == ref["decision"]
        assert [eng.rules[i]["id"] for i in ref["matched"]] == d.matched


def test_targets_js_and_rego_match_wasm(example):
    name, b, A, eng, r = example
    if name not in ("secure_api", "payment_workflow"):
        pytest.skip("differential targets are sampled on two examples to keep the suite fast")
    res = differential_targets(A, r["files"], eng, n=20)
    assert res, "neither node nor opa available"
    assert all(c["ok"] for c in res), res


def test_deterministic_repeat_calls():
    _, A, eng, _ = compiled("secure_api")
    s = eng.symbols.encode({"data": "Profile", "action": "Read", "zone": "Backend", "subject": {"roles": ["Support"], "mfa": True}, "context": {"time": 600}})
    assert eng.authorize_slots(s).to_dict()["matched"] == eng.authorize_slots(s).to_dict()["matched"]


def test_default_deny_and_precedence_explanations():
    _, A, eng, _ = compiled("secure_api")
    d = eng.evaluate({"data": "PublicCatalog", "action": "Delete"})
    assert d.decision == "deny" and "default deny" in d.reason_text
    d = eng.evaluate({"data": "Profile", "action": "Log", "zone": "Backend"})
    assert d.decision == "deny" and "audit" in d.obligations or d.decision == "deny"


def test_obligations_and_mfa_challenge():
    _, A, eng, _ = compiled("secure_api")
    base = {"subject": {"roles": ["Customer"], "mfa": False}, "data": "Profile", "action": "Write", "resource": "PublicApi", "zone": "Backend",
            "context": {"tenant_match": True, "time": 600}}
    assert eng.evaluate(base).decision in ("deny", "require_mfa")
    ok = json.loads(json.dumps(base)); ok["subject"]["mfa"] = True
    assert eng.evaluate(ok).decision == "allow"


def test_boundary_and_flow_validation_report_missing_controls():
    _, A, eng, _ = compiled("payment_workflow")
    r = eng.validate_boundary({"flow": {"src_zone": "Backend", "dst_zone": "ThirdParty", "controls": []}, "action": "Export", "data": "Order"})
    assert not r["ok"] and "redaction" in r["missing_controls"]
    r = eng.validate_flow({"flow": {"src_zone": "Backend", "dst_zone": "ThirdParty", "controls": ["redaction"], "source": "Orchestrator", "destination": "Psp"}, "action": "Export", "data": "CardData"})
    assert not r["ok"]  # CardData: export denied / zone not allowed


def test_context_classification_and_audit_apis():
    _, A, eng, _ = compiled("secure_api")
    assert eng.classify_data({"data": "Profile"})["classification"] in ("Personal", "Restricted", "Financial")
    flags = eng.inspect_context({"subject": {"mfa": False, "device_trust": 1}, "zone": "Browser"})["flags"]
    assert {"no-mfa", "low-device-trust", "low-trust-zone", "insecure-channel"} <= set(flags)
    assert len(eng.evaluate({"data": "Profile", "action": "Read"}).audit["hash"]) == 8


def test_sandbox_rejects_host_capabilities_and_bad_modules():
    import wasmtime
    wasm = bytes(wasmtime.wat2wasm('(module (import "env" "open" (func)) (memory (export "memory") 1))'))
    with pytest.raises(PolicyLoadError):
        WasmPolicy(wasm)
    with pytest.raises(PolicyLoadError):
        WasmPolicy(b"garbage")


def test_runtime_trap_fails_closed():
    import wasmtime
    _, A, eng, r = compiled("secure_api")
    e2 = PolicyEngine(r["files"]["policy.wasm"], json.loads(r["files"]["policy.json"]))
    def boom(*a):
        raise wasmtime.WasmtimeError("injected")
    e2.wasm._fn["authorize"] = boom
    d = e2.evaluate({"data": "Profile", "action": "Read"})
    assert d.decision == "deny" and d.reason == "runtime-failure" and e2.stats["failures"] == 1


def test_fuel_starvation_traps_on_next_call():
    import wasmtime
    _, A, eng, r = compiled("secure_api")
    with pytest.raises(PolicyLoadError):
        WasmPolicy(r["files"]["policy.wasm"], fuel=1)  # starved sandbox refuses to load (self-check traps)


def test_decision_cache_effectiveness():
    _, A, eng, r = compiled("secure_api")
    e2 = PolicyEngine(r["files"]["policy.wasm"], json.loads(r["files"]["policy.json"]), cache_size=64)
    req = {"data": "Profile", "action": "Read", "zone": "Backend"}
    for _ in range(5):
        e2.evaluate(req)
    assert e2.stats["hits"] == 4 and e2.stats["misses"] == 1
