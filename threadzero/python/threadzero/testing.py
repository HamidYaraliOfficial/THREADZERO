"""Policy Testing Framework: generated positive/negative/boundary/context tests (from the Haskell core),
property tests, flow/boundary tests, runtime-assertion tests, golden regression and cross-target differential tests."""
from __future__ import annotations

import json
import random
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .abi import DECISIONS, Symbols, full_slots, ref_decide
from .runtime import PolicyEngine


def ref_validate_flow(A: dict, slots: dict[str, int]) -> dict:
    T, checks = A["policy"]["tables"], A["policy"]["runtimeChecks"]
    s = full_slots(slots)
    nz, nc, ng, na = T["nz"], T["nc"], T["ng"], T["na"]
    nd = len(T["dataClass"])
    src, dst, data, action, controls = s["src_zone"], s["dst_zone"], s["data"], s["action"], s["controls"]
    cls, subj, res, secure = s["class"], s["subj"], s["res"], s["secure"]
    fail = 0
    if not (0 <= src < nz and 0 <= dst < nz):
        fail = 9
    if fail == 0 and 0 <= data < nd:
        cls = T["dataClass"][data]
        if T["dataZone"][data * nz + dst] == 0:
            fail = 1
        if fail == 0 and 0 <= action < 32 and not (T["dataOps"][data] >> action) & 1:
            fail = 2
        zmax = T["zoneMax"][dst]
        if fail == 0 and zmax >= 0 and cls > zmax:
            fail = 4
        if fail == 0 and T["exportAction"] >= 0 and action == T["exportAction"]:
            ex = T["dataExport"][data]
            if ex == 2:
                fail = 5
            elif ex == 1 and not controls & T["approvalBit"]:
                fail = 6
    for c in checks:
        if fail:
            break
        k = c["kind"]
        hit = {"never_enter": data == c.get("data") and dst == c.get("zone"),
               "must_not": subj == c.get("subj") and action == c.get("action") and res == c.get("res"),
               "never_op": data == c.get("data") and action == c.get("action"),
               "never_class_op": cls >= c.get("rank", 99) and action == c.get("action"),
               "require_control": action == c.get("action") and not controls & c.get("control", 0),
               "secure_flow": subj == c.get("subj") and res == c.get("res") and not secure,
               "secure_crossing": src != dst and not secure}.get(k, False)
        if hit:
            fail = {"never_enter": 10, "must_not": 11, "never_op": 12, "never_class_op": 13, "require_control": 14, "secure_flow": 15, "secure_crossing": 15}[k]
    req = miss = 0
    if fail == 0:
        g = T["actionGroup"][action] if 0 <= action < na else 0
        c2 = min(max(cls, 0), nc - 1)
        req = T["required"][((src * nz + dst) * nc + c2) * ng + g]
        miss = req & ~controls
        if miss:
            fail = 3
    return {"ok": fail == 0, "reason": fail, "required": req, "missing": miss & 0xFFFFFFFF if miss > 0 else miss}


def _case(section: str, name: str, ok: bool, kind: str = "", policy: str = "", request: Any = None, expected: Any = None,
          actual: Any = None, trace: Any = None) -> dict:
    return {"section": section, "name": name, "ok": bool(ok), "kind": kind, "policy": policy, "request": request,
            "expected": expected, "actual": actual, "trace": trace}


def random_request(rnd: random.Random, S: Symbols) -> dict:
    pick = lambda xs: rnd.choice([None] + list(xs))  # noqa: E731
    return {"data": pick(S.data), "zone": pick(S.zones), "resource": pick(S.nodes), "action": pick(S.actions),
            "env": pick(S.envs), "subject": {"roles": rnd.sample(list(S.roles), k=min(len(S.roles), rnd.randint(0, 2))) if S.roles else [],
                                              "mfa": rnd.random() < .5, "device_trust": rnd.randint(0, 5), "clearance": pick(S.classes)},
            "context": {"time": rnd.randint(0, 10079), "approved": rnd.random() < .3, "emergency": rnd.random() < .2,
                        "secure_channel": rnd.random() < .5, "tenant_match": rnd.random() < .5, "location": pick(S.locs)}}


def run_all(A: dict, engine: PolicyEngine, files: dict | None = None, seed: int = 0, n_random: int = 300,
            golden: dict | None = None, targets: bool = False) -> dict:
    S, rules = engine.symbols, engine.rules
    cases: list[dict] = []
    # 1. generated tests (expectations computed independently by the Haskell decision engine)
    for t in A["policy"]["tests"]:
        d = engine.authorize_slots(t["request"])
        e = t["expect"]
        exp_matched = [rules[i]["id"] for i in e["matched"]]
        ok = d.code == e["decision"] and d.matched == exp_matched and engine.wasm.call("authorize", t["request"])[1][2] == e["obligations"] \
            and (d.reason == (rules[e["reason"]]["id"] if e["reason"] >= 0 else ""))
        cases.append(_case("generated", t["name"], ok, t["kind"], t["rule"], S.decode(t["request"]),
                           {"decision": DECISIONS[e["decision"]], "matched": exp_matched},
                           {"decision": d.decision, "matched": d.matched, "reason": d.reason_text}, d.matched))
    # 2. property tests
    rnd = random.Random(seed)
    bad = 0
    for i in range(n_random):
        req = random_request(rnd, S)
        slots = S.encode(req)
        d = engine.authorize_slots(slots)
        r = ref_decide(rules, slots)
        d2 = engine.authorize_slots(slots)
        ok = d.code == r["decision"] and [rules[j]["id"] for j in r["matched"]] == d.matched and d2.code == d.code
        # invariant: a matched deny that outranks every matched allow forces deny
        term = [rules[j] for j in r["matched"] if rules[j]["terminal"]]
        if term and term[0]["effect"] == "deny":
            ok = ok and d.code == 0
        if not r["matched"]:
            ok = ok and d.code == 0 and d.reason == ""
        if not ok:
            bad += 1
            cases.append(_case("property", f"random-{i}", False, "property", "", req, {"decision": DECISIONS[r["decision"]]}, {"decision": d.decision}))
    cases.append(_case("property", f"{n_random} random requests: WASM == reference engine, deny-overrides, default-deny, determinism", bad == 0, "property"))
    # 3. flow / boundary tests
    edges = {e["id"]: e for e in A["graph"]["edges"]}
    for fl in A["ast"]["flows"]:
        e = edges.get(fl["name"])
        if not e:
            continue
        src = S.nodes[fl["from"]]["zone"]
        dst = S.nodes[fl["to"]]["zone"]
        any_fail = False
        for dname in fl["carries"]:
            req = {"flow": {"src_zone": src, "dst_zone": dst, "controls": e["controls"], "source": fl["from"], "destination": fl["to"]},
                   "data": dname, "action": fl["op"], "context": {"secure_channel": e["channel"] in ("tls", "mtls")}}
            slots = S.encode(req)
            slots.setdefault("class", S.data[dname]["rank"])
            got = engine.validate_flow(req)
            exp = ref_validate_flow(A, slots)
            any_fail |= not got["ok"]
            cases.append(_case("flows", f"{fl['name']}/{dname}", got["ok"] == exp["ok"] and got["reason_code"] == exp["reason"], "flow", "",
                               req, {"ok": exp["ok"], "reason": exp["reason"]}, got))
    # 4. runtime assertion checks
    for c in A["policy"]["runtimeChecks"]:
        req_slots = _violation(c, S)
        if req_slots is None:
            continue
        got = engine.wasm.call("validate_flow", req_slots)
        ok = got[0] == 0 and got[1][1] in (10, 11, 12, 13, 14, 15, 1, 2, 4, 5, 6, 9, 3)
        cases.append(_case("assertions-runtime", c["name"], ok, "assertion", c["name"], S.decode(req_slots), {"ok": False}, {"ok": bool(got[0]), "reason_code": got[1][1]}))
    # 5. static assertion / constraint / property outcomes
    for a in A["assertions"]:
        cases.append(_case("assertions", a["name"], a["status"] != "violated", "assertion", a["name"], None, {"status": "discharged|runtime"}, {"status": a["status"], "method": a["method"], "evidence": a["evidence"]}))
    for c in A["constraints"]:
        cases.append(_case("constraints", c["name"], c["satisfied"], "constraint", c["name"], None, {"satisfied": True}, {"satisfied": c["satisfied"], "evidence": c["evidence"]}))
    # 6. golden regression
    if golden:
        for g in golden.get("decisions", []):
            try:
                d = engine.authorize_slots(S.encode(g["request"]))
                ok = d.decision == g["decision"] and d.matched == g["matched"]
            except Exception:
                ok = False
            cases.append(_case("regression", "golden:" + json.dumps(g["request"], sort_keys=True)[:60], ok, "regression", "", g["request"], {"decision": g["decision"]}, {}))
    # 7. cross-target differential
    if targets and files:
        cases += differential_targets(A, files, engine, seed=seed)
    passed = sum(1 for c in cases if c["ok"])
    sections: dict[str, dict] = {}
    for c in cases:
        s = sections.setdefault(c["section"], {"passed": 0, "failed": 0})
        s["passed" if c["ok"] else "failed"] += 1
    return {"passed": passed, "failed": len(cases) - passed, "total": len(cases), "sections": sections, "cases": cases}


def _violation(c: dict, S: Symbols) -> dict | None:
    k = c["kind"]
    any_zone = next(iter(S.zones.values()), None)
    if any_zone is None:
        return None
    zid = any_zone["id"]
    base = {"src_zone": zid, "dst_zone": zid, "controls": 0xFFFFF, "secure": 1}
    if k == "never_enter" and c["data"] >= 0 and c["zone"] >= 0:
        return {**base, "data": c["data"], "dst_zone": c["zone"], "action": 1}
    if k == "must_not":
        return {**base, "subj": c["subj"], "res": c["res"], "action": c["action"]}
    if k == "never_op":
        return {**base, "data": c["data"], "action": c["action"]}
    if k == "never_class_op":
        return {**base, "class": c["rank"], "action": c["action"]}
    if k == "require_control":
        return {**base, "action": c["action"], "controls": 0}
    if k == "secure_flow":
        return {**base, "subj": c["subj"], "res": c["res"], "secure": 0}
    if k == "secure_crossing" and len(S.zones) > 1:
        z2 = [z["id"] for z in S.zones.values() if z["id"] != zid][0]
        return {**base, "dst_zone": z2, "secure": 0}
    return None


def differential_targets(A: dict, files: dict, engine: PolicyEngine, n: int = 30, seed: int = 3) -> list[dict]:
    """Run JS (node) and Rego (opa) on the same requests and compare with the WASM engine."""
    out: list[dict] = []
    S, rules = engine.symbols, engine.rules
    rnd = random.Random(seed)
    reqs = [random_request(rnd, S) for _ in range(n)]
    slots_list = [S.encode(r) for r in reqs]
    tmp = Path(tempfile.mkdtemp())
    node = shutil.which("node")
    if node:
        (tmp / "guard.js").write_text(files["guard.js"] if isinstance(files["guard.js"], str) else files["guard.js"].decode())
        proc = subprocess.run([node, "-e", "const g=require(process.argv[1]);const c=JSON.parse(require('fs').readFileSync(0,'utf8'));console.log(JSON.stringify(c.map(s=>g.decideSlots(s))))", str(tmp / "guard.js")],
                              input=json.dumps(slots_list).encode(), capture_output=True, timeout=60)
        try:
            res = json.loads(proc.stdout)
            bad = sum(1 for s, r in zip(slots_list, res) if engine.authorize_slots(s).code != r["decision"] or [rules[i]["id"] for i in r["matched"]] != engine.authorize_slots(s).matched)
            out.append(_case("targets", f"JavaScript wrapper equals WASM on {n} requests", bad == 0, "differential"))
        except Exception as exc:
            out.append(_case("targets", "JavaScript wrapper", False, "differential", actual=str(exc)))
    opa = shutil.which("opa")
    if opa:
        f = files["policy.rego"]
        (tmp / "p.rego").write_text(f if isinstance(f, str) else f.decode())
        bad = 0
        for s, req in zip(slots_list[:20], reqs[:20]):
            r = subprocess.run([opa, "eval", "-d", str(tmp / "p.rego"), "-I", "--format", "json", "data.threadzero.authz.decision"],
                               input=json.dumps(S.decode(s)).encode(), capture_output=True, timeout=30)
            try:
                v = json.loads(r.stdout)["result"][0]["expressions"][0]["value"]
                w = engine.authorize_slots(s)
                bad += v["decision"] != w.decision or sorted(v["matched"]) != sorted(w.matched)
            except Exception:
                bad += 1
        out.append(_case("targets", "Rego policy equals WASM on 20 requests (opa)", bad == 0, "differential"))
    return out


def golden_snapshot(A: dict, engine: PolicyEngine, n: int = 60, seed: int = 11) -> dict:
    rnd = random.Random(seed)
    S = engine.symbols
    decisions = []
    for _ in range(n):
        req = random_request(rnd, S)
        d = engine.authorize_slots(S.encode(req))
        decisions.append({"request": req, "decision": d.decision, "matched": d.matched})
    return {"sourceHash": A["sourceHash"], "decisions": decisions}
