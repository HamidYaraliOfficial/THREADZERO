"""Performance/Scale Lab and Fault Injection Lab."""
from __future__ import annotations

import json
import random
import resource
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from . import codegen
from .abi import full_slots
from .runtime import PolicyEngine, PolicyLoadError, WasmPolicy


def synthetic_analysis(n_rules: int, depth: int = 3, n_zones: int = 8, n_data: int = 12, seed: int = 1) -> dict:
    """A syntactically real policy IR of arbitrary size (for scale tests; bypasses the DSL front end)."""
    rnd = random.Random(seed)
    zones = [{"id": i, "name": f"Z{i}", "trust": i % 6, "kind": "Backend", "kindId": 5, "maxClass": None} for i in range(n_zones)]
    data = [{"id": i, "name": f"D{i}", "class": "Internal", "rank": i % 6} for i in range(n_data)]
    actions = ["Create", "Read", "Write", "Transform", "Enrich", "Copy", "Export", "Publish", "Subscribe", "Cache", "Log", "Delete"]
    nodes = [{"id": i, "name": f"N{i}", "kind": "service", "zone": zones[i % n_zones]["name"], "zoneId": i % n_zones} for i in range(16)]
    roles = [{"name": f"R{i}", "bit": 1 << i} for i in range(8)]
    sym = {"roles": roles, "zones": zones, "actions": [{"id": i, "name": a} for i, a in enumerate(actions)], "data": data, "nodes": nodes, "envs": [{"id": 0, "name": "prod"}],
           "locations": [], "classes": [{"name": "Public", "rank": 0}, {"name": "Internal", "rank": 1}], "zoneKinds": ["PublicInternet", "Browser", "MobileClient", "InternalNetwork", "ServiceMesh", "Backend", "DatabaseZone", "AdminZone", "PartnerZone", "ThirdPartyZone", "SecureProcessingZone", "SecretZone", "UntrustedZone", "Custom"],
           "nodeKinds": ["user", "identity", "device", "application", "service", "api", "database", "queue", "filestore", "cloud", "secret", "external", "agent", "approval"],
           "controls": [{"name": "audit", "bit": 512}], "effects": [{"name": n, "bit": (1 << i) if n not in ("allow", "deny") else 1 << i, "terminal": n in ("allow", "deny")} for i, n in enumerate(["allow", "deny", "require_mfa", "require_approval", "redact", "encrypt", "audit", "rate_limit", "tokenize", "quarantine", "require_trusted_zone"])], "slots": []}

    def atom():
        k = rnd.choice(["data", "zone", "action", "roles", "class", "ztrust", "mfa"])
        if k == "data":
            return {"op": "eq", "slot": "data", "val": rnd.randrange(n_data)}
        if k == "zone":
            return {"op": "eq", "slot": "zone", "val": rnd.randrange(n_zones)}
        if k == "action":
            return {"op": "in", "slot": "action", "vals": rnd.sample(range(12), 3)}
        if k == "roles":
            return {"op": "has", "slot": "roles", "mask": 1 << rnd.randrange(8)}
        if k == "class":
            return {"op": "ge", "slot": "class", "val": rnd.randrange(5)}
        if k == "ztrust":
            return {"op": "lt", "slot": "ztrust", "val": rnd.randrange(1, 6)}
        return {"op": "flag", "slot": "mfa"}
    effects = ["allow"] * 6 + ["deny"] * 3 + ["require_mfa", "audit"]
    rules = []
    for i in range(n_rules):
        eff = rnd.choice(effects)
        cond = {"op": "and", "args": [atom() for _ in range(max(1, depth))]}
        term = eff in ("allow", "deny")
        obl = [] if term else [eff]
        mask = sum(e["bit"] for e in sym["effects"] if e["name"] in obl)
        rules.append({"idx": i, "id": f"Synthetic.R{i}", "policy": "Synthetic", "name": f"R{i}", "effect": eff, "terminal": term, "cond": cond, "condText": "synthetic",
                      "reason": f"rule {i}", "obligations": obl, "obligationMask": mask, "priority": 1000 - i // 4, "specificity": 0, "file": "synthetic", "line": i, "version": "1"})
    nz, nc, ng = n_zones, 6, 5
    tables = {"nz": nz, "nc": nc, "ng": ng, "na": 12, "required": [0] * (nz * nz * nc * ng), "actionGroup": [0] * 12, "zoneTrust": [z["trust"] for z in zones],
              "zoneMax": [-1] * nz, "dataClass": [d["rank"] for d in data], "dataOps": [4095] * n_data, "dataExport": [0] * n_data, "dataZone": [1] * (n_data * nz),
              "approvalBit": 128, "exportAction": 6}
    return {"project": {"name": f"synthetic-{n_rules}", "version": "1", "timezone": "UTC"}, "symbols": sym, "sourceHash": "synthetic",
            "policy": {"rules": rules, "tables": tables, "windows": [], "runtimeChecks": [], "defaultEffect": "deny"}}


def _rand_slots(rnd: random.Random, n_zones: int, n_data: int) -> dict[str, int]:
    z = rnd.randrange(n_zones)
    d = rnd.randrange(n_data)
    return {"data": d, "class": d % 6, "zone": z, "ztrust": z % 6, "action": rnd.randrange(12), "roles": 1 << rnd.randrange(8), "mfa": rnd.randrange(2)}


def benchmark(rule_counts: list[int], requests: int = 20000, depth: int = 3, threads: int = 1, seed: int = 1) -> dict:
    rows = []
    for n in rule_counts:
        A = synthetic_analysis(n, depth, seed=seed)
        t0 = time.perf_counter()
        wat = codegen.gen_wat(A)
        wasm = codegen.wat_to_wasm(wat)
        compile_ms = (time.perf_counter() - t0) * 1000
        pol = {"symbols": A["symbols"], "project": A["project"], "rules": A["policy"]["rules"]}
        workers = [PolicyEngine(wasm, pol, fuel=200_000_000) for _ in range(max(1, threads))]
        rnd = random.Random(seed)
        reqs = [_rand_slots(rnd, 8, 12) for _ in range(requests)]
        lat: list[float] = []
        matched_total = 0
        cpu0, rss0 = time.process_time(), resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        def run(chunk_idx: int) -> tuple[list[float], int]:
            eng, out, m = workers[chunk_idx], [], 0
            for s in reqs[chunk_idx::len(workers)]:
                t = time.perf_counter()
                _, head, matched = eng.wasm.call("authorize", s)
                out.append((time.perf_counter() - t) * 1e6)
                m += len(matched)
            return out, m
        wall0 = time.perf_counter()
        if len(workers) == 1:
            res = [run(0)]
        else:
            with ThreadPoolExecutor(len(workers)) as ex:
                res = list(ex.map(run, range(len(workers))))
        wall = time.perf_counter() - wall0
        for l, m in res:
            lat += l
            matched_total += m
        lat.sort()
        pct = lambda p: lat[min(len(lat) - 1, int(len(lat) * p))]  # noqa: E731
        rows.append({"rules": n, "depth": depth, "threads": len(workers), "requests": requests, "wasmBytes": len(wasm), "compileMs": round(compile_ms, 1),
                     "p50Us": round(pct(.5), 2), "p95Us": round(pct(.95), 2), "p99Us": round(pct(.99), 2), "meanUs": round(statistics.mean(lat), 2),
                     "throughputPerSec": int(requests / wall), "cpuSeconds": round(time.process_time() - cpu0, 3),
                     "rssMB": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1), "wasmMemoryKB": workers[0].wasm.memory_bytes() // 1024,
                     "avgDecisionPath": round(matched_total / requests, 2)})
    return {"rows": rows, "note": "Latencies include the Python↔WASM call overhead; embedded hosts (Rust/Go/JS) are faster."}


def cache_effectiveness(engine: PolicyEngine, requests: list[dict], repeat: int = 3) -> dict:
    eng = PolicyEngine(engine.wasm._fn and open_wasm(engine), engine.policy, cache_size=1024) if False else engine
    eng.cache = __import__("collections").OrderedDict()
    eng.cache_size = 1024
    eng.stats.update(hits=0, misses=0)
    t0 = time.perf_counter()
    for _ in range(repeat):
        for r in requests:
            eng.evaluate(r)
    dt = time.perf_counter() - t0
    h, m = eng.stats["hits"], eng.stats["misses"]
    eng.cache = None
    return {"hits": h, "misses": m, "hitRatio": round(h / max(1, h + m), 3), "seconds": round(dt, 4)}


def open_wasm(engine: PolicyEngine) -> bytes:  # pragma: no cover - helper kept for API symmetry
    raise NotImplementedError


def performance_analysis(A: dict, engine: PolicyEngine, n: int = 3000) -> dict:
    from .testing import random_request
    rnd = random.Random(2)
    S = engine.symbols
    reqs = [random_request(rnd, S) for _ in range(min(n, 400))]
    lats, paths = [], []
    for r in reqs:
        d = engine.authorize_slots(S.encode(r))
        lats.append(d.duration_us)
        paths.append(len(d.matched))
    cache = cache_effectiveness(engine, reqs[:100])
    return {"ruleCount": len(engine.rules), "wasmBytes": engine.wasm.wasm_size, "wasmMemoryKB": engine.wasm.memory_bytes() // 1024,
            "meanLatencyUs": round(statistics.mean(lats), 2), "p95LatencyUs": round(sorted(lats)[int(len(lats) * .95) - 1], 2),
            "avgDecisionPathLength": round(statistics.mean(paths), 2), "maxDecisionPathLength": max(paths), "cache": cache}


# --- fault injection ---------------------------------------------------------------------
def fault_injection(package: bytes, ws) -> list[dict]:
    """Every scenario must end in a *safe failure* (deny / rejected load / previous version kept)."""
    import copy
    from .host import PolicyHost, distribute
    from .store import keygen, list_keys, make_package, read_package, sign_bytes
    from .core import canonical_json
    keys = [(ws / "keys" / f"{k}.pub").read_text().strip() for k in list_keys(ws)] or None
    req = {"data": None, "action": "Read", "context": {}}
    res: list[dict] = []

    def add(name: str, expected: str, actual: str, safe: bool) -> None:
        res.append({"scenario": name, "expected": expected, "actual": actual, "safe": bool(safe)})

    # 1. runtime failure (fuel exhaustion)
    files = read_package(package)
    eng = PolicyEngine(files["policy.wasm"], json.loads(files["policy.json"]))
    import wasmtime

    def boom(*a: Any) -> None:
        raise wasmtime.WasmtimeError("injected runtime trap")
    eng.wasm._fn["authorize"] = boom  # inject a trap into the sandbox call path
    d = eng.evaluate(req)
    add("Runtime failure (injected WASM trap)", "deny (fail-closed)", d.decision + " / " + d.reason, d.decision == "deny" and d.reason == "runtime-failure")
    # 2. missing policy module
    h = PolicyHost(keys)
    d = h.evaluate(req)
    add("Missing policy module", "deny (fail-closed)", d.decision, d.decision == "deny")
    # 3. invalid artifact
    h = PolicyHost(keys)
    h.activate(h.load(package))
    bad = dict(files)
    bad["policy.wasm"] = b"\x00asm-not-a-module"
    try:
        h.load(make_package(bad))
        add("Invalid artifact", "load rejected, previous version kept", "loaded", False)
    except Exception as exc:
        add("Invalid artifact", "load rejected, previous version kept", type(exc).__name__, h.evaluate(req).decision in ("deny", "allow") and h.status()["active"] is not None)
    # 4. signature failure (tampered wasm)
    tampered = dict(files)
    tampered["policy.wasm"] = files["policy.wasm"] + b"\x00"
    try:
        PolicyHost(keys).load(make_package(tampered))
        add("Signature failure (tampered module)", "load rejected", "loaded", False)
    except ValueError as exc:
        add("Signature failure (tampered module)", "load rejected", str(exc)[:60], True)
    # 5. version mismatch (validly signed, incompatible format)
    m = json.loads(files["manifest.json"])
    m["format"] = "threadzero-package/9"
    mt = canonical_json(m)
    incompatible = dict(files)
    incompatible["manifest.json"] = mt
    incompatible["SIGNATURE.json"] = json.dumps(sign_bytes(ws, mt.encode()))
    try:
        PolicyHost(None).load(make_package(incompatible))
        add("Version mismatch", "load rejected", "loaded", False)
    except ValueError as exc:
        add("Version mismatch", "load rejected", str(exc)[:60], True)
    # 6. host API failure (module asks for a non-allow-listed capability)
    import wasmtime
    wasm = bytes(wasmtime.wat2wasm('(module (import "env" "read_secret" (func (result i32))) (memory (export "memory") 1) (func (export "abi_version") (result i32) (i32.const 1)))'))
    try:
        WasmPolicy(wasm)
        add("Host API failure (non-allow-listed import)", "load rejected", "loaded", False)
    except PolicyLoadError as exc:
        add("Host API failure (non-allow-listed import)", "load rejected", str(exc)[:70], True)
    # 7. network failure
    r = distribute(package, ["http://127.0.0.1:9"], timeout=1.0)
    add("Network failure during distribution", "error reported, no state change", r[0].get("error", "ok")[:60], not r[0]["ok"])
    # 8. rollback
    h = PolicyHost(keys)
    a = h.load(package)
    h.activate(a)
    b = h.load(package)
    h.activate(b)
    back = h.rollback()
    add("Rollback after bad version", f"active = {a}", str(back), back == a)
    return res
