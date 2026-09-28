"""Change impact, security regression, dependency queries and architecture comparison."""
from __future__ import annotations

import random
from collections import deque
from typing import Any

from .abi import Symbols
from .runtime import PolicyEngine
from .testing import random_request

SEV_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


def _by_fp(A: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for f in A["findings"]:
        out.setdefault(f["fingerprint"], f)
    return out


def diff_analyses(base: dict, head: dict) -> dict:
    fb, fh = _by_fp(base), _by_fp(head)
    new = [fh[k] for k in fh if k not in fb]
    fixed = [fb[k] for k in fb if k not in fh]
    remaining = [fh[k] for k in fh if k in fb]
    props = [{"name": a["name"], "base": a["status"], "head": b["status"], "changed": a["status"] != b["status"]}
             for a, b in zip(base["properties"], head["properties"])]
    ab = {a["name"]: a["status"] for a in base["assertions"]}
    ah = {a["name"]: a["status"] for a in head["assertions"]}
    assertions = [{"name": n, "base": ab.get(n, "absent"), "head": ah.get(n, "absent")} for n in sorted(set(ab) | set(ah)) if ab.get(n) != ah.get(n)]
    rb = {r["id"]: r for r in base["policy"]["rules"]}
    rh = {r["id"]: r for r in head["policy"]["rules"]}
    rules = {"added": sorted(set(rh) - set(rb)), "removed": sorted(set(rb) - set(rh)),
             "changed": sorted(k for k in set(rb) & set(rh) if (rb[k]["condText"], rb[k]["effect"], rb[k]["priority"], rb[k]["obligations"]) != (rh[k]["condText"], rh[k]["effect"], rh[k]["priority"], rh[k]["obligations"]))}
    nb = {n["id"]: n for n in base["graph"]["nodes"]}
    nh = {n["id"]: n for n in head["graph"]["nodes"]}
    eb = {e["id"]: e for e in base["graph"]["edges"]}
    eh = {e["id"]: e for e in head["graph"]["edges"]}
    graph = {"nodesAdded": sorted(set(nh) - set(nb)), "nodesRemoved": sorted(set(nb) - set(nh)),
             "edgesAdded": sorted(set(eh) - set(eb)), "edgesRemoved": sorted(set(eb) - set(eh)),
             "edgesChanged": sorted(k for k in set(eb) & set(eh) if (eb[k]["controls"], eb[k]["data"], eb[k]["from"], eb[k]["to"], eb[k]["channel"]) != (eh[k]["controls"], eh[k]["data"], eh[k]["from"], eh[k]["to"], eh[k]["channel"])),
             "crossingsBase": sum(1 for e in eb.values() if e["crossing"]), "crossingsHead": sum(1 for e in eh.values() if e["crossing"])}
    cov = lambda A: (lambda c: round(100 * sum(1 for x in c if x["covered"]) / len(c), 1) if c else 100.0)(A["policy"]["coverage"])  # noqa: E731
    errs = lambda A: [d for d in A["diagnostics"] if d["severity"] == "error"]  # noqa: E731
    return {"findings": {"new": new, "fixed": fixed, "remaining": remaining}, "properties": props, "assertions": assertions, "rules": rules, "graph": graph,
            "coverage": {"base": cov(base), "head": cov(head)}, "errors": {"base": len(errs(base)), "head": len(errs(head))},
            "metrics": {k: {"base": base["metrics"].get(k), "head": head["metrics"].get(k)} for k in ("nodes", "flows", "zones", "rules", "boundaryCrossings", "guardedNodes")},
            "gate": {"newCritical": sum(1 for f in new if f["severity"] == "Critical"), "newHigh": sum(1 for f in new if f["severity"] == "High"),
                     "newErrors": max(0, len(errs(head)) - len(errs(base))), "regressedProperties": [p["name"] for p in props if p["base"] == "holds" and p["head"] == "violated"],
                     "newViolatedAssertions": [a["name"] for a in assertions if a["head"] == "violated"]}}


def regression(base: dict, head: dict, base_engine: PolicyEngine, head_engine: PolicyEngine, n: int = 300, seed: int = 5) -> dict:
    """Replay base generated tests + random requests against the head policy; report every decision change."""
    Sb, Sh = base_engine.symbols, head_engine.symbols
    reqs = [Sb.decode(t["request"]) for t in base["policy"]["tests"]]
    rnd = random.Random(seed)
    reqs += [random_request(rnd, Sb) for _ in range(n)]
    changes, unmappable, same = [], 0, 0
    for r in reqs:
        names = [r.get("data"), r.get("zone"), r.get("resource"), r.get("action")]
        if any(x and (x not in Sh.data and x not in Sh.zones and x not in Sh.nodes and x not in Sh.actions) for x in names):
            unmappable += 1
            continue
        try:
            db, dh = base_engine.authorize_slots(Sb.encode(r)), head_engine.authorize_slots(Sh.encode(r))
        except Exception:
            unmappable += 1
            continue
        if db.decision != dh.decision:
            changes.append({"request": r, "base": db.decision, "head": dh.decision, "baseReason": db.reason, "headReason": dh.reason,
                            "kind": "loosened" if dh.decision == "allow" and db.decision != "allow" else "tightened" if db.decision == "allow" else "changed"})
        else:
            same += 1
    return {"replayed": same + len(changes), "unchanged": same, "unmappable": unmappable, "changes": changes[:200], "changeCount": len(changes),
            "loosened": sum(1 for c in changes if c["kind"] == "loosened"), "tightened": sum(1 for c in changes if c["kind"] == "tightened")}


def dependency_impact(A: dict, entity: str, direction: str = "dependents") -> dict:
    """Entities are prefixed ('data:Card', 'zone:Backend', 'node:Api', 'policy:X', 'flow:F')."""
    edges = A["dependencies"]
    if ":" not in entity:
        for kind in ("node", "data", "zone", "flow", "policy", "role"):
            if any(entity in (e["from"], e["to"]) or f"{kind}:{entity}" in (e["from"], e["to"]) for e in edges):
                entity = f"{kind}:{entity}"
                break
    fwd: dict[str, list[dict]] = {}
    rev: dict[str, list[dict]] = {}
    for e in edges:
        fwd.setdefault(e["from"], []).append(e)
        rev.setdefault(e["to"], []).append(e)
    graph = rev if direction == "dependents" else fwd
    seen, order, q = {entity}, [], deque([(entity, 0)])
    paths = []
    while q:
        cur, depth = q.popleft()
        for e in graph.get(cur, []):
            nxt = e["from"] if direction == "dependents" else e["to"]
            if nxt not in seen:
                seen.add(nxt)
                order.append({"entity": nxt, "depth": depth + 1, "via": e["kind"], "from": cur})
                q.append((nxt, depth + 1))
            paths.append({"from": e["from"], "to": e["to"], "kind": e["kind"]})
    groups: dict[str, list[str]] = {}
    for o in order:
        groups.setdefault(o["entity"].split(":")[0], []).append(o["entity"].split(":", 1)[1])
    return {"entity": entity, "direction": direction, "impacted": order, "groups": groups, "edges": paths}


def history(snapshots: list[dict]) -> list[dict]:
    return [{"id": s["id"], "created": s["created"], "label": s.get("label", ""), **{k: s["metrics"].get(k) for k in ("nodes", "flows", "zones", "rules", "boundaryCrossings")},
             "findings": sum(s["metrics"]["findingsBySeverity"].values()), "critical": s["metrics"]["findingsBySeverity"].get("Critical", 0),
             "high": s["metrics"]["findingsBySeverity"].get("High", 0)} for s in snapshots]


def compare_architectures(named: dict[str, dict]) -> dict:
    """Counterfactual Architecture Lab: side-by-side technical metrics — deliberately no single overall score."""
    rows = []
    for name, A in named.items():
        sev = A["metrics"]["findingsBySeverity"]
        cov = A["policy"]["coverage"]
        rows.append({"name": name, "ok": A["ok"], "errors": A["errorCount"], "findings": sum(sev.values()), "bySeverity": sev,
                     "boundaryCrossings": A["metrics"]["boundaryCrossings"], "flows": A["metrics"]["flows"], "nodes": A["metrics"]["nodes"],
                     "rules": A["metrics"]["rules"], "policyCoveragePct": round(100 * sum(1 for c in cov if c["covered"]) / len(cov), 1) if cov else 100.0,
                     "propertiesHolding": sum(1 for p in A["properties"] if p["status"] == "holds"), "propertiesTotal": len(A["properties"]),
                     "assertionsViolated": sum(1 for a in A["assertions"] if a["status"] == "violated"),
                     "conflicts": len(A["policy"]["conflicts"]), "sourceHash": A["sourceHash"][:12]})
    return {"rows": rows, "note": "Compare metrics individually; THREADZERO intentionally does not collapse them into one score."}
