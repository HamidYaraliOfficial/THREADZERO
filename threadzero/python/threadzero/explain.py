"""Authorization Reasoning Graph: why a request was allowed/denied (rules, atoms, precedence)."""
from __future__ import annotations

from .abi import DECISIONS, Symbols, full_slots, eval_expr
from .runtime import PolicyEngine

CMP = {"ge": ">=", "gt": ">", "le": "<=", "lt": "<"}


def _val(S: Symbols, slot: str, v: int) -> str:
    tbl = {"szone": "zone", "rzone": "zone", "zone": "zone", "res": "node", "subj": "node", "data": "data", "action": "action", "env": "env", "loc": "loc"}
    if slot in tbl:
        return S.name_of(tbl[slot], v) or "∅"
    if slot == "roles":
        return "|".join(S.role_names(v)) or str(v)
    if slot == "reskind":
        return S.node_kinds[v] if 0 <= v < len(S.node_kinds) else "∅"
    if slot == "zkind":
        return S.zone_kinds[v] if 0 <= v < len(S.zone_kinds) else "∅"
    if slot in ("class", "clearance"):
        return next((n for n, r in S.classes.items() if r == v), str(v))
    return str(v)


def expr_tree(e: dict, S: Symbols, s: dict[str, int]) -> dict:
    op = e["op"]
    ok = eval_expr(e, s)
    if op in ("and", "or"):
        return {"op": op, "value": ok, "children": [expr_tree(x, S, s) for x in e["args"]]}
    if op == "not":
        return {"op": "not", "value": ok, "children": [expr_tree(e["arg"], S, s)]}
    if op in ("true", "false"):
        return {"op": op, "value": ok, "text": op}
    slot = e.get("slot", "")
    actual = _val(S, slot, s.get(slot, 0)) if slot else ""
    if op == "eq":
        text = f"{slot} == {_val(S, slot, e['val'])}"
    elif op == "has":
        text = f"{slot} has {_val(S, slot, e['mask'])}"
    elif op in CMP:
        text = f"{slot} {CMP[op]} {_val(S, slot, e['val'])}"
    elif op == "in":
        text = f"{slot} in [{', '.join(_val(S, slot, v) for v in e['vals'])}]"
    elif op == "flag":
        text = slot
    elif op == "win":
        text = "in window " + str(e["id"])
        actual = f"minute-of-week {s['mow']}"
    else:
        text = f"{slot} {e.get('cmp')} {e.get('slot2')}"
    return {"op": op, "value": ok, "text": text, "actual": actual}


def explain_decision(engine: PolicyEngine, request: dict) -> dict:
    S = engine.symbols
    slots = S.encode(request)
    d = engine.authorize_slots(slots)
    d.audit = engine.audit(slots, d.code)
    s = full_slots(slots)
    rules = []
    for r in engine.rules:
        matched = eval_expr(r["cond"], s)
        rules.append({"idx": r["idx"], "id": r["id"], "effect": r["effect"], "priority": r["priority"], "specificity": r["specificity"],
                      "matched": matched, "won": d.reason == r["id"], "condText": r["condText"], "reason": r["reason"], "line": r["line"], "file": r["file"],
                      "obligations": r["obligations"], "tree": expr_tree(r["cond"], S, s) if matched or len(engine.rules) <= 40 else None})
    steps = []
    winner = next((x for x in rules if x["matched"] and x["effect"] in ("allow", "deny")), None)
    steps.append(f"{sum(1 for x in rules if x['matched'])} of {len(rules)} rules matched the request")
    if winner:
        steps.append(f"highest-precedence terminal rule: {winner['id']} ({winner['effect']}, priority {winner['priority']}, specificity {winner['specificity']})")
    else:
        steps.append("no terminal (allow/deny) rule matched — default deny applies")
    if d.decision in ("require_mfa", "require_approval", "quarantine") or (d.decision == "deny" and winner and winner["effect"] == "allow"):
        steps.append(f"an obligation rule ({d.reason}) turned the allow into '{d.decision}'")
    steps.append(f"final decision: {d.decision}" + (f" — {d.reason_text}" if d.reason_text else ""))
    nodes = [{"id": "request", "type": "request", "label": "request"}] + \
            [{"id": r["id"], "type": "rule", "label": r["id"], "matched": r["matched"], "won": r["won"], "effect": r["effect"]} for r in rules if r["matched"]] + \
            [{"id": "decision", "type": "decision", "label": d.decision}]
    edges = [{"from": "request", "to": r["id"]} for r in rules if r["matched"]] + [{"from": r["id"], "to": "decision", "won": r["won"]} for r in rules if r["matched"]]
    return {"decision": d.to_dict(), "request": S.decode(slots), "rules": rules, "steps": steps, "graph": {"nodes": nodes, "edges": edges},
            "context": engine.inspect_context(request)}
