"""Policy Execution ABI: symbol tables, request encoding, and the reference decision engine."""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

# --- ABI layout (must match the generated WASM) ---------------------------------------
INFIELDS = ["subj", "roles", "szone", "mfa", "dtrust", "clearance", "res", "reskind", "rzone", "action",
            "data", "class", "zone", "ztrust", "zkind", "env", "loc", "mow", "flags", "src_zone",
            "dst_zone", "controls", "decision_in"]
IN_OFF, OUT_OFF, MATCH_OFF, MAX_MATCH, TABLE_BASE = 0, 256, 64, 1000, 8192
DEFAULTS = {"subj": -1, "roles": 0, "szone": -1, "mfa": 0, "dtrust": 0, "clearance": 0, "res": -1, "reskind": -1,
            "rzone": -1, "action": -1, "data": -1, "class": 0, "zone": -1, "ztrust": 0, "zkind": -1, "env": -1,
            "loc": -1, "mow": 0, "flags": 0, "src_zone": -1, "dst_zone": -1, "controls": 0, "decision_in": 0}
FLAG_BITS = {"approved": 1, "emergency": 2, "secure": 4, "tenant": 8}
DECISIONS = {0: "deny", 1: "allow", 2: "require_mfa", 3: "require_approval", 4: "quarantine"}
FLOW_REASONS = {0: "ok", 1: "data type not allowed in destination zone", 2: "operation not permitted for data type",
                3: "missing required boundary controls", 4: "classification exceeds destination zone limit",
                5: "export denied for data type", 6: "export requires approval control", 9: "unknown zone",
                10: "assertion: data must never enter zone", 11: "assertion: direct operation forbidden",
                12: "assertion: operation forbidden for data", 13: "assertion: operation forbidden for class",
                14: "assertion: required control missing for action", 15: "assertion: secure channel required"}
CONTEXT_FLAGS = {1: "no-mfa", 2: "low-device-trust", 4: "outside-open-window", 8: "emergency", 16: "low-trust-zone", 32: "insecure-channel"}


def pack_request(slots: dict[str, int]) -> bytes:
    """Numeric slot dict (incl. approved/emergency/secure/tenant booleans) -> ABI struct bytes."""
    s = dict(DEFAULTS)
    for k, v in slots.items():
        if k in FLAG_BITS:
            if v:
                s["flags"] |= FLAG_BITS[k]
        elif k in s:
            s[k] = int(v)
    return struct.pack("<%di" % len(INFIELDS), *[s[f] for f in INFIELDS])


def full_slots(slots: dict[str, int]) -> dict[str, int]:
    s = dict(DEFAULTS)
    s.update({k: int(v) for k, v in slots.items() if k not in FLAG_BITS})
    for k, bit in FLAG_BITS.items():
        if slots.get(k):
            s["flags"] |= bit
    for k, bit in FLAG_BITS.items():
        s[k] = 1 if s["flags"] & bit else 0
    return s


# --- Symbols ---------------------------------------------------------------------------
@dataclass
class Symbols:
    roles: dict[str, int] = field(default_factory=dict)      # name -> bit mask
    zones: dict[str, dict] = field(default_factory=dict)
    actions: dict[str, int] = field(default_factory=dict)
    data: dict[str, dict] = field(default_factory=dict)
    nodes: dict[str, dict] = field(default_factory=dict)
    envs: dict[str, int] = field(default_factory=dict)
    locs: dict[str, int] = field(default_factory=dict)
    classes: dict[str, int] = field(default_factory=dict)
    zone_kinds: list[str] = field(default_factory=list)
    node_kinds: list[str] = field(default_factory=list)
    controls: dict[str, int] = field(default_factory=dict)
    effects: dict[str, dict] = field(default_factory=dict)
    tz: str = "UTC"

    @staticmethod
    def from_analysis(a: dict) -> "Symbols":
        s = a["symbols"]
        return Symbols(
            roles={r["name"]: r["bit"] for r in s["roles"]}, zones={z["name"]: z for z in s["zones"]},
            actions={x["name"]: x["id"] for x in s["actions"]}, data={d["name"]: d for d in s["data"]},
            nodes={n["name"]: n for n in s["nodes"]}, envs={e["name"]: e["id"] for e in s["envs"]},
            locs={e["name"]: e["id"] for e in s["locations"]}, classes={c["name"]: c["rank"] for c in s["classes"]},
            zone_kinds=s["zoneKinds"], node_kinds=s["nodeKinds"], controls={c["name"]: c["bit"] for c in s["controls"]},
            effects={e["name"]: e for e in s["effects"]}, tz=a["project"]["timezone"])

    # id -> name helpers
    def name_of(self, table: str, ident: int) -> str:
        if ident < 0:
            return ""
        if table == "zone":
            return next((n for n, z in self.zones.items() if z["id"] == ident), str(ident))
        if table == "node":
            return next((n for n, z in self.nodes.items() if z["id"] == ident), str(ident))
        if table == "data":
            return next((n for n, z in self.data.items() if z["id"] == ident), str(ident))
        if table == "action":
            return next((n for n, i in self.actions.items() if i == ident), str(ident))
        if table == "env":
            return next((n for n, i in self.envs.items() if i == ident), str(ident))
        if table == "loc":
            return next((n for n, i in self.locs.items() if i == ident), str(ident))
        return str(ident)

    def role_names(self, mask: int) -> list[str]:
        return [n for n, b in self.roles.items() if mask & b]

    def control_names(self, mask: int) -> list[str]:
        return [n for n, b in self.controls.items() if mask & b]

    def control_mask(self, names: list[str]) -> int:
        m = 0
        for n in names:
            m |= self.controls.get(n, 0)
        return m

    def obligations(self, mask: int) -> list[str]:
        return [n for n, e in self.effects.items() if not e["terminal"] and mask & e["bit"]]

    def mow(self, when: datetime | str | None) -> int:
        if when is None:
            when = datetime.now(ZoneInfo(self.tz))
        if isinstance(when, str):
            when = datetime.fromisoformat(when)
        if when.tzinfo is None:
            when = when.replace(tzinfo=ZoneInfo(self.tz))
        local = when.astimezone(ZoneInfo(self.tz))
        return local.weekday() * 1440 + local.hour * 60 + local.minute

    # request (names) -> numeric slots
    def encode(self, req: dict) -> dict[str, int]:
        s: dict[str, int] = {}
        subj = req.get("subject", {})
        if isinstance(subj, str):
            subj = {"id": subj}
        roles = subj.get("roles", [])
        s["roles"] = sum(self.roles.get(r, 0) for r in roles)
        if subj.get("id") in self.nodes:
            s["subj"] = self.nodes[subj["id"]]["id"]
        if subj.get("zone") in self.zones:
            s["szone"] = self.zones[subj["zone"]]["id"]
        s["mfa"] = 1 if subj.get("mfa") else 0
        s["dtrust"] = int(subj.get("device_trust", 0))
        if subj.get("clearance") in self.classes:
            s["clearance"] = self.classes[subj["clearance"]]
        res = req.get("resource")
        if isinstance(res, dict):
            res = res.get("name")
        if res in self.nodes:
            n = self.nodes[res]
            s["res"] = n["id"]
            s["reskind"] = self.node_kinds.index(n["kind"])
            s["rzone"] = n["zoneId"]
        if req.get("action") in self.actions:
            s["action"] = self.actions[req["action"]]
        d = req.get("data")
        if isinstance(d, dict):
            d = d.get("name")
        if d in self.data:
            s["data"] = self.data[d]["id"]
            s["class"] = self.data[d]["rank"]
        z = req.get("zone")
        if isinstance(z, dict):
            z = z.get("name")
        if z in self.zones:
            zz = self.zones[z]
            s["zone"] = zz["id"]
            s["ztrust"] = zz["trust"]
            s["zkind"] = zz["kindId"]
        if req.get("env") in self.envs:
            s["env"] = self.envs[req["env"]]
        ctx = req.get("context", {})
        if ctx.get("location") in self.locs:
            s["loc"] = self.locs[ctx["location"]]
        if "time" in ctx:
            s["mow"] = int(ctx["time"])
        elif "timestamp" in ctx:
            s["mow"] = self.mow(ctx["timestamp"])
        for k, key in (("approved", "approved"), ("emergency", "emergency"), ("secure", "secure_channel"), ("tenant", "tenant_match")):
            s[k] = 1 if ctx.get(key) else 0
        flow = req.get("flow")
        if flow:
            if flow.get("src_zone") in self.zones:
                s["src_zone"] = self.zones[flow["src_zone"]]["id"]
            if flow.get("dst_zone") in self.zones:
                s["dst_zone"] = self.zones[flow["dst_zone"]]["id"]
            s["controls"] = self.control_mask(flow.get("controls", []))
            if flow.get("source") in self.nodes:
                s["subj"] = self.nodes[flow["source"]]["id"]
            if flow.get("destination") in self.nodes:
                s["res"] = self.nodes[flow["destination"]]["id"]
        return s

    # numeric slots -> request (names): inverse of encode (for Rego/JSON targets and UI display)
    def decode(self, slots: dict[str, int]) -> dict:
        v = full_slots(slots)
        req: dict[str, Any] = {"subject": {"roles": self.role_names(v["roles"]), "mfa": bool(v["mfa"]), "device_trust": v["dtrust"]},
                               "context": {"time": v["mow"], "approved": bool(v["approved"]), "emergency": bool(v["emergency"]),
                                           "secure_channel": bool(v["secure"]), "tenant_match": bool(v["tenant"])}}
        if v["subj"] >= 0:
            req["subject"]["id"] = self.name_of("node", v["subj"])
        if v["szone"] >= 0:
            req["subject"]["zone"] = self.name_of("zone", v["szone"])
        cl = next((n for n, r in self.classes.items() if r == v["clearance"]), None)
        if cl and v["clearance"]:
            req["subject"]["clearance"] = cl
        if v["res"] >= 0:
            req["resource"] = self.name_of("node", v["res"])
        if v["action"] >= 0:
            req["action"] = self.name_of("action", v["action"])
        if v["data"] >= 0:
            req["data"] = self.name_of("data", v["data"])
        if v["zone"] >= 0:
            req["zone"] = self.name_of("zone", v["zone"])
        if v["env"] >= 0:
            req["env"] = self.name_of("env", v["env"])
        if v["loc"] >= 0:
            req["context"]["location"] = self.name_of("loc", v["loc"])
        return req


# --- reference decision engine (pure Python, independent of WASM) -----------------------
def eval_expr(e: dict, s: dict[str, int]) -> bool:
    op = e["op"]
    if op == "true":
        return True
    if op == "false":
        return False
    if op == "not":
        return not eval_expr(e["arg"], s)
    if op == "and":
        return all(eval_expr(x, s) for x in e["args"])
    if op == "or":
        return any(eval_expr(x, s) for x in e["args"])
    if op == "eq":
        return s[e["slot"]] == e["val"]
    if op == "has":
        return (s[e["slot"]] & e["mask"]) != 0
    if op == "ge":
        return s[e["slot"]] >= e["val"]
    if op == "gt":
        return s[e["slot"]] > e["val"]
    if op == "le":
        return s[e["slot"]] <= e["val"]
    if op == "lt":
        return s[e["slot"]] < e["val"]
    if op == "in":
        return s[e["slot"]] in e["vals"]
    if op == "flag":
        return s[e["slot"]] == 1
    if op == "win":
        return any(a <= s["mow"] < b for a, b in e["ranges"])
    if op == "cmp":
        a, b = s[e["slot"]], s[e["slot2"]]
        return {"==": a == b, "!=": a != b, ">=": a >= b, "<=": a <= b, ">": a > b, "<": a < b}[e["cmp"]]
    raise ValueError(op)


def ref_decide(rules: list[dict], slots: dict[str, int]) -> dict:
    s = full_slots(slots)
    matched = [r for r in rules if eval_expr(r["cond"], s)]
    obl = 0
    for r in matched:
        obl |= r["obligationMask"]
    winner = next((r for r in matched if r["terminal"]), None)
    base = 1 if winner and winner["effect"] == "allow" else 0
    wreason = winner["idx"] if winner else -1

    def first(effect: str) -> int:
        for r in matched:
            if effect in r["obligations"]:
                return r["idx"]
        return -1
    code, reason = base, wreason
    if base == 1:
        if first("quarantine") != -1:
            code, reason = 4, first("quarantine")
        elif first("require_trusted_zone") != -1 and s["ztrust"] < 3:
            code, reason = 0, first("require_trusted_zone")
        elif first("require_mfa") != -1 and s["mfa"] == 0:
            code, reason = 2, first("require_mfa")
        elif first("require_approval") != -1 and s["approved"] == 0:
            code, reason = 3, first("require_approval")
    return {"decision": code, "reason": reason, "obligations": obl, "matched": [r["idx"] for r in matched]}
