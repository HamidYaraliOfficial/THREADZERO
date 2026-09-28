"""Policy compiler back end: IR -> WASM (via WAT), Rego, JSON artifact, JS/TS wrapper, guards."""
from __future__ import annotations

import json
import struct
from pathlib import Path

from .abi import (DEFAULTS, FLAG_BITS, INFIELDS, MATCH_OFF, MAX_MATCH, OUT_OFF, TABLE_BASE, Symbols)
from .core import canonical_json

LOCAL_SLOTS = [f for f in INFIELDS if f != "flags"]
DERIVED_FLAGS = {"approved": 1, "emergency": 2, "secure": 4, "tenant": 8}


def _i32s(vals: list[int]) -> bytes:
    return b"".join(struct.pack("<i", v) for v in vals)


def _esc(b: bytes) -> str:
    return "".join("\\%02x" % x for x in b)


class Layout:
    def __init__(self) -> None:
        self.cur, self.chunks, self.off = TABLE_BASE, [], {}

    def add(self, name: str, data: bytes) -> int:
        self.cur = (self.cur + 3) & ~3
        self.off[name] = self.cur
        self.chunks.append((self.cur, data))
        self.cur += len(data)
        return self.off[name]

    @property
    def pages(self) -> int:
        return max(1, (self.cur + 65535) // 65536 + 0)


def _fold(op: str, xs: list[str], empty: str) -> str:
    if not xs:
        return empty
    acc = xs[-1]
    for x in reversed(xs[:-1]):
        acc = f"({op} {x} {acc})"
    return acc


def _const(v: int) -> str:
    return f"(i32.const {v})"


def _loc(slot: str) -> str:
    return f"(local.get $s_{slot})"


def cond_wat(e: dict) -> str:
    op = e["op"]
    if op == "true":
        return _const(1)
    if op == "false":
        return _const(0)
    if op == "not":
        return f"(i32.eqz {cond_wat(e['arg'])})"
    if op == "and":
        return _fold("i32.and", [cond_wat(x) for x in e["args"]], _const(1))
    if op == "or":
        return _fold("i32.or", [cond_wat(x) for x in e["args"]], _const(0))
    if op == "eq":
        return f"(i32.eq {_loc(e['slot'])} {_const(e['val'])})"
    if op == "has":
        return f"(i32.ne (i32.and {_loc(e['slot'])} {_const(e['mask'])}) {_const(0)})"
    if op in ("ge", "gt", "le", "lt"):
        return f"(i32.{op}_s {_loc(e['slot'])} {_const(e['val'])})"
    if op == "in":
        return _fold("i32.or", [f"(i32.eq {_loc(e['slot'])} {_const(v)})" for v in e["vals"]], _const(0))
    if op == "flag":
        return f"(i32.eq {_loc(e['slot'])} {_const(1)})"
    if op == "win":
        return _fold("i32.or", [f"(i32.and (i32.ge_s {_loc('mow')} {_const(a)}) (i32.lt_s {_loc('mow')} {_const(b)}))"
                                for a, b in e["ranges"]], _const(0))
    if op == "cmp":
        name = {"==": "eq", "!=": "ne", ">=": "ge_s", "<=": "le_s", ">": "gt_s", "<": "lt_s"}[e["cmp"]]
        return f"(i32.{name} {_loc(e['slot'])} {_loc(e['slot2'])})"
    raise ValueError(f"unknown expression op {op}")


def _prologue(slots: list[str]) -> str:
    out = []
    for i, f in enumerate(INFIELDS):
        if f in slots or f == "flags":
            out.append(f"(local.set $s_{f} (i32.load offset={4 * i} (local.get $inp)))")
    for name, bit in DERIVED_FLAGS.items():
        if name in slots:
            out.append(f"(local.set $s_{name} (i32.and (i32.shr_u (local.get $s_flags) {_const(bit.bit_length() - 1)}) {_const(1)}))")
    return "\n    ".join(out)


def _locals(names: list[str]) -> str:
    return " ".join(f"(local $s_{n} i32)" for n in names)


def gen_wat(A: dict) -> str:
    pol = A["policy"]
    rules, T, checks, wins = pol["rules"], pol["tables"], pol["runtimeChecks"], pol["windows"]
    nz, nc, ng, na = T["nz"], T["nc"], T["ng"], T["na"]
    nd = len(T["dataClass"])
    lay = Layout()
    lay.add("req", _i32s(T["required"]))
    lay.add("ag", _i32s(T["actionGroup"]))
    lay.add("dz", _i32s(T["dataZone"]))
    lay.add("ops", _i32s(T["dataOps"]))
    lay.add("dcls", _i32s(T["dataClass"]))
    lay.add("dexp", _i32s(T["dataExport"]))
    lay.add("zmax", _i32s(T["zoneMax"]))
    o = lay.off
    all_slots = LOCAL_SLOTS + list(DERIVED_FLAGS)
    open_ranges = [r for w in wins if w["kind"] == "open" for r in w["ranges"]]

    def required_fn() -> str:
        return f"""
  (func $required (param $src i32) (param $dst i32) (param $cls i32) (param $act i32) (result i32)
    (local $g i32) (local $c i32)
    (local.set $g (i32.const 0))
    (if (i32.and (i32.ge_s (local.get $act) (i32.const 0)) (i32.lt_s (local.get $act) (i32.const {na})))
      (then (local.set $g (i32.load (i32.add (i32.const {o['ag']}) (i32.shl (local.get $act) (i32.const 2)))))))
    (local.set $c (local.get $cls))
    (if (i32.lt_s (local.get $c) (i32.const 0)) (then (local.set $c (i32.const 0))))
    (if (i32.ge_s (local.get $c) (i32.const {nc})) (then (local.set $c (i32.const {nc - 1}))))
    (i32.load (i32.add (i32.const {o['req']})
      (i32.shl (i32.add (i32.mul (i32.add (i32.mul (i32.add (i32.mul (local.get $src) (i32.const {nz})) (local.get $dst)) (i32.const {nc})) (local.get $c)) (i32.const {ng})) (local.get $g)) (i32.const 2)))))"""

    # ---- authorize ----
    blocks = []
    for r in rules:
        i = r["idx"]
        parts = [
            f"(if (i32.lt_u (local.get $nm) (i32.const {MAX_MATCH})) (then (i32.store (i32.add (i32.add (local.get $out) (i32.const {MATCH_OFF})) (i32.shl (local.get $nm) (i32.const 2))) (i32.const {i}))))",
            "(local.set $nm (i32.add (local.get $nm) (i32.const 1)))",
        ]
        if r["obligationMask"]:
            parts.append(f"(local.set $obl (i32.or (local.get $obl) (i32.const {r['obligationMask']})))")
        if r["terminal"]:
            parts.append(f"(if (i32.eqz (local.get $decided)) (then (local.set $decided (i32.const 1)) (local.set $base (i32.const {1 if r['effect'] == 'allow' else 0})) (local.set $wreason (i32.const {i}))))")
        for eff, loc in (("quarantine", "$q"), ("require_trusted_zone", "$tz"), ("require_mfa", "$mf"), ("require_approval", "$ap")):
            if eff in r["obligations"]:
                parts.append(f"(if (i32.eq (local.get {loc}) (i32.const -1)) (then (local.set {loc} (i32.const {i}))))")
        blocks.append(f"    ;; rule {i}: {r['id']} ({r['effect']})\n    (if {cond_wat(r['cond'])}\n      (then {' '.join(parts)}))")
    authorize = f"""
  (func $authorize (export "authorize") (param $inp i32) (param $out i32) (result i32)
    {_locals(all_slots)}
    (local $s_flags i32)
    (local $obl i32) (local $nm i32) (local $decided i32) (local $base i32) (local $wreason i32)
    (local $q i32) (local $tz i32) (local $mf i32) (local $ap i32) (local $dec i32) (local $reason i32) (local $done i32)
    (local.set $wreason (i32.const -1)) (local.set $q (i32.const -1)) (local.set $tz (i32.const -1))
    (local.set $mf (i32.const -1)) (local.set $ap (i32.const -1))
    {_prologue(all_slots)}
{chr(10).join(blocks)}
    (local.set $dec (i32.const 0))
    (local.set $reason (local.get $wreason))
    (if (local.get $base) (then
      (local.set $dec (i32.const 1))
      (if (i32.ne (local.get $q) (i32.const -1)) (then (local.set $dec (i32.const 4)) (local.set $reason (local.get $q)) (local.set $done (i32.const 1))))
      (if (i32.and (i32.eqz (local.get $done)) (i32.and (i32.ne (local.get $tz) (i32.const -1)) (i32.lt_s (local.get $s_ztrust) (i32.const 3))))
        (then (local.set $dec (i32.const 0)) (local.set $reason (local.get $tz)) (local.set $done (i32.const 1))))
      (if (i32.and (i32.eqz (local.get $done)) (i32.and (i32.ne (local.get $mf) (i32.const -1)) (i32.eqz (local.get $s_mfa))))
        (then (local.set $dec (i32.const 2)) (local.set $reason (local.get $mf)) (local.set $done (i32.const 1))))
      (if (i32.and (i32.eqz (local.get $done)) (i32.and (i32.ne (local.get $ap) (i32.const -1)) (i32.eqz (local.get $s_approved))))
        (then (local.set $dec (i32.const 3)) (local.set $reason (local.get $ap)) (local.set $done (i32.const 1))))))
    (i32.store offset=0 (local.get $out) (local.get $dec))
    (i32.store offset=4 (local.get $out) (local.get $reason))
    (i32.store offset=8 (local.get $out) (local.get $obl))
    (i32.store offset=12 (local.get $out) (local.get $nm))
    (local.get $dec))"""

    # ---- validate_flow / validate_boundary ----
    chk = []
    for c in checks:
        k = c["kind"]
        if k == "never_enter":
            cond = f"(i32.and (i32.eq (local.get $data) {_const(c['data'])}) (i32.eq (local.get $dst) {_const(c['zone'])}))"; code = 10
        elif k == "must_not":
            cond = f"(i32.and (i32.eq (local.get $subj) {_const(c['subj'])}) (i32.and (i32.eq (local.get $action) {_const(c['action'])}) (i32.eq (local.get $res) {_const(c['res'])})))"; code = 11
        elif k == "never_op":
            cond = f"(i32.and (i32.eq (local.get $data) {_const(c['data'])}) (i32.eq (local.get $action) {_const(c['action'])}))"; code = 12
        elif k == "never_class_op":
            cond = f"(i32.and (i32.ge_s (local.get $class) {_const(c['rank'])}) (i32.eq (local.get $action) {_const(c['action'])}))"; code = 13
        elif k == "require_control":
            cond = f"(i32.and (i32.eq (local.get $action) {_const(c['action'])}) (i32.eqz (i32.and (local.get $controls) {_const(c['control'])})))"; code = 14
        elif k == "secure_flow":
            cond = f"(i32.and (i32.and (i32.eq (local.get $subj) {_const(c['subj'])}) (i32.eq (local.get $res) {_const(c['res'])})) (i32.eqz (local.get $secure)))"; code = 15
        elif k == "secure_crossing":
            cond = "(i32.and (i32.ne (local.get $src) (local.get $dst)) (i32.eqz (local.get $secure)))"; code = 15
        else:
            continue
        chk.append(f"    (if (i32.and (i32.eqz (local.get $fail)) {cond}) (then (local.set $fail (i32.const {code}))))  ;; assertion {c['name']}")
    export_action = T["exportAction"]
    validate_flow = f"""
  (func $validate_flow (export "validate_flow") (param $inp i32) (param $out i32) (result i32)
    (local $subj i32) (local $res i32) (local $action i32) (local $data i32) (local $class i32) (local $src i32) (local $dst i32)
    (local $controls i32) (local $flags i32) (local $secure i32) (local $fail i32) (local $req i32) (local $miss i32)
    (local $dcls i32) (local $ops i32) (local $zmax i32) (local $ex i32)
    (local.set $subj (i32.load offset={4 * INFIELDS.index('subj')} (local.get $inp)))
    (local.set $res (i32.load offset={4 * INFIELDS.index('res')} (local.get $inp)))
    (local.set $action (i32.load offset={4 * INFIELDS.index('action')} (local.get $inp)))
    (local.set $data (i32.load offset={4 * INFIELDS.index('data')} (local.get $inp)))
    (local.set $class (i32.load offset={4 * INFIELDS.index('class')} (local.get $inp)))
    (local.set $src (i32.load offset={4 * INFIELDS.index('src_zone')} (local.get $inp)))
    (local.set $dst (i32.load offset={4 * INFIELDS.index('dst_zone')} (local.get $inp)))
    (local.set $controls (i32.load offset={4 * INFIELDS.index('controls')} (local.get $inp)))
    (local.set $flags (i32.load offset={4 * INFIELDS.index('flags')} (local.get $inp)))
    (local.set $secure (i32.and (i32.shr_u (local.get $flags) (i32.const 2)) (i32.const 1)))
    (if (i32.or (i32.or (i32.lt_s (local.get $src) (i32.const 0)) (i32.ge_s (local.get $src) (i32.const {nz})))
                (i32.or (i32.lt_s (local.get $dst) (i32.const 0)) (i32.ge_s (local.get $dst) (i32.const {nz}))))
      (then (local.set $fail (i32.const 9))))
    (if (i32.and (i32.eqz (local.get $fail)) (i32.and (i32.ge_s (local.get $data) (i32.const 0)) (i32.lt_s (local.get $data) (i32.const {nd}))))
      (then
        (local.set $dcls (i32.load (i32.add (i32.const {o['dcls']}) (i32.shl (local.get $data) (i32.const 2)))))
        (local.set $class (local.get $dcls))
        (if (i32.eqz (i32.load (i32.add (i32.const {o['dz']}) (i32.shl (i32.add (i32.mul (local.get $data) (i32.const {nz})) (local.get $dst)) (i32.const 2)))))
          (then (local.set $fail (i32.const 1))))
        (if (i32.and (i32.eqz (local.get $fail)) (i32.and (i32.ge_s (local.get $action) (i32.const 0)) (i32.lt_s (local.get $action) (i32.const 32))))
          (then
            (local.set $ops (i32.load (i32.add (i32.const {o['ops']}) (i32.shl (local.get $data) (i32.const 2)))))
            (if (i32.eqz (i32.and (i32.shr_u (local.get $ops) (local.get $action)) (i32.const 1))) (then (local.set $fail (i32.const 2))))))
        (local.set $zmax (i32.load (i32.add (i32.const {o['zmax']}) (i32.shl (local.get $dst) (i32.const 2)))))
        (if (i32.and (i32.eqz (local.get $fail)) (i32.and (i32.ge_s (local.get $zmax) (i32.const 0)) (i32.gt_s (local.get $dcls) (local.get $zmax))))
          (then (local.set $fail (i32.const 4))))
        (if (i32.and (i32.eqz (local.get $fail)) (i32.and (i32.ge_s (i32.const {export_action}) (i32.const 0)) (i32.eq (local.get $action) (i32.const {export_action}))))
          (then
            (local.set $ex (i32.load (i32.add (i32.const {o['dexp']}) (i32.shl (local.get $data) (i32.const 2)))))
            (if (i32.eq (local.get $ex) (i32.const 2)) (then (local.set $fail (i32.const 5))))
            (if (i32.and (i32.eqz (local.get $fail)) (i32.eq (local.get $ex) (i32.const 1)))
              (then (if (i32.eqz (i32.and (local.get $controls) (i32.const {T['approvalBit']}))) (then (local.set $fail (i32.const 6))))))))))
{chr(10).join(chk)}
    (if (i32.eqz (local.get $fail))
      (then
        (local.set $req (call $required (local.get $src) (local.get $dst) (local.get $class) (local.get $action)))
        (local.set $miss (i32.and (local.get $req) (i32.xor (local.get $controls) (i32.const -1))))
        (if (i32.ne (local.get $miss) (i32.const 0)) (then (local.set $fail (i32.const 3))))))
    (i32.store offset=0 (local.get $out) (i32.eqz (local.get $fail)))
    (i32.store offset=4 (local.get $out) (local.get $fail))
    (i32.store offset=16 (local.get $out) (local.get $req))
    (i32.store offset=20 (local.get $out) (local.get $miss))
    (i32.eqz (local.get $fail)))

  (func $validate_boundary (export "validate_boundary") (param $inp i32) (param $out i32) (result i32)
    (local $src i32) (local $dst i32) (local $class i32) (local $action i32) (local $controls i32) (local $req i32) (local $miss i32) (local $fail i32)
    (local.set $src (i32.load offset={4 * INFIELDS.index('src_zone')} (local.get $inp)))
    (local.set $dst (i32.load offset={4 * INFIELDS.index('dst_zone')} (local.get $inp)))
    (local.set $class (i32.load offset={4 * INFIELDS.index('class')} (local.get $inp)))
    (local.set $action (i32.load offset={4 * INFIELDS.index('action')} (local.get $inp)))
    (local.set $controls (i32.load offset={4 * INFIELDS.index('controls')} (local.get $inp)))
    (if (i32.or (i32.or (i32.lt_s (local.get $src) (i32.const 0)) (i32.ge_s (local.get $src) (i32.const {nz})))
                (i32.or (i32.lt_s (local.get $dst) (i32.const 0)) (i32.ge_s (local.get $dst) (i32.const {nz}))))
      (then (local.set $fail (i32.const 9)))
      (else
        (local.set $req (call $required (local.get $src) (local.get $dst) (local.get $class) (local.get $action)))
        (local.set $miss (i32.and (local.get $req) (i32.xor (local.get $controls) (i32.const -1))))
        (if (i32.ne (local.get $miss) (i32.const 0)) (then (local.set $fail (i32.const 3))))))
    (i32.store offset=0 (local.get $out) (i32.eqz (local.get $fail)))
    (i32.store offset=4 (local.get $out) (local.get $fail))
    (i32.store offset=16 (local.get $out) (local.get $req))
    (i32.store offset=20 (local.get $out) (local.get $miss))
    (i32.eqz (local.get $fail)))"""

    open_expr = _fold("i32.or", [f"(i32.and (i32.ge_s (local.get $mow) {_const(a)}) (i32.lt_s (local.get $mow) {_const(b)}))" for a, b in open_ranges], _const(0))
    aux = f"""
  (func $inspect_context (export "inspect_context") (param $inp i32) (param $out i32) (result i32)
    (local $mfa i32) (local $dt i32) (local $mow i32) (local $flags i32) (local $zone i32) (local $zt i32) (local $f i32)
    (local.set $mfa (i32.load offset={4 * INFIELDS.index('mfa')} (local.get $inp)))
    (local.set $dt (i32.load offset={4 * INFIELDS.index('dtrust')} (local.get $inp)))
    (local.set $mow (i32.load offset={4 * INFIELDS.index('mow')} (local.get $inp)))
    (local.set $flags (i32.load offset={4 * INFIELDS.index('flags')} (local.get $inp)))
    (local.set $zone (i32.load offset={4 * INFIELDS.index('zone')} (local.get $inp)))
    (local.set $zt (i32.load offset={4 * INFIELDS.index('ztrust')} (local.get $inp)))
    (if (i32.eqz (local.get $mfa)) (then (local.set $f (i32.or (local.get $f) (i32.const 1)))))
    (if (i32.lt_s (local.get $dt) (i32.const 2)) (then (local.set $f (i32.or (local.get $f) (i32.const 2)))))
    {"(if (i32.eqz " + open_expr + ") (then (local.set $f (i32.or (local.get $f) (i32.const 4)))))" if open_ranges else ";; no open windows declared"}
    (if (i32.and (i32.shr_u (local.get $flags) (i32.const 1)) (i32.const 1)) (then (local.set $f (i32.or (local.get $f) (i32.const 8)))))
    (if (i32.and (i32.ge_s (local.get $zone) (i32.const 0)) (i32.le_s (local.get $zt) (i32.const 1))) (then (local.set $f (i32.or (local.get $f) (i32.const 16)))))
    (if (i32.eqz (i32.and (i32.shr_u (local.get $flags) (i32.const 2)) (i32.const 1))) (then (local.set $f (i32.or (local.get $f) (i32.const 32)))))
    (i32.store offset=24 (local.get $out) (local.get $f))
    (local.get $f))

  (func $classify_data (export "classify_data") (param $inp i32) (param $out i32) (result i32)
    (local $data i32) (local $c i32)
    (local.set $data (i32.load offset={4 * INFIELDS.index('data')} (local.get $inp)))
    (if (i32.and (i32.ge_s (local.get $data) (i32.const 0)) (i32.lt_s (local.get $data) (i32.const {nd})))
      (then (local.set $c (i32.load (i32.add (i32.const {o['dcls']}) (i32.shl (local.get $data) (i32.const 2)))))))
    (i32.store offset=28 (local.get $out) (local.get $c))
    (local.get $c))

  (func $audit_event (export "audit_event") (param $inp i32) (param $out i32) (result i32)
    (local $h i32)
    (local.set $h (i32.const 2166136261))
    {chr(10).join(f"(local.set $h (i32.mul (i32.xor (local.get $h) (i32.load offset={4 * INFIELDS.index(f)} (local.get $inp))) (i32.const 16777619)))" for f in ("subj", "res", "action", "data", "zone", "decision_in"))}
    (i32.store offset=32 (local.get $out) (local.get $h))
    (local.get $h))

  (func $deny_reason (export "deny_reason") (param $out i32) (result i32) (i32.load offset=4 (local.get $out)))
  (func (export "abi_version") (result i32) (i32.const 1))
  (func (export "rule_count") (result i32) (i32.const {len(rules)}))"""
    data = "\n".join(f'  (data (i32.const {off}) "{_esc(chunk)}")' for off, chunk in lay.chunks if chunk)
    return f""";; THREADZERO generated policy module — ABI v1 — deterministic, no imports, no host access.
;; project: {A['project']['name']} v{A['project']['version']}   source: {A.get('sourceHash', '')[:16]}
(module
  (memory (export "memory") {lay.pages})
{data}
{required_fn()}
{authorize}
{validate_flow}
{aux}
)
"""


def wat_to_wasm(wat: str) -> bytes:
    import wasmtime
    return bytes(wasmtime.wat2wasm(wat))


# --- Rego ---------------------------------------------------------------------------------
def gen_rego(A: dict) -> str:
    S = Symbols.from_analysis(A)
    rules = A["policy"]["rules"]
    zname = lambda i: S.name_of("zone", i)  # noqa: E731

    def q(s: str) -> str:
        return json.dumps(s)

    def val(slot: str) -> str:
        g = lambda path, d: f"object.get(input, {json.dumps(path)}, {d})"  # noqa: E731
        return {
            "subj": g(["subject", "id"], '""'), "szone": g(["subject", "zone"], '""'), "mfa": g(["subject", "mfa"], "false"),
            "dtrust": g(["subject", "device_trust"], "0"), "clearance": f"object.get(class_rank, {g(['subject', 'clearance'], '\"\"')}, 0)",
            "res": g(["resource"], '""'), "reskind": f"object.get(node_kind, {g(['resource'], '\"\"')}, \"\")",
            "rzone": f"object.get(node_zone, {g(['resource'], '\"\"')}, \"\")", "action": g(["action"], '""'),
            "data": g(["data"], '""'), "class": f"object.get(data_class, {g(['data'], '\"\"')}, 0)",
            "zone": g(["zone"], '""'), "ztrust": f"object.get(zone_trust, {g(['zone'], '\"\"')}, 0)",
            "zkind": f"object.get(zone_kind, {g(['zone'], '\"\"')}, \"\")", "env": g(["env"], '""'),
            "loc": g(["context", "location"], '""'), "mow": g(["context", "time"], "0"),
            "approved": g(["context", "approved"], "false"), "emergency": g(["context", "emergency"], "false"),
            "secure": g(["context", "secure_channel"], "false"), "tenant": g(["context", "tenant_match"], "false"),
        }[slot]

    def lit(slot: str, v: int):
        m = {"szone": ("zone", 1), "rzone": ("zone", 1), "zone": ("zone", 1), "res": ("node", 1), "subj": ("node", 1),
             "data": ("data", 1), "action": ("action", 1), "env": ("env", 1), "loc": ("loc", 1)}
        if slot in m:
            return q(S.name_of(m[slot][0], v))
        if slot == "reskind":
            return q(S.node_kinds[v] if 0 <= v < len(S.node_kinds) else "")
        if slot == "zkind":
            return q(S.zone_kinds[v] if 0 <= v < len(S.zone_kinds) else "")
        return str(v)

    def num(e: dict) -> str:
        op = e["op"]
        if op == "true":
            return "1"
        if op == "false":
            return "0"
        if op == "not":
            return f"minus(1, {num(e['arg'])})"
        if op == "and":
            return _fold_call("mul", [num(x) for x in e["args"]])
        if op == "or":
            return "max([" + ", ".join(num(x) for x in e["args"]) + "])"
        if op == "eq":
            return f"to_number(equal({val(e['slot'])}, {lit(e['slot'], e['val'])}))"
        if op == "has":
            names = S.role_names(e["mask"])
            return "max([" + ", ".join(f"to_number(gt(count([1 | input.subject.roles[_] == {q(n)}]), 0))" for n in names) + "])" if names else "0"
        if op in ("ge", "gt", "le", "lt"):
            fn = {"ge": "gte", "gt": "gt", "le": "lte", "lt": "lt"}[op]
            return f"to_number({fn}({val(e['slot'])}, {e['val']}))"
        if op == "in":
            return "max([" + ", ".join(f"to_number(equal({val(e['slot'])}, {lit(e['slot'], v)}))" for v in e["vals"]) + "])" if e["vals"] else "0"
        if op == "flag":
            return f"to_number({val(e['slot'])})"
        if op == "win":
            return "max([" + ", ".join(f"mul(to_number(gte({val('mow')}, {a})), to_number(lt({val('mow')}, {b})))" for a, b in e["ranges"]) + "])" if e["ranges"] else "0"
        if op == "cmp":
            fn = {"==": "equal", "!=": "neq", ">=": "gte", "<=": "lte", ">": "gt", "<": "lt"}[e["cmp"]]
            return f"to_number({fn}({val(e['slot'])}, {val(e['slot2'])}))"
        raise ValueError(op)

    def _fold_call(fn: str, xs: list[str]) -> str:
        acc = xs[-1]
        for x in reversed(xs[:-1]):
            acc = f"{fn}({x}, {acc})"
        return acc

    ids = [r["id"] for r in rules]
    lines = ["# THREADZERO generated Rego policy (equivalent to the WASM guard).",
             f"# project: {A['project']['name']} v{A['project']['version']}", "package threadzero.authz", "", "import rego.v1", ""]
    lines.append("class_rank := " + json.dumps(S.classes))
    lines.append("zone_trust := " + json.dumps({n: z["trust"] for n, z in S.zones.items()}))
    lines.append("zone_kind := " + json.dumps({n: z["kind"] for n, z in S.zones.items()}))
    lines.append("node_kind := " + json.dumps({n: z["kind"] for n, z in S.nodes.items()}))
    lines.append("node_zone := " + json.dumps({n: z["zone"] for n, z in S.nodes.items()}))
    lines.append("data_class := " + json.dumps({n: d["rank"] for n, d in S.data.items()}))
    lines.append("effect_of := " + json.dumps({r["id"]: r["effect"] for r in rules if r["terminal"]}))
    lines.append("obl_of := " + json.dumps({r["id"]: [o for o in r["obligations"]] for r in rules}))
    lines.append("ordered := " + json.dumps(ids))
    lines.append("")
    for i, r in enumerate(rules):
        lines.append(f"# {r['id']}: {r['effect']} when {r['condText']}")
        lines.append(f"m_{i} if {{ {num(r['cond'])} == 1 }}")
        lines.append(f"matched contains {q(r['id'])} if {{ m_{i} }}")
    lines.append("")
    term = [(i, r) for i, r in enumerate(rules) if r["terminal"]]
    if term:
        chain = " else := ".join(f"{q(r['id'])} if {{ m_{i} }}" for i, r in term)
        lines.append(f"winner := {chain} else := \"\"")
    else:
        lines.append('winner := ""')
    lines += ["", 'base := object.get(effect_of, winner, "deny")', "",
              "obl_set contains o if {", "\tsome id in matched", "\tsome o in obl_of[id]", "}", "",
              "first_with(o) := [id | some id in ordered; id in matched; o in obl_of[id]][0]", "",
              "ztrust := object.get(zone_trust, object.get(input, [\"zone\"], \"\"), 0)",
              "mfa := object.get(input, [\"subject\", \"mfa\"], false)",
              "approved := object.get(input, [\"context\", \"approved\"], false)", "",
              "result := {\"decision\": \"deny\", \"reason\": winner} if { base == \"deny\" } else := {\"decision\": \"quarantine\", \"reason\": first_with(\"quarantine\")} if {",
              "\t\"quarantine\" in obl_set", "} else := {\"decision\": \"deny\", \"reason\": first_with(\"require_trusted_zone\")} if {",
              "\t\"require_trusted_zone\" in obl_set", "\tztrust < 3", "} else := {\"decision\": \"require_mfa\", \"reason\": first_with(\"require_mfa\")} if {",
              "\t\"require_mfa\" in obl_set", "\tnot mfa", "} else := {\"decision\": \"require_approval\", \"reason\": first_with(\"require_approval\")} if {",
              "\t\"require_approval\" in obl_set", "\tnot approved", "} else := {\"decision\": \"allow\", \"reason\": winner}", "",
              "allow if { result.decision == \"allow\" }", "",
              "decision := {\"decision\": result.decision, \"reason\": result.reason, \"obligations\": sort(obl_set), \"matched\": sort(matched)}", ""]
    return "\n".join(lines)


# --- JS / TS -----------------------------------------------------------------------------
def _js(e: dict) -> str:
    op = e["op"]
    s = lambda k: f"s.{k}"  # noqa: E731
    if op == "true":
        return "true"
    if op == "false":
        return "false"
    if op == "not":
        return f"!({_js(e['arg'])})"
    if op == "and":
        return "(" + " && ".join(_js(x) for x in e["args"]) + ")"
    if op == "or":
        return "(" + " || ".join(_js(x) for x in e["args"]) + ")"
    if op == "eq":
        return f"({s(e['slot'])} === {e['val']})"
    if op == "has":
        return f"(({s(e['slot'])} & {e['mask']}) !== 0)"
    if op in ("ge", "gt", "le", "lt"):
        return f"({s(e['slot'])} {dict(ge='>=', gt='>', le='<=', lt='<')[op]} {e['val']})"
    if op == "in":
        return "(" + " || ".join(f"{s(e['slot'])} === {v}" for v in e["vals"]) + ")" if e["vals"] else "false"
    if op == "flag":
        return f"({s(e['slot'])} === 1)"
    if op == "win":
        return "(" + " || ".join(f"(s.mow >= {a} && s.mow < {b})" for a, b in e["ranges"]) + ")" if e["ranges"] else "false"
    if op == "cmp":
        return f"({s(e['slot'])} {dict({'==': '===', '!=': '!=='}, **{k: k for k in ('>=', '<=', '>', '<')})[e['cmp']]} {s(e['slot2'])})"
    raise ValueError(op)


def gen_js(A: dict) -> str:
    rules = A["policy"]["rules"]
    S = Symbols.from_analysis(A)
    data = {
        "defaults": {k: v for k, v in DEFAULTS.items() if k not in ("flags", "src_zone", "dst_zone", "controls", "decision_in")} | {"approved": 0, "emergency": 0, "secure": 0, "tenant": 0},
        "obligationBits": {n: e["bit"] for n, e in S.effects.items() if not e["terminal"]},
        "rules": [{"id": r["id"], "effect": r["effect"], "terminal": r["terminal"], "obligations": r["obligations"],
                   "obligationMask": r["obligationMask"], "reason": r["reason"]} for r in rules],
    }
    conds = ",\n  ".join(f"/* {r['idx']} {r['id']} */ (s) => {_js(r['cond'])}" for r in rules)
    return f"""// THREADZERO generated JavaScript validation wrapper (equivalent to the WASM guard).
// Usage: const {{ decideSlots }} = require('./guard.js');  decideSlots({{ data: 1, action: 2, ... }})
'use strict';
const META = {json.dumps(data, indent=1)};
const CONDS = [
  {conds}
];
function decideSlots(slots) {{
  const s = Object.assign({{}}, META.defaults, slots);
  const matched = []; let obl = 0; let winner = null;
  const first = {{ quarantine: -1, require_trusted_zone: -1, require_mfa: -1, require_approval: -1 }};
  META.rules.forEach((r, i) => {{
    if (!CONDS[i](s)) return;
    matched.push(i); obl |= r.obligationMask;
    if (r.terminal && winner === null) winner = i;
    for (const k of Object.keys(first)) if (r.obligations.includes(k) && first[k] === -1) first[k] = i;
  }});
  const base = winner !== null && META.rules[winner].effect === 'allow' ? 1 : 0;
  let decision = base, reason = winner === null ? -1 : winner;
  if (base === 1) {{
    if (first.quarantine !== -1) {{ decision = 4; reason = first.quarantine; }}
    else if (first.require_trusted_zone !== -1 && s.ztrust < 3) {{ decision = 0; reason = first.require_trusted_zone; }}
    else if (first.require_mfa !== -1 && s.mfa === 0) {{ decision = 2; reason = first.require_mfa; }}
    else if (first.require_approval !== -1 && s.approved === 0) {{ decision = 3; reason = first.require_approval; }}
  }}
  return {{ decision, reason, obligations: obl, matched }};
}}
async function loadWasm(bytes) {{
  // Runs the same policy inside the WebAssembly sandbox (browser, edge, serverless, Node >= 18).
  const {{ instance }} = await WebAssembly.instantiate(bytes, {{}});
  const mem = instance.exports.memory;
  const FIELDS = {json.dumps(INFIELDS)};
  return {{
    authorize(slots) {{
      const v = new Int32Array(mem.buffer, 0, FIELDS.length);
      const d = Object.assign({{}}, {json.dumps(DEFAULTS)}, slots);
      let flags = d.flags | 0;
      for (const [k, b] of Object.entries({json.dumps(FLAG_BITS)})) if (slots[k]) flags |= b;
      d.flags = flags;
      FIELDS.forEach((f, i) => (v[i] = d[f] | 0));
      const dec = instance.exports.authorize(0, {OUT_OFF});
      const out = new Int32Array(mem.buffer, {OUT_OFF}, 16);
      const matched = Array.from(new Int32Array(mem.buffer, {OUT_OFF + MATCH_OFF}, Math.min(out[3], {MAX_MATCH})));
      return {{ decision: dec, reason: out[1], obligations: out[2], matched }};
    }},
    instance,
  }};
}}
module.exports = {{ decideSlots, loadWasm, META }};
"""


def gen_ts(A: dict) -> str:
    S = Symbols.from_analysis(A)
    return f"""// THREADZERO generated TypeScript wrapper. Works in Node, browsers, edge and serverless runtimes.
// The request uses entity *names*; numeric ABI slots are derived from the embedded symbol tables.
export type Decision = 'deny' | 'allow' | 'require_mfa' | 'require_approval' | 'quarantine';
export interface TzRequest {{
  subject?: {{ id?: string; roles?: string[]; zone?: string; mfa?: boolean; device_trust?: number; clearance?: string }};
  resource?: string; action?: string; data?: string; zone?: string; env?: string;
  context?: {{ location?: string; time?: number; approved?: boolean; emergency?: boolean; secure_channel?: boolean; tenant_match?: boolean }};
}}
export interface TzResult {{ decision: Decision; reason: string; obligations: string[]; matched: string[] }}
// eslint-disable-next-line @typescript-eslint/no-var-requires
const guard = require('./guard.js');
const SYMBOLS = {json.dumps({"roles": S.roles, "zones": S.zones, "actions": S.actions, "data": S.data, "nodes": S.nodes, "envs": S.envs, "locs": S.locs, "kinds": S.node_kinds, "classes": S.classes}, separators=(",", ":"))};
const NAMES = {json.dumps([r["id"] for r in A["policy"]["rules"]])};
const DECISIONS: Decision[] = ['deny', 'allow', 'require_mfa', 'require_approval', 'quarantine'];
const OBLIGATION_BITS: Record<string, number> = guard.META.obligationBits;

export function encode(req: TzRequest): Record<string, number> {{
  const s: Record<string, number> = {{}};
  const sub = req.subject ?? {{}};
  s.roles = (sub.roles ?? []).reduce((m, r) => m | (SYMBOLS.roles as any)[r] || 0, 0);
  if (sub.id && (SYMBOLS.nodes as any)[sub.id]) s.subj = (SYMBOLS.nodes as any)[sub.id].id;
  if (sub.zone && (SYMBOLS.zones as any)[sub.zone]) s.szone = (SYMBOLS.zones as any)[sub.zone].id;
  s.mfa = sub.mfa ? 1 : 0; s.dtrust = sub.device_trust ?? 0;
  if (sub.clearance && (SYMBOLS.classes as any)[sub.clearance] !== undefined) s.clearance = (SYMBOLS.classes as any)[sub.clearance];
  const n = req.resource ? (SYMBOLS.nodes as any)[req.resource] : undefined;
  if (n) {{ s.res = n.id; s.reskind = SYMBOLS.kinds.indexOf(n.kind); s.rzone = n.zoneId; }}
  if (req.action && (SYMBOLS.actions as any)[req.action] !== undefined) s.action = (SYMBOLS.actions as any)[req.action];
  const d = req.data ? (SYMBOLS.data as any)[req.data] : undefined;
  if (d) {{ s.data = d.id; s.class = d.rank; }}
  const z = req.zone ? (SYMBOLS.zones as any)[req.zone] : undefined;
  if (z) {{ s.zone = z.id; s.ztrust = z.trust; s.zkind = z.kindId; }}
  if (req.env && (SYMBOLS.envs as any)[req.env] !== undefined) s.env = (SYMBOLS.envs as any)[req.env];
  const c = req.context ?? {{}};
  if (c.location && (SYMBOLS.locs as any)[c.location] !== undefined) s.loc = (SYMBOLS.locs as any)[c.location];
  s.mow = c.time ?? 0; s.approved = c.approved ? 1 : 0; s.emergency = c.emergency ? 1 : 0;
  s.secure = c.secure_channel ? 1 : 0; s.tenant = c.tenant_match ? 1 : 0;
  return s;
}}

export function authorize(req: TzRequest): TzResult {{
  const r = guard.decideSlots(encode(req));
  return {{
    decision: DECISIONS[r.decision], reason: r.reason >= 0 ? NAMES[r.reason] : 'default-deny',
    obligations: Object.entries(OBLIGATION_BITS).filter(([, bit]) => (r.obligations & (bit as number)) !== 0).map(([k]) => k),
    matched: r.matched.map((i: number) => NAMES[i]),
  }};
}}
"""


# --- JSON artifact -----------------------------------------------------------------------
def gen_policy_json(A: dict) -> dict:
    return {"format": "threadzero-policy/1", "project": A["project"], "symbols": A["symbols"], "rules": A["policy"]["rules"],
            "tables": A["policy"]["tables"], "windows": A["policy"]["windows"], "runtimeChecks": A["policy"]["runtimeChecks"],
            "defaultEffect": A["policy"]["defaultEffect"], "abi": {"version": 1, "fields": INFIELDS, "in": 0, "out": OUT_OFF, "matchOffset": MATCH_OFF, "maxMatched": MAX_MATCH},
            "precedence": "priority desc, scope specificity desc, deny before allow, declaration order; first terminal match wins; default deny"}


# --- Guards / middleware -----------------------------------------------------------------
def gen_route_rules(A: dict) -> dict:
    """HTTP + gRPC rule tables: one entry per api/service node with the data it is allowed to receive."""
    nodes = {n["name"]: n for n in A["symbols"]["nodes"]}
    into: dict[str, set] = {}
    for e in A["graph"]["edges"]:
        into.setdefault(e["to"], set()).update(e["data"])
    http, grpc = [], []
    for g in A["guards"]:
        n = nodes.get(g["node"])
        if not n:
            continue
        data = sorted(into.get(g["node"], []))
        if g["guard"] == "http_middleware":
            for method, action in (("GET", "Read"), ("HEAD", "Read"), ("POST", "Create"), ("PUT", "Write"), ("PATCH", "Write"), ("DELETE", "Delete")):
                http.append({"resource": g["node"], "method": method, "path_prefix": "/" + g["node"].lower(), "action": action, "data": data[0] if data else None, "zone": n["zone"]})
        elif g["guard"] in ("grpc_interceptor", "service_wrapper"):
            grpc.append({"resource": g["node"], "service": g["node"], "methods": {"Get*": "Read", "List*": "Read", "Create*": "Create", "Update*": "Write", "Delete*": "Delete", "Export*": "Export"}, "data": data[0] if data else None, "zone": n["zone"]})
    return {"http": http, "grpc": grpc}


def _read_pkg(name: str) -> str:
    return (Path(__file__).parent / name).read_text(encoding="utf-8")


def gen_support_files() -> dict[str, str]:
    abi = _read_pkg("abi.py")
    rt = _read_pkg("runtime.py").replace("from .abi import", "from tz_abi import").replace("from .core import", "from tz_core_stub import")
    return {"guards/tz_abi.py": abi, "guards/tz_runtime.py": rt}


HTTP_MW = '''"""Generated ASGI middleware (FastAPI/Starlette): enforces the compiled THREADZERO policy on every request.
The application MUST supply `subject_resolver(request) -> dict` (roles, mfa, device_trust, zone) from its own
authenticated session — the guard never trusts client-supplied identity headers.
"""
import json
from pathlib import Path
from tz_runtime import PolicyEngine

RULES = json.loads((Path(__file__).parent / "http_rules.json").read_text())["http"]


class TZGuardMiddleware:
    def __init__(self, app, engine: PolicyEngine, subject_resolver, obligation_hooks=None, env="prod"):
        if subject_resolver is None:
            raise ValueError("subject_resolver is required")
        self.app, self.engine, self.resolve, self.hooks, self.env = app, engine, subject_resolver, obligation_hooks or {}, env

    def _route(self, method, path):
        for r in RULES:
            if r["method"] == method and path.startswith(r["path_prefix"]):
                return r
        return None

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        route = self._route(scope["method"], scope["path"])
        if route is None:                       # not a guarded resource
            return await self.app(scope, receive, send)
        request = {"subject": self.resolve(scope), "resource": route["resource"], "action": route["action"],
                   "data": route["data"], "zone": route["zone"], "env": self.env,
                   "context": {"secure_channel": scope.get("scheme") == "https", "tenant_match": bool(scope.get("tz_tenant_match", False))}}
        decision = self.engine.evaluate(request)
        for ob in decision.obligations:         # audit / rate_limit / redact ... are host-provided hooks
            hook = self.hooks.get(ob)
            if hook:
                hook(request, decision)
        if decision.decision != "allow":
            status = {"require_mfa": 401, "require_approval": 202, "quarantine": 423}.get(decision.decision, 403)
            body = json.dumps({"decision": decision.decision, "reason": decision.reason_text}).encode()
            await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"application/json")]})
            return await send({"type": "http.response.body", "body": body})
        return await self.app(scope, receive, send)
'''

EXPRESS_MW = '''// Generated Express/Connect middleware. Requires guard.js (same folder) and a subjectResolver(req) from your session layer.
const rules = require('./http_rules.json').http;
const { decideSlots } = require('../guard.js');
const { authorize } = (() => { try { return require('../guard.ts.js'); } catch (e) { return {}; } })();
module.exports = function tzGuard({ subjectResolver, encode, names, hooks = {}, env = 'prod' }) {
  if (!subjectResolver || !encode) throw new Error('subjectResolver and encode are required');
  return (req, res, next) => {
    const r = rules.find((x) => x.method === req.method && req.path.startsWith(x.path_prefix));
    if (!r) return next();
    const slots = encode({ subject: subjectResolver(req), resource: r.resource, action: r.action, data: r.data, zone: r.zone, env,
                           context: { secure_channel: req.secure, tenant_match: !!req.tzTenantMatch } });
    const d = decideSlots(slots);
    if (d.decision !== 1) return res.status(d.decision === 2 ? 401 : d.decision === 3 ? 202 : d.decision === 4 ? 423 : 403).json({ decision: d.decision, reason: d.reason });
    for (const h of Object.values(hooks)) h(req, d);
    next();
  };
};
'''

GRPC_IC = '''"""Generated gRPC server interceptor. Maps service methods to policy actions (see grpc_rules.json)."""
import fnmatch
import json
from pathlib import Path
import grpc
from tz_runtime import PolicyEngine

RULES = json.loads((Path(__file__).parent / "grpc_rules.json").read_text())["grpc"]


class TZInterceptor(grpc.ServerInterceptor):
    def __init__(self, engine: PolicyEngine, subject_resolver, env="prod"):
        self.engine, self.resolve, self.env = engine, subject_resolver, env

    def intercept_service(self, continuation, handler_call_details):
        service, _, method = handler_call_details.method.strip("/").partition("/")
        for r in RULES:
            if r["service"] == service:
                action = next((a for pat, a in r["methods"].items() if fnmatch.fnmatch(method, pat)), None)
                if action:
                    d = self.engine.evaluate({"subject": self.resolve(handler_call_details), "resource": r["resource"], "action": action,
                                              "data": r["data"], "zone": r["zone"], "env": self.env, "context": {"secure_channel": True}})
                    if d.decision != "allow":
                        def deny(request, context, _d=d):
                            context.abort(grpc.StatusCode.PERMISSION_DENIED, f"{_d.decision}: {_d.reason_text}")
                        return grpc.unary_unary_rpc_method_handler(deny)
        return continuation(handler_call_details)
'''

QUEUE_GUARD = '''"""Generated message-queue guard: wrap publish/consume callables of any broker client."""
from tz_runtime import PolicyEngine


class QueueGuard:
    def __init__(self, engine: PolicyEngine, queue_node: str, zone: str, subject_resolver):
        self.engine, self.node, self.zone, self.resolve = engine, queue_node, zone, subject_resolver

    def _check(self, action, data_type, ctx):
        d = self.engine.evaluate({"subject": self.resolve(ctx), "resource": self.node, "action": action, "data": data_type, "zone": self.zone,
                                  "context": {"secure_channel": True}})
        if d.decision != "allow":
            raise PermissionError(f"{d.decision}: {d.reason_text}")
        return d

    def publish(self, publish_fn, data_type, message, ctx=None, **kw):
        self._check("Publish", data_type, ctx)
        return publish_fn(message, **kw)

    def consume(self, handler, data_type, ctx=None):
        def wrapped(message, *a, **kw):
            self._check("Subscribe", data_type, ctx)
            return handler(message, *a, **kw)
        return wrapped
'''

STORAGE_GUARD = '''"""Generated file-storage guard for object stores / file systems (wrap read/write/delete/export callables)."""
from tz_runtime import PolicyEngine


class StorageGuard:
    ACTIONS = {"read": "Read", "write": "Write", "delete": "Delete", "export": "Export", "copy": "Copy"}

    def __init__(self, engine: PolicyEngine, store_node: str, zone: str, subject_resolver):
        self.engine, self.node, self.zone, self.resolve = engine, store_node, zone, subject_resolver

    def call(self, op, fn, data_type, *args, ctx=None, **kw):
        d = self.engine.evaluate({"subject": self.resolve(ctx), "resource": self.node, "action": self.ACTIONS[op], "data": data_type,
                                  "zone": self.zone, "context": {"secure_channel": True}})
        if d.decision != "allow":
            raise PermissionError(f"{d.decision}: {d.reason_text}")
        return fn(*args, **kw)
'''

WORKFLOW_GUARD = '''"""Generated workflow-step guard: every step is authorized; steps needing approval block until approved."""
from tz_runtime import PolicyEngine


class WorkflowGuard:
    def __init__(self, engine: PolicyEngine, resource: str, zone: str):
        self.engine, self.resource, self.zone = engine, resource, zone

    def step(self, action, data_type, subject, approved=False):
        d = self.engine.evaluate({"subject": subject, "resource": self.resource, "action": action, "data": data_type, "zone": self.zone,
                                  "context": {"approved": approved, "secure_channel": True}})
        return d   # caller inspects d.decision: allow | require_approval | require_mfa | deny
'''


def gen_guards(A: dict) -> dict[str, str]:
    rules = gen_route_rules(A)
    files = {
        "guards/http_middleware.py": HTTP_MW, "guards/express_middleware.js": EXPRESS_MW, "guards/grpc_interceptor.py": GRPC_IC,
        "guards/queue_guard.py": QUEUE_GUARD, "guards/storage_guard.py": STORAGE_GUARD, "guards/workflow_guard.py": WORKFLOW_GUARD,
        "guards/http_rules.json": json.dumps({"http": rules["http"]}, indent=1), "guards/grpc_rules.json": json.dumps({"grpc": rules["grpc"]}, indent=1),
        "guards/points.json": json.dumps({"guards": A["guards"], "validationPoints": A["validationPoints"]}, indent=1),
    }
    return files
