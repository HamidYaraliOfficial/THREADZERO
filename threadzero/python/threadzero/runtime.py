"""WASM Security Runtime: sandboxed, deterministic policy execution (wasmtime).

Host capabilities are explicit and allow-listed (default: none — generated modules import nothing).
Every call is fuel-limited and memory-capped; any failure produces a fail-closed deny decision.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .abi import (CONTEXT_FLAGS, DECISIONS, FLOW_REASONS, INFIELDS, IN_OFF, MATCH_OFF, MAX_MATCH, OUT_OFF, Symbols,
                  full_slots, pack_request, ref_decide)


class PolicyLoadError(RuntimeError):
    pass


@dataclass
class Decision:
    decision: str
    code: int
    reason: str = ""
    reason_text: str = ""
    obligations: list[str] = field(default_factory=list)
    matched: list[str] = field(default_factory=list)
    required_controls: list[str] = field(default_factory=list)
    audit: dict = field(default_factory=dict)
    duration_us: float = 0.0

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in ("decision", "code", "reason", "reason_text", "obligations", "matched", "required_controls", "audit", "duration_us")}


class WasmPolicy:
    """Low-level wrapper around one compiled module (numeric slot API)."""

    def __init__(self, wasm: bytes, fuel: int = 20_000_000, memory_limit: int = 32 * 1024 * 1024, host_allowlist: tuple[str, ...] = ()):
        import wasmtime
        self._wt = wasmtime
        cfg = wasmtime.Config()
        cfg.consume_fuel = True
        self.engine = wasmtime.Engine(cfg)
        try:
            self.module = wasmtime.Module(self.engine, wasm)
        except Exception as exc:  # invalid artifact
            raise PolicyLoadError(f"invalid WASM artifact: {exc}") from exc
        for imp in self.module.imports:
            key = f"{imp.module}.{imp.name}"
            if key not in host_allowlist:
                raise PolicyLoadError(f"module requests non-allow-listed host capability: {key}")
        self.fuel = fuel
        self.store = wasmtime.Store(self.engine)
        self.store.set_limits(memory_size=memory_limit)
        self.store.set_fuel(fuel)
        self.instance = wasmtime.Instance(self.store, self.module, [])
        ex = self.instance.exports(self.store)
        self._mem = ex["memory"]
        self._fn = {n: ex[n] for n in ("authorize", "validate_flow", "validate_boundary", "inspect_context", "classify_data", "audit_event", "deny_reason", "abi_version", "rule_count") if n in ex}
        try:
            version = self._fn["abi_version"](self.store)
        except Exception as exc:  # trap during the self-check (e.g. fuel starvation)
            raise PolicyLoadError(f"module failed its self-check: {type(exc).__name__}") from exc
        if version != 1:
            raise PolicyLoadError("unsupported ABI version")
        self.rule_count = int(self._fn["rule_count"](self.store))
        self._lock = threading.Lock()
        self.wasm_size = len(wasm)

    def call(self, name: str, slots: dict[str, int]) -> tuple[int, list[int], list[int]]:
        with self._lock:
            self.store.set_fuel(self.fuel)
            self._mem.write(self.store, pack_request(slots), IN_OFF)
            ret = self._fn[name](self.store, IN_OFF, OUT_OFF)
            head = struct.unpack("<10i", bytes(self._mem.read(self.store, OUT_OFF, OUT_OFF + 40)))
            n = min(head[3], MAX_MATCH) if name == "authorize" else 0
            matched = list(struct.unpack("<%di" % n, bytes(self._mem.read(self.store, OUT_OFF + MATCH_OFF, OUT_OFF + MATCH_OFF + 4 * n)))) if n else []
            return ret, list(head), matched

    def memory_bytes(self) -> int:
        return self._mem.data_len(self.store)


class PolicyEngine:
    """High-level, names-based engine used by guards, the simulator and tests."""

    def __init__(self, wasm: bytes, policy: dict, cache_size: int = 0, **kw: Any):
        self.policy = policy
        self.symbols = Symbols.from_analysis(policy)
        self.rules = policy["rules"]
        self.wasm = WasmPolicy(wasm, **kw)
        self.cache: OrderedDict | None = OrderedDict() if cache_size else None
        self.cache_size = cache_size
        self.stats = {"hits": 0, "misses": 0, "evaluations": 0, "failures": 0}
        self.fail_closed = True

    # -- construction -------------------------------------------------------------------
    @staticmethod
    def from_files(wasm_path: str | Path, policy_path: str | Path, **kw: Any) -> "PolicyEngine":
        return PolicyEngine(Path(wasm_path).read_bytes(), json.loads(Path(policy_path).read_text("utf-8")), **kw)

    @staticmethod
    def from_package(path: str | Path, **kw: Any) -> "PolicyEngine":
        p = Path(path)
        if p.is_dir():
            return PolicyEngine.from_files(p / "policy.wasm", p / "policy.json", **kw)
        import zipfile
        with zipfile.ZipFile(p) as z:
            return PolicyEngine(z.read("policy.wasm"), json.loads(z.read("policy.json")), **kw)

    # -- evaluation ---------------------------------------------------------------------
    def _reason_text(self, code: int, idx: int) -> str:
        if idx < 0:
            return "no rule matched (default deny)" if code == 0 else ""
        return self.rules[idx]["reason"] if idx < len(self.rules) else ""

    def authorize_slots(self, slots: dict[str, int]) -> Decision:
        t0 = time.perf_counter()
        ret, head, matched = self.wasm.call("authorize", slots)
        code, reason, obl = head[0], head[1], head[2]
        idx = reason
        d = Decision(DECISIONS.get(code, "deny"), code, self.rules[idx]["id"] if 0 <= idx < len(self.rules) else "",
                     self._reason_text(code, idx), self.symbols.obligations(obl),
                     [self.rules[i]["id"] for i in matched if i < len(self.rules)])
        d.duration_us = (time.perf_counter() - t0) * 1e6
        self.stats["evaluations"] += 1
        return d

    def evaluate(self, request: dict) -> Decision:
        try:
            slots = self.symbols.encode(request)
            key = None
            if self.cache is not None:
                key = pack_request(slots)
                if key in self.cache:
                    self.cache.move_to_end(key)
                    self.stats["hits"] += 1
                    return self.cache[key]
                self.stats["misses"] += 1
            d = self.authorize_slots(slots)
            d.audit = self.audit(slots, d.code)
            if key is not None:
                self.cache[key] = d
                if len(self.cache) > self.cache_size:
                    self.cache.popitem(last=False)
            return d
        except Exception as exc:  # fail closed
            self.stats["failures"] += 1
            if not self.fail_closed:
                raise
            return Decision("deny", 0, "runtime-failure", f"fail-closed: {type(exc).__name__}: {exc}")

    def audit(self, slots: dict[str, int], code: int) -> dict:
        s = dict(slots)
        s["decision_in"] = code
        ret, _, _ = self.wasm.call("audit_event", s)
        return {"hash": f"{ret & 0xFFFFFFFF:08x}"}

    def validate_flow(self, request: dict) -> dict:
        slots = self.symbols.encode(request)
        ok, head, _ = self.wasm.call("validate_flow", slots)
        return {"ok": bool(ok), "reason_code": head[1], "reason": FLOW_REASONS.get(head[1], str(head[1])),
                "required_controls": self.symbols.control_names(head[4]), "missing_controls": self.symbols.control_names(head[5])}

    def validate_boundary(self, request: dict) -> dict:
        slots = self.symbols.encode(request)
        ok, head, _ = self.wasm.call("validate_boundary", slots)
        return {"ok": bool(ok), "reason": FLOW_REASONS.get(head[1], str(head[1])),
                "required_controls": self.symbols.control_names(head[4]), "missing_controls": self.symbols.control_names(head[5])}

    def inspect_context(self, request: dict) -> dict:
        flags, _, _ = self.wasm.call("inspect_context", self.symbols.encode(request))
        return {"flags": [n for b, n in CONTEXT_FLAGS.items() if flags & b], "mask": flags}

    def classify_data(self, request: dict) -> dict:
        c, _, _ = self.wasm.call("classify_data", self.symbols.encode(request))
        name = next((n for n, r in self.symbols.classes.items() if r == c), str(c))
        return {"rank": c, "classification": name}

    def deny_reason(self, request: dict) -> str:
        d = self.authorize_slots(self.symbols.encode(request))
        return d.reason_text or d.reason or "allowed"

    def reference(self, slots: dict[str, int]) -> dict:
        return ref_decide(self.rules, slots)


# --- obligation execution (host side) ---------------------------------------------------
class TokenBucket:
    def __init__(self, rate: float, burst: int):
        self.rate, self.burst, self.tokens, self.t = rate, burst, float(burst), time.monotonic()
        self.lock = threading.Lock()

    def allow(self) -> bool:
        with self.lock:
            now = time.monotonic()
            self.tokens = min(self.burst, self.tokens + (now - self.t) * self.rate)
            self.t = now
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False


def redact(value: Any, fields: tuple[str, ...] = ("password", "token", "secret", "card", "ssn", "email", "phone", "address")) -> Any:
    if isinstance(value, dict):
        return {k: ("***" if any(f in k.lower() for f in fields) else redact(v, fields)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, fields) for v in value]
    return value


def tokenize(value: str, key: bytes | None = None) -> str:
    """Deterministic HMAC token; the key comes from the host environment (never from the model)."""
    key = key or os.environ.get("THREADZERO_TOKEN_KEY", "").encode()
    if not key:
        raise RuntimeError("THREADZERO_TOKEN_KEY is not set")
    return "tok_" + hmac.new(key, value.encode(), hashlib.sha256).hexdigest()[:24]


class ObligationRunner:
    """Executes obligations returned by a decision. Unknown obligations fail closed."""

    def __init__(self, audit_sink: Callable[[dict], None] | None = None, rate: float = 50, burst: int = 100):
        self.audit_sink = audit_sink or (lambda rec: None)
        self.bucket = TokenBucket(rate, burst)

    def run(self, decision: Decision, payload: Any = None) -> tuple[bool, Any]:
        out = payload
        for ob in decision.obligations:
            if ob == "audit":
                self.audit_sink({"decision": decision.decision, "reason": decision.reason, "hash": decision.audit.get("hash")})
            elif ob == "rate_limit" and not self.bucket.allow():
                return False, None
            elif ob == "redact":
                out = redact(out)
            elif ob == "tokenize" and isinstance(out, str):
                out = tokenize(out)
            elif ob in ("encrypt", "require_mfa", "require_approval", "quarantine", "require_trusted_zone"):
                continue  # enforced by decision code / host storage layer
            else:
                return False, None
        return True, out
