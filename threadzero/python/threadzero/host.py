"""Policy runtime host: signed distribution, compatibility checks, canary mode, rollback, fail-closed evaluation.
Authorized/defensive use only — there is no hidden bypass path: every failure results in DENY."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .runtime import Decision, PolicyEngine, PolicyLoadError
from .store import read_package, verify_package


@dataclass
class Version:
    id: str
    manifest: dict
    engine: PolicyEngine
    loaded_at: float = field(default_factory=time.time)
    healthy: bool = True


class PolicyHost:
    def __init__(self, trusted_public_keys: list[str] | None = None, compat: tuple[str, ...] = ("1",), cache: int = 0, on_decision=None):
        self.trusted = trusted_public_keys
        self.compat = compat
        self.versions: list[Version] = []
        self.active: int | None = None
        self.cache = cache
        self.on_decision = on_decision
        self.events: list[dict] = []

    def _log(self, kind: str, **kw: Any) -> None:
        self.events.append({"t": time.time(), "event": kind, **kw})

    # -- loading ------------------------------------------------------------------------
    def load(self, package: bytes) -> str:
        """Verify signature + hashes + compatibility BEFORE instantiating. Loading never changes the active version."""
        try:
            manifest = verify_package(package, self.trusted, self.compat)
            files = read_package(package)
            engine = PolicyEngine(files["policy.wasm"], json.loads(files["policy.json"]), cache_size=self.cache)
        except Exception as exc:
            self._log("load-rejected", error=f"{type(exc).__name__}: {exc}")
            raise
        vid = manifest["sourceHash"][:8] + "-" + str(len(self.versions) + 1)
        self.versions.append(Version(vid, manifest, engine))
        self._log("loaded", id=vid)
        return vid

    def activate(self, vid: str | None = None) -> str:
        idx = len(self.versions) - 1 if vid is None else next(i for i, v in enumerate(self.versions) if v.id == vid)
        self.active = idx
        self._log("activated", id=self.versions[idx].id)
        return self.versions[idx].id

    def rollback(self) -> str | None:
        """Return to the most recent earlier healthy version."""
        if self.active is None:
            return None
        self.versions[self.active].healthy = False
        for i in range(self.active - 1, -1, -1):
            if self.versions[i].healthy:
                self.active = i
                self._log("rollback", to=self.versions[i].id)
                return self.versions[i].id
        self.active = None
        self._log("rollback-none")
        return None

    # -- evaluation ---------------------------------------------------------------------
    def evaluate(self, request: dict) -> Decision:
        if self.active is None:
            return Decision("deny", 0, "no-active-policy", "fail-closed: no active policy module")
        v = self.versions[self.active]
        d = v.engine.evaluate(request)
        if d.reason == "runtime-failure":
            v.healthy = False
        if self.on_decision:
            self.on_decision(v.id, request, d)
        return d

    # -- canary ---------------------------------------------------------------------------
    def canary(self, candidate_id: str, requests: list[dict], max_changed_ratio: float = 0.05, max_latency_ratio: float = 3.0, promote: bool = False) -> dict:
        """Run the candidate in shadow mode next to the active version on controlled requests."""
        if self.active is None:
            raise RuntimeError("no active version to compare against")
        cand = next(v for v in self.versions if v.id == candidate_id)
        cur = self.versions[self.active]
        diffs, t_cur, t_new = [], 0.0, 0.0
        allow_cur = allow_new = 0
        for r in requests:
            a = cur.engine.evaluate(r)
            b = cand.engine.evaluate(r)
            t_cur += a.duration_us
            t_new += b.duration_us
            allow_cur += a.decision == "allow"
            allow_new += b.decision == "allow"
            if a.decision != b.decision:
                diffs.append({"request": r, "active": a.decision, "candidate": b.decision, "candidateReason": b.reason})
        n = max(1, len(requests))
        ratio = len(diffs) / n
        lat_ratio = (t_new / t_cur) if t_cur else 1.0
        ok = ratio <= max_changed_ratio and lat_ratio <= max_latency_ratio
        rep = {"requests": len(requests), "changed": len(diffs), "changedRatio": round(ratio, 4), "allowActive": allow_cur, "allowCandidate": allow_new,
               "avgLatencyActiveUs": round(t_cur / n, 2), "avgLatencyCandidateUs": round(t_new / n, 2), "latencyRatio": round(lat_ratio, 2),
               "withinThresholds": ok, "differences": diffs[:100]}
        self._log("canary", candidate=candidate_id, ok=ok, changed=len(diffs))
        if promote and ok:
            self.activate(candidate_id)
            rep["promoted"] = True
        return rep

    def status(self) -> dict:
        return {"active": self.versions[self.active].id if self.active is not None else None,
                "versions": [{"id": v.id, "project": v.manifest["project"], "rules": v.manifest["rules"], "healthy": v.healthy, "compiler": v.manifest["compiler"]} for v in self.versions],
                "events": self.events[-30:]}


# --- distribution -------------------------------------------------------------------------
def distribute(package: bytes, targets: list[str], timeout: float = 5.0) -> list[dict]:
    """Copy a signed package to directory targets or POST it to http(s) runtimes (/api/host/load). Receivers verify before load."""
    out = []
    for t in targets:
        try:
            if t.startswith(("http://", "https://")):
                req = urllib.request.Request(t.rstrip("/") + "/api/host/load", data=package, headers={"Content-Type": "application/octet-stream"}, method="POST")
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    out.append({"target": t, "ok": r.status == 200, "response": json.loads(r.read() or b"{}")})
            else:
                d = Path(t)
                d.mkdir(parents=True, exist_ok=True)
                m = json.loads(read_package(package)["manifest.json"])
                (d / f"{m['sourceHash'][:12]}.tzpkg").write_bytes(package)
                (d / "CURRENT").write_text(f"{m['sourceHash'][:12]}.tzpkg\n")
                out.append({"target": t, "ok": True})
        except (urllib.error.URLError, OSError, ValueError) as exc:
            out.append({"target": t, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    return out
