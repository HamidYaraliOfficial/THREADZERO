"""Workspace state: signing keys, artifact registry, decision log, snapshots (all file based, offline)."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .core import canonical_json, sha256_hex

STATE_DIR = ".threadzero"


def workspace(path: str | Path | None = None) -> Path:
    base = Path(path or os.environ.get("THREADZERO_HOME") or Path.cwd())
    d = base / STATE_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------- signing (Ed25519)
def _keys():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    return serialization, Ed25519PrivateKey, Ed25519PublicKey


def key_id_of(pub_raw: bytes) -> str:
    return hashlib.sha256(pub_raw).hexdigest()[:16]


def keygen(ws: Path) -> str:
    ser, Priv, _ = _keys()
    priv = Priv.generate()
    raw_priv = priv.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
    raw_pub = priv.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    kid = key_id_of(raw_pub)
    kd = ws / "keys"
    kd.mkdir(parents=True, exist_ok=True)
    f = kd / f"{kid}.key"
    f.write_text(raw_priv.hex())
    try:
        f.chmod(0o600)
    except OSError:
        pass
    (kd / f"{kid}.pub").write_text(raw_pub.hex())
    return kid


def list_keys(ws: Path) -> list[str]:
    kd = ws / "keys"
    return sorted(p.stem for p in kd.glob("*.pub")) if kd.exists() else []


def sign_bytes(ws: Path, data: bytes, key_id: str | None = None) -> dict:
    ser, Priv, _ = _keys()
    kid = key_id or (list_keys(ws) or [keygen(ws)])[0]
    priv = Priv.from_private_bytes(bytes.fromhex((ws / "keys" / f"{kid}.key").read_text().strip()))
    return {"alg": "ed25519", "key_id": kid, "signature": base64.b64encode(priv.sign(data)).decode(),
            "public_key": (ws / "keys" / f"{kid}.pub").read_text().strip()}


def verify_signature(data: bytes, sig: dict, trusted_public_keys: list[str] | None = None) -> bool:
    ser, _, Pub = _keys()
    try:
        pub_hex = sig["public_key"]
        if trusted_public_keys is not None and pub_hex not in trusted_public_keys:
            return False
        Pub.from_public_bytes(bytes.fromhex(pub_hex)).verify(base64.b64decode(sig["signature"]), data)
        return key_id_of(bytes.fromhex(pub_hex)) == sig["key_id"]
    except Exception:
        return False


# ---------------------------------------------------------------- deterministic package (zip)
def make_package(files: dict[str, bytes | str]) -> bytes:
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name in sorted(files):
            data = files[name].encode("utf-8") if isinstance(files[name], str) else files[name]
            zi = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            z.writestr(zi, data)
    return buf.getvalue()


def read_package(data: bytes) -> dict[str, bytes]:
    import io
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return {n: z.read(n) for n in z.namelist()}


def verify_package(data: bytes, trusted_public_keys: list[str] | None = None, compat: tuple[str, ...] = ("1",)) -> dict:
    """Signature, per-file hashes and compatibility. Returns manifest on success, raises ValueError otherwise."""
    files = read_package(data)
    if "manifest.json" not in files or "SIGNATURE.json" not in files:
        raise ValueError("package is unsigned or has no manifest")
    manifest = json.loads(files["manifest.json"])
    if not verify_signature(files["manifest.json"], json.loads(files["SIGNATURE.json"]), trusted_public_keys):
        raise ValueError("signature verification failed")
    for name, digest in manifest["files"].items():
        if name not in files or sha256_hex(files[name]) != digest:
            raise ValueError(f"file hash mismatch: {name}")
    if str(manifest.get("format", "")).split("/")[-1] not in compat:
        raise ValueError(f"incompatible package format {manifest.get('format')}")
    return manifest


# ---------------------------------------------------------------- artifact registry
class Registry:
    def __init__(self, ws: Path):
        self.dir = ws / "registry"
        self.dir.mkdir(parents=True, exist_ok=True)

    def put(self, artifact_id: str, package: bytes, meta: dict) -> dict:
        d = self.dir / artifact_id
        d.mkdir(parents=True, exist_ok=True)
        (d / "package.zip").write_bytes(package)
        meta = dict(meta, id=artifact_id, created=datetime.now(timezone.utc).isoformat(timespec="seconds"), size=len(package))
        (d / "meta.json").write_text(json.dumps(meta, indent=1))
        return meta

    def list(self) -> list[dict]:
        out = []
        for d in self.dir.iterdir():
            if (d / "meta.json").exists():
                out.append(json.loads((d / "meta.json").read_text()))
        return sorted(out, key=lambda m: m["created"], reverse=True)

    def get(self, artifact_id: str) -> tuple[dict, bytes]:
        d = self.dir / artifact_id
        if not (d / "meta.json").exists():
            raise KeyError(artifact_id)
        return json.loads((d / "meta.json").read_text()), (d / "package.zip").read_bytes()

    def latest(self, project: str | None = None) -> dict | None:
        items = [m for m in self.list() if project is None or m.get("project") == project]
        return items[0] if items else None


# ---------------------------------------------------------------- immutable decision log
class DecisionLog:
    """Append-only hash chain. Records hold only IDs/hashes — never raw request data."""

    def __init__(self, ws: Path):
        self.path = ws / "decisions.jsonl"

    def _last(self) -> str:
        if not self.path.exists():
            return "0" * 64
        last = "0" * 64
        with self.path.open("rb") as f:
            for line in f:
                if line.strip():
                    last = json.loads(line)["hash"]
        return last

    def append(self, artifact: str, decision: str, rule: str, request_digest: str, obligations: list[str]) -> dict:
        rec = {"seq": int(time.time() * 1000), "artifact": artifact, "decision": decision, "rule": rule,
               "request": request_digest, "obligations": obligations, "prev": self._last()}
        rec["hash"] = sha256_hex(canonical_json(rec))
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        return rec

    def verify(self) -> dict:
        prev, n = "0" * 64, 0
        if not self.path.exists():
            return {"ok": True, "records": 0}
        for i, line in enumerate(self.path.read_text().splitlines()):
            if not line.strip():
                continue
            rec = json.loads(line)
            h = rec.pop("hash")
            if rec["prev"] != prev or sha256_hex(canonical_json(rec)) != h:
                return {"ok": False, "records": n, "broken_at": i + 1}
            prev, n = h, n + 1
        return {"ok": True, "records": n, "head": prev}

    def tail(self, n: int = 50) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(x) for x in self.path.read_text().splitlines()[-n:] if x.strip()]

    @staticmethod
    def digest_request(slots: dict[str, int]) -> str:
        return sha256_hex(canonical_json(slots))[:32]


# ---------------------------------------------------------------- snapshots
class Snapshots:
    def __init__(self, ws: Path):
        self.dir = ws / "snapshots"
        self.dir.mkdir(parents=True, exist_ok=True)

    def create(self, analysis: dict, bundle_files: dict[str, str], label: str = "", extra: dict | None = None) -> dict:
        sid = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + analysis["sourceHash"][:8]
        d = self.dir / sid
        d.mkdir(parents=True, exist_ok=True)
        keep = {k: analysis[k] for k in ("project", "findings", "properties", "assertions", "constraints", "metrics", "diagnostics", "policy", "graph", "sourceHash", "symbols", "controlCoverage") if k in analysis}
        keep["policy"] = {k: v for k, v in analysis["policy"].items() if k in ("rules", "conflicts", "coverage", "tests", "optimizations")}
        (d / "analysis.json").write_text(json.dumps(keep))
        (d / "sources.json").write_text(json.dumps(bundle_files))
        meta = {"id": sid, "label": label, "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "sourceHash": analysis["sourceHash"], "project": analysis["project"]["name"], "metrics": analysis["metrics"], **(extra or {})}
        (d / "meta.json").write_text(json.dumps(meta, indent=1))
        return meta

    def list(self) -> list[dict]:
        return sorted((json.loads((d / "meta.json").read_text()) for d in self.dir.iterdir() if (d / "meta.json").exists()), key=lambda m: m["created"])

    def load(self, sid: str) -> dict:
        d = self.dir / sid
        if not d.exists():
            raise KeyError(sid)
        return {"meta": json.loads((d / "meta.json").read_text()), "analysis": json.loads((d / "analysis.json").read_text()),
                "sources": json.loads((d / "sources.json").read_text())}
