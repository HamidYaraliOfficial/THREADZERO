"""Regenerate golden artifacts: python python/tests/update_golden.py"""
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from conftest import EXAMPLES, compiled  # noqa: E402
from threadzero.testing import golden_snapshot  # noqa: E402

sha = lambda x: hashlib.sha256(x if isinstance(x, bytes) else x.encode()).hexdigest()  # noqa: E731
for n in EXAMPLES:
    _, A, eng, r = compiled(n)
    g = {"files": {f: sha(r["files"][f]) for f in ("policy.wat", "policy.json", "policy.rego", "guard.js")},
         "decisions": golden_snapshot(A, eng)["decisions"][:40]}
    (Path(__file__).parent / "golden" / f"{n}.json").write_text(json.dumps(g, indent=1, sort_keys=True))
    print("golden", n)
