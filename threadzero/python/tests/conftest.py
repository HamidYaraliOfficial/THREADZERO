import json
import os
import sys
from functools import lru_cache
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))
EXAMPLES = ["secure_api", "payment_workflow", "document_pipeline", "ai_agent_access", "multi_tenant_saas", "partner_integration"]

from threadzero import build, core  # noqa: E402
from threadzero.runtime import PolicyEngine  # noqa: E402


@lru_cache(maxsize=None)
def compiled(name: str):
    b = core.load_project(ROOT / "examples" / name)
    r = build.compile_bundle(b, ws=None, sign=False, register=False, run_tests=False)
    eng = PolicyEngine(r["files"]["policy.wasm"], json.loads(r["files"]["policy.json"]))
    return b, r["analysis"], eng, r


@pytest.fixture(params=EXAMPLES)
def example(request):
    return request.param, *compiled(request.param)


@pytest.fixture
def ws(tmp_path):
    from threadzero.store import workspace
    return workspace(tmp_path)


def pytest_sessionfinish(session, exitstatus):  # release wasmtime objects before interpreter teardown
    import gc
    compiled.cache_clear()
    gc.collect()
