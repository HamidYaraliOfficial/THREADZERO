"""FastAPI service: everything the web UI (and any integration) needs. Binds to localhost by default."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import COMPILER_VERSION, ABI_VERSION, RULESET_VERSION, ai, build, codegen, core, impact, integrations, lab, reports, schedule
from .core import Bundle, ROOT
from .explain import explain_decision
from .host import PolicyHost, distribute
from .runtime import PolicyEngine
from .store import DecisionLog, Registry, Snapshots, keygen, list_keys, read_package, workspace
from .testing import run_all

EXAMPLES = ROOT / "examples"


class State:
    def __init__(self) -> None:
        self.root = Path(os.environ.get("THREADZERO_HOME") or Path.cwd())
        self.ws = workspace(self.root)
        self.host = PolicyHost(None, on_decision=self._log)
        self.analyses: dict[str, dict] = {}
        self.engines: dict[str, tuple[PolicyEngine, dict]] = {}
        self.log = DecisionLog(self.ws)

    def _log(self, version: str, request: dict, d: Any) -> None:
        self.log.append(version, d.decision, d.reason, DecisionLogDigest(request), d.obligations)

    def bundle(self, body: dict) -> Bundle:
        if body.get("files"):
            return core.Bundle(core.bundle_text(body["files"]), body["files"], "")
        if body.get("example"):
            return core.load_project(EXAMPLES / body["example"])
        if body.get("path"):
            p = (self.root / body["path"]).resolve()
            if not str(p).startswith(str(self.root.resolve())) and not str(p).startswith(str(EXAMPLES.resolve())):
                raise HTTPException(403, "path is outside the workspace")
            return core.load_project(p)
        if "source" in body:
            return core.bundle_from_source(body["source"], body.get("name", "main.tz"))
        raise HTTPException(400, "provide source, files, example or path")

    def analyze(self, b: Bundle) -> dict:
        if b.hash not in self.analyses:
            if len(self.analyses) > 64:
                self.analyses.pop(next(iter(self.analyses)))
            self.analyses[b.hash] = core.analyze_bundle(b)
        return self.analyses[b.hash]

    def engine(self, b: Bundle) -> tuple[PolicyEngine, dict, dict]:
        A = self.analyze(b)
        if b.hash not in self.engines:
            if any(d["severity"] == "error" for d in A["diagnostics"]):
                raise HTTPException(422, "the model has compiler errors; fix them before simulating")
            files = build.generate_artifacts(A)
            self.engines[b.hash] = (PolicyEngine(files["policy.wasm"], json.loads(files["policy.json"])), files)
        eng, files = self.engines[b.hash]
        return eng, files, A


def DecisionLogDigest(request: dict) -> str:
    return core.sha256_hex(core.canonical_json(request))[:32]


def create_app() -> FastAPI:
    st = State()
    app = FastAPI(title="THREADZERO", version=COMPILER_VERSION, docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:8737", "http://127.0.0.1:8737"],
                       allow_methods=["*"], allow_headers=["*"])
    B = Body(...)

    @app.get("/api/health")
    def health() -> dict:
        try:
            cv = core.core_version()
        except core.CoreError as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "core": cv, "compiler": COMPILER_VERSION, "abi": ABI_VERSION, "ruleset": RULESET_VERSION, "workspace": str(st.root)}

    # ---- examples ---------------------------------------------------------------------
    @app.get("/api/examples")
    def examples() -> list[dict]:
        out = []
        for d in sorted(EXAMPLES.iterdir()) if EXAMPLES.exists() else []:
            f = d / ("main.tz" if (d / "main.tz").exists() else "errors.tz")
            if f.exists():
                first = f.read_text("utf-8").splitlines()
                out.append({"name": d.name, "file": f.name, "title": next((ln.lstrip("# ").strip() for ln in first if ln.startswith("# THREADZERO")), d.name)})
        return out

    @app.get("/api/examples/{name}")
    def example(name: str) -> dict:
        d = EXAMPLES / name
        f = d / "main.tz" if (d / "main.tz").exists() else d / "errors.tz"
        if not f.exists() or ".." in name:
            raise HTTPException(404, "unknown example")
        return {"name": name, "source": f.read_text("utf-8")}

    # ---- compiler ---------------------------------------------------------------------
    @app.post("/api/parse")
    def parse(body: dict = B) -> dict:
        return core.parse(body["source"])

    @app.post("/api/format")
    def fmt(body: dict = B) -> dict:
        try:
            return {"source": core.fmt(body["source"])}
        except core.CoreError as exc:
            raise HTTPException(422, str(exc))

    @app.post("/api/analyze")
    def analyze(body: dict = B) -> dict:
        return st.analyze(st.bundle(body))

    @app.post("/api/compile")
    def compile_(body: dict = B) -> dict:
        b = st.bundle(body)
        try:
            r = build.compile_bundle(b, ws=st.ws, sign=body.get("sign", True), register=body.get("register", True), run_tests=True, force=body.get("force", False))
        except build.BuildError as exc:
            return {"ok": False, "error": str(exc), "diagnostics": exc.analysis["diagnostics"] if exc.analysis else []}
        st.analyses[b.hash] = r["analysis"]
        st.engines[b.hash] = (PolicyEngine(r["files"]["policy.wasm"], json.loads(r["files"]["policy.json"])), r["files"])
        t = r["tests"]
        return {"ok": True, "artifactId": r["artifactId"], "manifest": r["manifest"], "manifestHash": r["manifestHash"], "diagnostics": r["diagnostics"],
                "files": [{"name": n, "size": len(c)} for n, c in sorted(r["files"].items())], "tests": {k: t[k] for k in ("passed", "failed", "total", "sections")},
                "signed": True if body.get("sign", True) else False}

    @app.post("/api/compile/preview")
    def compile_preview(body: dict = B) -> dict:
        """Compiler Playground: AST, semantic graph, policy output, WASM metadata and tests in one response."""
        b = st.bundle(body)
        A = st.analyze(b)
        out: dict[str, Any] = {"ast": A["ast"], "diagnostics": A["diagnostics"], "graph": A["graph"], "ok": A["ok"]}
        if A["ok"]:
            files = build.generate_artifacts(A)
            eng, _, _ = st.engine(b)
            t = run_all(A, eng, files)
            out.update(policy={"rules": A["policy"]["rules"], "wat": files["policy.wat"], "rego": files["policy.rego"], "json": json.loads(files["policy.json"])},
                       wasm={"bytes": len(files["policy.wasm"]), "sha256": core.sha256_hex(files["policy.wasm"]), "exports": ["authorize", "validate_flow", "validate_boundary", "inspect_context", "classify_data", "audit_event", "deny_reason"], "rules": len(A["policy"]["rules"])},
                       tests={k: t[k] for k in ("passed", "failed", "total", "sections")})
        return out

    @app.post("/api/tests")
    def tests(body: dict = B) -> dict:
        eng, files, A = st.engine(st.bundle(body))
        return run_all(A, eng, files, n_random=body.get("random", 300), targets=body.get("targets", False))

    # ---- simulation ---------------------------------------------------------------------
    @app.post("/api/simulate")
    def simulate(body: dict = B) -> dict:
        eng, _, _ = st.engine(st.bundle(body))
        out = explain_decision(eng, body["request"])
        return out

    @app.post("/api/simulate/boundary")
    def simulate_boundary(body: dict = B) -> dict:
        eng, _, A = st.engine(st.bundle(body))
        req = body["request"]
        flow = eng.validate_flow(req)
        boundary = eng.validate_boundary(req)
        return {"flow": flow, "boundary": boundary, "explanation": ("All required controls are present." if flow["ok"] else
                "Missing controls: " + ", ".join(flow["missing_controls"] or ["(none — see reason)"]) + f". Reason: {flow['reason']}.")}

    @app.post("/api/context")
    def context(body: dict = B) -> dict:
        eng, _, _ = st.engine(st.bundle(body))
        return {"context": eng.inspect_context(body["request"]), "classification": eng.classify_data(body["request"])}

    @app.post("/api/permissions")
    def permissions(body: dict = B) -> dict:
        """Permission Explorer: every resource/data/action a subject (roles + context) may reach, plus delegation paths."""
        eng, _, A = st.engine(st.bundle(body))
        roles = body.get("roles", [])
        touch: dict[str, set] = {}
        for e in A["graph"]["edges"]:
            touch.setdefault(e["to"], set()).update(e["data"])
            touch.setdefault(e["from"], set()).update(e["data"])
        ops = {d["name"]: d["props"].get("operations") for d in A["ast"]["dataTypes"]}
        actions = [a["name"] for a in A["symbols"]["actions"]]
        rows = []
        for n in A["graph"]["nodes"]:
            for d in sorted(touch.get(n["id"], [])):
                for act in (ops.get(d) or actions):
                    req = {"subject": {"roles": roles, "mfa": body.get("mfa", True), "device_trust": body.get("deviceTrust", 3)}, "resource": n["id"], "action": act,
                           "data": d, "zone": n["zone"], "context": {"time": body.get("time", 600), "secure_channel": True, "tenant_match": True, "approved": body.get("approved", False), "emergency": body.get("emergency", False)}}
                    dec = eng.evaluate(req)
                    if dec.decision != "deny" or body.get("includeDenied"):
                        rows.append({"resource": n["id"], "zone": n["zone"], "data": d, "action": act, "decision": dec.decision, "reason": dec.reason, "obligations": dec.obligations})
        deleg = [{"name": x["name"], **{k: v for k, v in x["props"].items()}} for x in A["ast"]["delegations"] if x["props"].get("role") in roles or x["props"].get("to") in body.get("subjects", [])]
        return {"rows": rows[:600], "total": len(rows), "delegations": deleg}

    @app.post("/api/encode")
    def encode(body: dict = B) -> dict:
        eng, _, _ = st.engine(st.bundle(body))
        slots = eng.symbols.encode(body["request"])
        from .abi import full_slots
        return {"slots": full_slots(slots), "fields": codegen.INFIELDS if hasattr(codegen, "INFIELDS") else []}

    # ---- refactoring / diff / impact -------------------------------------------------------
    @app.post("/api/refactor")
    def refactor(body: dict = B) -> dict:
        return core.refactor(st.bundle(body), body["findingId"])

    @app.post("/api/diff")
    def diff(body: dict = B) -> dict:
        a, b = st.analyze(core.bundle_from_source(body["base"])), st.analyze(core.bundle_from_source(body["head"]))
        return impact.diff_analyses(a, b)

    @app.post("/api/impact")
    def change_impact(body: dict = B) -> dict:
        bb, hb = core.bundle_from_source(body["base"]), core.bundle_from_source(body["head"])
        base, head = st.analyze(bb), st.analyze(hb)
        out: dict[str, Any] = {"diff": impact.diff_analyses(base, head)}
        if base["ok"] and head["ok"]:
            be, _, _ = st.engine(bb)
            he, _, _ = st.engine(hb)
            out["regression"] = impact.regression(base, head, be, he)
        return out

    @app.post("/api/dependencies")
    def dependencies(body: dict = B) -> dict:
        return impact.dependency_impact(st.analyze(st.bundle(body)), body["entity"], body.get("direction", "dependents"))

    @app.post("/api/counterfactual")
    def counterfactual(body: dict = B) -> dict:
        named = {n: st.analyze(core.bundle_from_source(src)) for n, src in body["variants"].items()}
        return impact.compare_architectures(named)

    # ---- reports / compliance -------------------------------------------------------------
    @app.post("/api/reports")
    def report(body: dict = B) -> dict:
        b = st.bundle(body)
        A = st.analyze(b)
        t = None
        if body.get("kind") in ("tests", "all") and A["ok"]:
            eng, files, _ = st.engine(b)
            t = run_all(A, eng, files)
        ref = core.refactor(b, body["findingId"]) if body.get("findingId") else None
        content, mime = reports.export(body.get("kind", "security"), A, body.get("format", "md"), t, ref)
        return {"content": content, "mime": mime}

    # ---- artifacts / registry ------------------------------------------------------------------
    @app.get("/api/registry")
    def registry() -> list[dict]:
        return Registry(st.ws).list()

    @app.get("/api/registry/{aid}")
    def registry_item(aid: str) -> dict:
        try:
            meta, pkg = Registry(st.ws).get(aid)
        except KeyError:
            raise HTTPException(404, "unknown artifact")
        files = read_package(pkg)
        return {"meta": meta, "manifest": json.loads(files["manifest.json"]), "signature": json.loads(files["SIGNATURE.json"]) if "SIGNATURE.json" in files else None,
                "files": [{"name": n, "size": len(c)} for n, c in sorted(files.items())]}

    @app.get("/api/registry/{aid}/file")
    def registry_file(aid: str, name: str = Query(...)) -> Response:
        try:
            _, pkg = Registry(st.ws).get(aid)
        except KeyError:
            raise HTTPException(404, "unknown artifact")
        files = read_package(pkg)
        if name not in files:
            raise HTTPException(404, "no such file")
        if name.endswith(".wasm"):
            return Response(files[name], media_type="application/wasm")
        return PlainTextResponse(files[name].decode("utf-8", "replace"))

    @app.get("/api/registry/{aid}/package")
    def registry_package(aid: str) -> Response:
        _, pkg = Registry(st.ws).get(aid)
        return Response(pkg, media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="{aid}.tzpkg"'})

    @app.get("/api/keys")
    def keys() -> list[str]:
        return list_keys(st.ws)

    @app.post("/api/keys")
    def new_key() -> dict:
        return {"keyId": keygen(st.ws)}

    # ---- snapshots / history -----------------------------------------------------------
    @app.post("/api/snapshots")
    def snapshot(body: dict = B) -> dict:
        b = st.bundle(body)
        return Snapshots(st.ws).create(st.analyze(b), b.files, body.get("label", ""))

    @app.get("/api/snapshots")
    def snapshots() -> list[dict]:
        return Snapshots(st.ws).list()

    @app.get("/api/snapshots/diff")
    def snapshot_diff(a: str, b: str) -> dict:
        s = Snapshots(st.ws)
        return impact.diff_analyses(s.load(a)["analysis"] | {"tool": {}}, s.load(b)["analysis"] | {"tool": {}})

    @app.get("/api/history")
    def hist() -> list[dict]:
        return impact.history(Snapshots(st.ws).list())

    # ---- schedule (time-bounded access) -----------------------------------------------------
    sched_file = st.ws / "schedule.json"

    @app.get("/api/schedule")
    def get_schedule() -> dict:
        return json.loads(sched_file.read_text()) if sched_file.exists() else {"timezone": "UTC", "windows": []}

    @app.put("/api/schedule")
    def put_schedule(body: dict = B) -> dict:
        sched_file.write_text(json.dumps(body, indent=1))
        return body

    @app.post("/api/schedule/evaluate")
    def sched_eval(body: dict = B) -> dict:
        tz = body.get("timezone", "UTC")
        try:
            return {"results": schedule.evaluate(body["windows"], body.get("now"), tz), "timezone": tz}
        except Exception as exc:
            raise HTTPException(422, f"invalid schedule: {exc}")

    @app.post("/api/schedule/dsl")
    def sched_dsl(body: dict = B) -> dict:
        return {"dsl": schedule.windows_to_dsl(body["windows"])}

    @app.post("/api/schedule/from-model")
    def sched_from_model(body: dict = B) -> dict:
        A = st.analyze(st.bundle(body))
        return {"timezone": A["project"]["timezone"], "windows": schedule.windows_from_ast(A)}

    # ---- labs -----------------------------------------------------------------------------
    @app.post("/api/perf")
    def perf(body: dict = B) -> dict:
        return lab.benchmark([int(x) for x in body.get("rules", [10, 100, 1000])], int(body.get("requests", 10000)), int(body.get("depth", 3)), int(body.get("threads", 1)))

    @app.post("/api/perf/policy")
    def perf_policy(body: dict = B) -> dict:
        eng, _, A = st.engine(st.bundle(body))
        return lab.performance_analysis(A, eng)

    @app.post("/api/faults")
    def faults(body: dict = B) -> list[dict]:
        b = st.bundle(body)
        r = build.compile_bundle(b, ws=st.ws, sign=True, register=False, run_tests=False)
        return lab.fault_injection(r["package"], st.ws)

    # ---- CI / repo / code ------------------------------------------------------------------
    @app.post("/api/ci")
    def ci(body: dict = B) -> dict:
        b = st.bundle(body)
        A = st.analyze(b)
        t = None
        if A["ok"]:
            eng, files, _ = st.engine(b)
            t = run_all(A, eng, files)
        base = st.analyze(core.bundle_from_source(body["baseline"])) if body.get("baseline") else None
        res = integrations.ci_evaluate(A, body.get("failOn", "high"), t, base)
        return {**res, "sarif": integrations.to_sarif(A), "junit": integrations.to_junit(A, t), "markdown": integrations.impact_markdown(impact.diff_analyses(base, A), A) if base else ""}

    @app.post("/api/codemap")
    def codemap(body: dict = B) -> dict:
        root = (st.root / body.get("dir", ".")).resolve()
        if not str(root).startswith(str(st.root.resolve())):
            raise HTTPException(403, "directory is outside the workspace")
        A = st.analyze(st.bundle(body)) if any(k in body for k in ("source", "example", "path", "files")) else None
        scan = integrations.scan_tree(root)
        mapping = integrations.map_to_model(scan, A) if A else {"mapped": [], "unmapped": scan["endpoints"], "suggestedDsl": ""}
        return {"scan": {k: (v if k == "filesScanned" else v[:100]) for k, v in scan.items()}, "mapping": mapping, "traceability": integrations.traceability(A, mapping) if A else None}

    @app.post("/api/traceability")
    def trace(body: dict = B) -> dict:
        return integrations.traceability(st.analyze(st.bundle(body)))

    @app.post("/api/ai")
    def ask(body: dict = B) -> dict:
        b = st.bundle(body)
        A = st.analyze(b)
        eng = None
        try:
            eng, _, _ = st.engine(b) if A["ok"] else (None, None, None)
        except HTTPException:
            eng = None
        a = ai.Assistant(ai.Tools(A, b, eng))
        out = a.ask(body["question"], body.get("request"))
        phr = a.llm_rephrase(body["question"], out)
        if phr:
            out["llmAnswer"] = phr
        return out

    @app.post("/api/smt")
    def smt(body: dict = B) -> dict:
        text = core.smt(st.bundle(body), body["rule"])
        return {"smt": text, "z3": core.solve_with_z3(text)}

    # ---- runtime host ------------------------------------------------------------------------
    @app.post("/api/host/load")
    async def host_load(request: Request) -> dict:
        """Receives a signed .tzpkg (application/octet-stream). Verification happens before anything is loaded."""
        try:
            vid = st.host.load(await request.body())
        except Exception as exc:
            raise HTTPException(400, f"rejected: {exc}")
        return {"version": vid, "loaded": True}

    @app.post("/api/host/load-artifact")
    def host_load_artifact(body: dict = B) -> dict:
        _, pkg = Registry(st.ws).get(body["artifact"])
        vid = st.host.load(pkg)
        if body.get("activate", True):
            st.host.activate(vid)
        return {"version": vid, "status": st.host.status()}

    @app.post("/api/host/activate")
    def host_activate(body: dict = B) -> dict:
        return {"active": st.host.activate(body.get("version")), "status": st.host.status()}

    @app.post("/api/host/rollback")
    def host_rollback() -> dict:
        return {"active": st.host.rollback(), "status": st.host.status()}

    @app.post("/api/host/canary")
    def host_canary(body: dict = B) -> dict:
        _, pkg = Registry(st.ws).get(body["artifact"])
        vid = st.host.load(pkg)
        eng = st.host.versions[-1].engine
        from .testing import random_request
        import random
        rnd = random.Random(4)
        reqs = body.get("requests") or [random_request(rnd, eng.symbols) for _ in range(int(body.get("count", 200)))]
        return {"candidate": vid, **st.host.canary(vid, reqs, float(body.get("maxChangedRatio", 0.1)), promote=body.get("promote", False))}

    @app.post("/api/host/evaluate")
    def host_eval(body: dict = B) -> dict:
        return st.host.evaluate(body["request"]).to_dict()

    @app.get("/api/host/status")
    def host_status() -> dict:
        return st.host.status()

    @app.post("/api/distribute")
    def distribute_(body: dict = B) -> list[dict]:
        _, pkg = Registry(st.ws).get(body["artifact"])
        return distribute(pkg, body["targets"])

    # ---- decision log ---------------------------------------------------------------------------
    @app.get("/api/decisions")
    def decisions(n: int = 100) -> list[dict]:
        return st.log.tail(n)

    @app.get("/api/decisions/verify")
    def decisions_verify() -> dict:
        return st.log.verify()

    # ---- static UI (built with `npm run build` in web/) ----------------------------------------------
    ui = ROOT / "web" / "out"
    if ui.exists():
        app.mount("/", StaticFiles(directory=str(ui), html=True), name="ui")
    return app


app = create_app()
