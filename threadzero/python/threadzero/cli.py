"""threadzero — command line interface."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import COMPILER_VERSION, build, core, impact, integrations, lab, reports, schedule
from .core import CoreError
from .explain import explain_decision
from .runtime import PolicyEngine
from .store import DecisionLog, Registry, Snapshots, keygen, list_keys, read_package, verify_package, workspace
from .testing import run_all

SEV_COLOR = {"error": "31", "warning": "33", "notice": "36", "finding": "35", "optimization": "34"}


def c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() and not os.environ.get("NO_COLOR") else text


def print_diags(diags: list[dict], only: set[str] | None = None) -> None:
    for d in diags:
        if only and d["severity"] not in only:
            continue
        loc = f"{d['file']}:{d['line']}:{d['col']}" if d["line"] else d["file"] or "-"
        print(f"{loc}: {c(d['severity'], SEV_COLOR.get(d['severity'], '0'))} [{d['code']}] {d['message']}")
        if d.get("hint"):
            print(f"    hint: {d['hint']}")


def _engine(path: str):
    b = core.load_project(path)
    r = build.compile_bundle(b, ws=None, sign=False, register=False, run_tests=False)
    return b, r["analysis"], PolicyEngine(r["files"]["policy.wasm"], json.loads(r["files"]["policy.json"])), r


def cmd_check(a: argparse.Namespace) -> int:
    A = core.analyze(Path(a.model))
    if a.json:
        print(json.dumps(A["diagnostics"], indent=1))
    else:
        print_diags(A["diagnostics"], None if a.all else {"error", "warning", "notice"})
        m = A["metrics"]["findingsBySeverity"]
        print(f"\n{A['project']['name']}: {A['errorCount']} error(s), {sum(m.values())} finding(s) " + " ".join(f"{k}:{v}" for k, v in m.items() if v))
    return 1 if A["errorCount"] else 0


def cmd_verify(a: argparse.Namespace) -> int:
    A = core.analyze(Path(a.model))
    print(f"{A['project']['name']} — security properties")
    for p in A["properties"]:
        print(f"  {'✔' if p['status'] == 'holds' else '✘' if p['status'] == 'violated' else '–'} {p['name']:<20} {p['status']:<9} {p['discharge']}")
    print("assertions:")
    for x in A["assertions"]:
        print(f"  {'✔' if x['status'] != 'violated' else '✘'} {x['name']:<28} {x['status']:<10} ({x['method']})  {x['evidence'][0] if x['evidence'] else ''}")
    for x in A["constraints"]:
        print(f"  {'✔' if x['satisfied'] else '✘'} constraint {x['name']}")
    bad = [p for p in A["properties"] if p["status"] == "violated"] or [x for x in A["assertions"] if x["status"] == "violated"]
    return 1 if bad and a.strict else 0


def cmd_compile(a: argparse.Namespace) -> int:
    try:
        r = build.compile_path(a.model, out=a.out, sign=not a.no_sign, register=not a.no_register, force=a.force, update_lock=a.update_lock, locked=a.locked)
    except build.BuildError as exc:
        print_diags(exc.analysis["diagnostics"] if exc.analysis else [], {"error"})
        print(c(f"build failed: {exc}", "31"))
        return 1
    print_diags(r["diagnostics"], {"error", "warning"})
    t = r["tests"]
    print(f"artifact {r['artifactId']}  ({len(r['files']['policy.wasm'])} B wasm, {r['manifest']['rules']} rules, package {len(r['package'])} B)")
    print(f"tests: {t['passed']}/{t['total']} passed  " + "  ".join(f"{k}:{v['passed']}/{v['passed'] + v['failed']}" for k, v in t["sections"].items()))
    print(f"lockfile: {r.get('lockStatus', 'n/a')}   reproducible manifest hash: {r['manifestHash'][:16]}")
    if a.out:
        print(f"written to {a.out}")
    return 0


def cmd_test(a: argparse.Namespace) -> int:
    b, A, eng, r = _engine(a.model)
    t = run_all(A, eng, r["files"], n_random=a.random, targets=a.targets)
    for cs in t["cases"]:
        if not cs["ok"] or a.verbose:
            print(f"{'PASS' if cs['ok'] else 'FAIL'}  [{cs['section']}] {cs['name']}")
            if not cs["ok"]:
                print(f"      expected {cs['expected']}  actual {cs['actual']}")
    print(f"{t['passed']}/{t['total']} passed  " + "  ".join(f"{k}:{v['passed']}/{v['passed'] + v['failed']}" for k, v in t["sections"].items()))
    return 0 if not t["failed"] or a.allow_model_failures and all(cs["section"] in ("assertions", "constraints") for cs in t["cases"] if not cs["ok"]) else 1


def cmd_simulate(a: argparse.Namespace) -> int:
    b, A, eng, _ = _engine(a.model)
    req = json.loads(Path(a.request).read_text() if a.request and Path(a.request).exists() else a.request or "{}")
    out = explain_decision(eng, req)
    d = out["decision"]
    print(c(d["decision"].upper(), "32" if d["decision"] == "allow" else "31"), "—", d["reason_text"] or d["reason"])
    for s in out["steps"]:
        print("  •", s)
    if d["obligations"]:
        print("  obligations:", ", ".join(d["obligations"]))
    print("  context flags:", ", ".join(out["context"]["flags"]) or "none")
    if a.json:
        print(json.dumps(out, indent=1))
    return 0


def cmd_refactor(a: argparse.Namespace) -> int:
    b = core.load_project(a.model)
    A = core.analyze_bundle(b)
    fid = a.finding or (A["findings"][0]["id"] if A["findings"] else None)
    if not fid:
        print("no findings to refactor")
        return 0
    res = core.refactor(b, fid)
    f = res["finding"]
    print(f"{f['id']} {f['category']} ({f['severity']}): {f['message']}\n")
    for cand in res["candidates"]:
        ok = all(p["holds"] for p in cand["postconditions"])
        print(f"Candidate {cand['id']} — {cand['title']}  [{'verified' if ok else 'partial'}]")
        print(f"  {cand['description']}")
        print(f"  removes {len(cand['securityImpact']['removed'])} / adds {len(cand['securityImpact']['added'])} findings · equivalent={cand['functionalImpact']['equivalent']} · +{cand['cost']['newComponents']} components")
        for p in cand["postconditions"]:
            print(f"    {'✔' if p['holds'] else '✘'} {p['text']}")
        if a.out:
            out = Path(a.out)
            out.mkdir(parents=True, exist_ok=True)
            (out / f"{f['id']}-candidate-{cand['id']}.tz").write_text(cand["dsl"])
    if a.out:
        print(f"\ncandidate models written to {a.out} (review them; nothing was applied)")
    return 0


def cmd_diff(a: argparse.Namespace) -> int:
    base, head = core.analyze(Path(a.base)), core.analyze(Path(a.head))
    d = impact.diff_analyses(base, head)
    print(f"findings: +{len(d['findings']['new'])} new, -{len(d['findings']['fixed'])} fixed, {len(d['findings']['remaining'])} remaining")
    for f in d["findings"]["new"]:
        print(f"  + {f['severity']:<8} {f['category']}: {f['message'][:110]}")
    for f in d["findings"]["fixed"]:
        print(f"  - {f['severity']:<8} {f['category']}: {f['message'][:110]}")
    print("graph:", {k: v for k, v in d["graph"].items() if v})
    print("rules:", {k: v for k, v in d["rules"].items() if v})
    print("policy coverage:", d["coverage"], " gate:", d["gate"])
    if a.json:
        print(json.dumps(d, indent=1))
    return 1 if a.fail_on_regression and (d["gate"]["newCritical"] or d["gate"]["regressedProperties"] or d["gate"]["newErrors"]) else 0


def cmd_generate(a: argparse.Namespace) -> int:
    b = core.load_project(a.model)
    r = build.compile_bundle(b, ws=None, sign=False, register=False, run_tests=False, force=a.force)
    out = Path(a.out)
    only = set(a.target or [])
    for name, content in r["files"].items():
        if only and not any(name.startswith(t) or name.endswith(t) for t in only):
            continue
        f = out / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(content if isinstance(content, bytes) else content.encode())
        print("generated", f)
    return 0


def cmd_package(a: argparse.Namespace) -> int:
    ws = workspace(Path(a.model).resolve().parent if Path(a.model).is_file() else a.model)
    r = build.compile_path(a.model, out=None, sign=True, register=True, key_id=a.key, run_tests=True)
    path = Path(a.out or f"{r['artifactId']}.tzpkg")
    path.write_bytes(r["package"])
    print(f"signed package {path} ({len(r['package'])} B) artifact {r['artifactId']} tests {r['tests']['passed']}/{r['tests']['total']}")
    return 0


def cmd_explain(a: argparse.Namespace) -> int:
    A = core.analyze(Path(a.model))
    if a.what.startswith("F-"):
        f = next((x for x in A["findings"] if x["id"] == a.what), None)
        if not f:
            print("unknown finding")
            return 1
        print(f"{f['id']} {f['category']} — {f['severity']} (confidence {f['confidence']})\n{f['message']}")
        print("path:", " → ".join(f["path"]))
        for e in f["evidence"]:
            print("evidence:", e)
        print("violated rule:", f["violatedRule"])
        print("suggested fix:", f["suggestedFix"])
        return 0
    if a.what.startswith("TZ"):
        for d in A["diagnostics"]:
            if d["code"] == a.what:
                print_diags([d])
        return 0
    rs = [r for r in A["policy"]["rules"] if a.what in (r["id"], r["policy"], r["name"])]
    for r in rs:
        print(f"{r['id']}: {r['effect']} (priority {r['priority']}, specificity {r['specificity']})\n  when {r['condText']}\n  reason: {r['reason']}  obligations: {r['obligations']}  [{r['file']}:{r['line']}]")
    if not rs:
        print("nothing found; pass a finding id (F-001), a diagnostic code (TZ2001) or a policy/rule name")
        return 1
    return 0


def cmd_fmt(a: argparse.Namespace) -> int:
    p = Path(a.file)
    out = core.fmt(p.read_text("utf-8"))
    if a.write:
        p.write_text(out, "utf-8")
    else:
        print(out, end="")
    return 0


def cmd_init(a: argparse.Namespace) -> int:
    d = Path(a.dir)
    d.mkdir(parents=True, exist_ok=True)
    src = (Path(__file__).resolve().parents[2] / "examples" / "secure_api" / "main.tz").read_text("utf-8")
    (d / "main.tz").write_text(src)
    workspace(d)
    keygen(d / ".threadzero")
    print(f"initialised {d} — edit main.tz, then: threadzero check {d}/main.tz && threadzero compile {d}/main.tz")
    return 0


def cmd_bench(a: argparse.Namespace) -> int:
    res = lab.benchmark([int(x) for x in a.rules.split(",")], a.requests, a.depth, a.threads)
    print(f"{'rules':>7} {'wasm B':>8} {'p50 µs':>8} {'p95 µs':>8} {'p99 µs':>9} {'req/s':>9} {'rss MB':>7} {'path':>6}")
    for r in res["rows"]:
        print(f"{r['rules']:>7} {r['wasmBytes']:>8} {r['p50Us']:>8} {r['p95Us']:>8} {r['p99Us']:>9} {r['throughputPerSec']:>9} {r['rssMB']:>7} {r['avgDecisionPath']:>6}")
    return 0


def cmd_fault(a: argparse.Namespace) -> int:
    ws = workspace(Path(a.model).resolve().parent)
    b = core.load_project(a.model)
    r = build.compile_bundle(b, ws=ws, sign=True, register=False, run_tests=False)
    bad = 0
    for x in lab.fault_injection(r["package"], ws):
        print(f"{'SAFE  ' if x['safe'] else 'UNSAFE'} {x['scenario']:<48} -> {x['actual'][:70]}")
        bad += not x["safe"]
    return 1 if bad else 0


def cmd_snapshot(a: argparse.Namespace) -> int:
    ws = workspace(Path(a.model).resolve().parent)
    s = Snapshots(ws)
    if a.action == "create":
        b = core.load_project(a.model)
        print(json.dumps(s.create(core.analyze_bundle(b), b.files, a.label or ""), indent=1))
    elif a.action == "list":
        for m in s.list():
            print(m["id"], m.get("label", ""), m["metrics"]["findingsBySeverity"])
    else:
        d = impact.diff_analyses(s.load(a.ids[0])["analysis"] | {"tool": {}}, s.load(a.ids[1])["analysis"] | {"tool": {}})
        print(json.dumps({k: d[k] for k in ("findings", "rules", "graph", "coverage")}, indent=1)[:4000])
    return 0


def cmd_schedule(a: argparse.Namespace) -> int:
    A = core.analyze(Path(a.model))
    for r in schedule.evaluate(schedule.windows_from_ast(A), a.now, A["project"]["timezone"]):
        print(f"{r['name']:<22} {r['kind']:<11} {r['text']}   (now {r['now_local']})")
    return 0


def cmd_ci(a: argparse.Namespace) -> int:
    """Security CI Compiler Mode: exit 1 when the configured gate fails."""
    worst = 0
    for m in a.models:
        b = core.load_project(m)
        A = core.analyze_bundle(b)
        t = None
        if A["ok"]:
            r = build.compile_bundle(b, ws=None, sign=False, register=False, run_tests=True)
            t = r["tests"]
        base = core.analyze(Path(a.baseline)) if a.baseline else None
        res = integrations.ci_evaluate(A, a.fail_on, t, base)
        print(f"{'PASS' if res['passed'] else 'FAIL'}  {m}  " + ("; ".join(res["reasons"]) or "no blocking issues"))
        if a.sarif:
            Path(a.sarif).write_text(json.dumps(integrations.to_sarif(A), indent=1))
        if a.junit:
            Path(a.junit).write_text(integrations.to_junit(A, t))
        worst |= 0 if res["passed"] else 1
    return worst


def cmd_codemap(a: argparse.Namespace) -> int:
    scan = integrations.scan_tree(a.dir)
    A = core.analyze(Path(a.model)) if a.model else None
    m = integrations.map_to_model(scan, A) if A else None
    print(f"scanned {scan['filesScanned']} files: {len(scan['endpoints'])} endpoints, {len(scan['database'])} db access, {len(scan['queue'])} queue, {len(scan['client'])} clients")
    for e in scan["endpoints"][:20]:
        print(f"  {e['method']:<6} {e['path']:<30} {e['file']}:{e['line']} ({e['lang']})")
    if m and m["suggestedDsl"]:
        print("\nsuggested DSL:\n" + m["suggestedDsl"])
    return 0


def cmd_report(a: argparse.Namespace) -> int:
    A = core.analyze(Path(a.model))
    content, _ = reports.export(a.kind, A, a.format)
    if a.out:
        Path(a.out).write_text(content, "utf-8")
        print("written", a.out)
    else:
        print(content)
    return 0


def cmd_verify_package(a: argparse.Namespace) -> int:
    try:
        m = verify_package(Path(a.package).read_bytes())
        print("OK", m["project"], m["sourceHash"][:12], "files:", len(m["files"]))
        return 0
    except ValueError as exc:
        print("INVALID:", exc)
        return 1


def cmd_keygen(a: argparse.Namespace) -> int:
    ws = workspace(a.dir)
    print("created key", keygen(ws), "in", ws / "keys", "(keep the .key file secret)")
    return 0


def cmd_serve(a: argparse.Namespace) -> int:
    import uvicorn
    os.environ.setdefault("THREADZERO_HOME", str(Path(a.workspace).resolve()))
    print(f"THREADZERO on http://{a.host}:{a.port}   workspace: {os.environ['THREADZERO_HOME']}")
    uvicorn.run("threadzero.api:app", host=a.host, port=a.port, log_level="info")
    return 0


def cmd_doctor(a: argparse.Namespace) -> int:
    import shutil
    ok = True
    def row(name: str, good: bool, detail: str, required: bool = True) -> None:
        nonlocal ok
        if required:
            ok &= good
        print(f"{'✔' if good else '✘'} {name:<22} {detail}")
    try:
        row("Haskell core", True, core.core_version())
    except CoreError as exc:
        row("Haskell core", False, str(exc))
    try:
        import wasmtime  # noqa
        row("wasmtime", True, "importable")
    except Exception as exc:
        row("wasmtime", False, str(exc))
    for mod in ("fastapi", "uvicorn", "cryptography", "yaml"):
        try:
            __import__(mod)
            row(mod, True, "importable")
        except Exception as exc:
            row(mod, False, str(exc))
    row("node (optional)", bool(shutil.which("node")), shutil.which("node") or "needed to build the web studio and for JS differential tests", False)
    row("opa (optional)", bool(shutil.which("opa")), shutil.which("opa") or "enables Rego differential tests", False)
    row("z3 (optional)", bool(shutil.which("z3")), shutil.which("z3") or "enables external SMT solving", False)
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="threadzero", description=f"THREADZERO {COMPILER_VERSION} — Trust-Boundary Compiler")
    sp = p.add_subparsers(dest="cmd", required=True)

    def add(name: str, fn, help_: str):
        s = sp.add_parser(name, help=help_)
        s.set_defaults(fn=fn)
        return s
    s = add("check", cmd_check, "parse + semantic analysis + findings"); s.add_argument("model"); s.add_argument("--json", action="store_true"); s.add_argument("--all", action="store_true", help="include findings and optimization notes")
    s = add("verify", cmd_verify, "security properties, assertions and constraints"); s.add_argument("model"); s.add_argument("--strict", action="store_true")
    s = add("compile", cmd_compile, "generate WASM/Rego/JS/guards, run tests, package, sign, register"); s.add_argument("model"); s.add_argument("-o", "--out")
    s.add_argument("--no-sign", action="store_true"); s.add_argument("--no-register", action="store_true"); s.add_argument("--force", action="store_true"); s.add_argument("--update-lock", action="store_true"); s.add_argument("--locked", action="store_true")
    s = add("test", cmd_test, "run generated + property + flow + regression tests"); s.add_argument("model"); s.add_argument("--random", type=int, default=300); s.add_argument("--targets", action="store_true", help="also compare JS (node) and Rego (opa)"); s.add_argument("-v", "--verbose", action="store_true"); s.add_argument("--allow-model-failures", action="store_true")
    s = add("simulate", cmd_simulate, "evaluate a request in the WASM sandbox"); s.add_argument("model"); s.add_argument("request", nargs="?", help="JSON string or file"); s.add_argument("--json", action="store_true")
    s = add("refactor", cmd_refactor, "propose verified architecture candidates for a finding"); s.add_argument("model"); s.add_argument("--finding"); s.add_argument("-o", "--out")
    s = add("diff", cmd_diff, "security diff between two models"); s.add_argument("base"); s.add_argument("head"); s.add_argument("--json", action="store_true"); s.add_argument("--fail-on-regression", action="store_true")
    s = add("generate", cmd_generate, "write generated artifacts"); s.add_argument("model"); s.add_argument("-o", "--out", default="generated"); s.add_argument("--target", action="append", help="policy.wasm, policy.rego, guards/, ..."); s.add_argument("--force", action="store_true")
    s = add("package", cmd_package, "signed, versioned .tzpkg"); s.add_argument("model"); s.add_argument("-o", "--out"); s.add_argument("--key")
    s = add("explain", cmd_explain, "explain a finding (F-001), diagnostic (TZ2001) or policy/rule"); s.add_argument("model"); s.add_argument("what")
    s = add("fmt", cmd_fmt, "canonical formatting"); s.add_argument("file"); s.add_argument("-w", "--write", action="store_true")
    s = add("init", cmd_init, "create a starter project"); s.add_argument("dir", nargs="?", default="my-architecture")
    s = add("bench", cmd_bench, "Performance/Scale Lab"); s.add_argument("--rules", default="10,100,1000,5000"); s.add_argument("--requests", type=int, default=20000); s.add_argument("--depth", type=int, default=3); s.add_argument("--threads", type=int, default=1)
    s = add("fault", cmd_fault, "Fault Injection Lab (all scenarios must fail safe)"); s.add_argument("model")
    s = add("snapshot", cmd_snapshot, "create/list/diff security snapshots"); s.add_argument("action", choices=["create", "list", "diff"]); s.add_argument("model"); s.add_argument("--label"); s.add_argument("ids", nargs="*")
    s = add("schedule", cmd_schedule, "evaluate the time windows of a model (open now? next change?)"); s.add_argument("model"); s.add_argument("--now", help="ISO time to simulate")
    s = add("ci", cmd_ci, "Security CI Compiler Mode"); s.add_argument("models", nargs="+"); s.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "low"]); s.add_argument("--baseline"); s.add_argument("--sarif"); s.add_argument("--junit")
    s = add("codemap", cmd_codemap, "Code-to-Architecture mapping (Go, Python, TypeScript, C#, Java)"); s.add_argument("dir"); s.add_argument("--model")
    s = add("report", cmd_report, "generate documentation (md|json|yaml|html)"); s.add_argument("model"); s.add_argument("--kind", default="security", choices=["security", "policies", "controls", "tests", "compliance", "dfd", "tbd", "all"]); s.add_argument("--format", default="md"); s.add_argument("-o", "--out")
    s = add("verify-package", cmd_verify_package, "verify a .tzpkg signature and hashes"); s.add_argument("package")
    s = add("keygen", cmd_keygen, "create an Ed25519 signing key"); s.add_argument("dir", nargs="?", default=".")
    s = add("serve", cmd_serve, "start the API + web UI"); s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8737); s.add_argument("--workspace", default=".")
    add("doctor", cmd_doctor, "check the installation")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.fn(args) or 0)
    except CoreError as exc:
        print(c(f"error: {exc}", "31"), file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(c(f"error: {exc}", "31"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
