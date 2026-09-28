"""Repository integration (GitHub/GitLab), Code-to-Architecture mapping, traceability graph and Security CI mode."""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from . import core
from .core import Bundle, bundle_text
from .impact import SEV_ORDER, diff_analyses


# ------------------------------------------------------------------ git providers
class GitError(RuntimeError):
    pass


class _Provider:
    """Credentials are read from the environment only and never logged."""
    token_env = ""

    def __init__(self, repo: str, token_env: str | None = None, api: str | None = None):
        self.repo, self.api = repo, (api or self.default_api).rstrip("/")
        self.token_env = token_env or self.token_env

    def _token(self) -> str:
        t = os.environ.get(self.token_env, "")
        if not t:
            raise GitError(f"environment variable {self.token_env} is not set")
        return t

    def _req(self, path: str, method: str = "GET", body: dict | None = None) -> Any:
        req = urllib.request.Request(self.api + path, method=method, data=json.dumps(body).encode() if body else None,
                                     headers=self._headers() | ({"Content-Type": "application/json"} if body else {}))
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raise GitError(f"{method} {path.split('?')[0]} failed: HTTP {exc.code}") from None
        except urllib.error.URLError as exc:
            raise GitError(f"network error: {exc.reason}") from None


class GitHub(_Provider):
    token_env, default_api = "GITHUB_TOKEN", "https://api.github.com"

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._token()}", "Accept": "application/vnd.github+json", "User-Agent": "threadzero"}

    def pr(self, number: int) -> dict:
        p = self._req(f"/repos/{self.repo}/pulls/{number}")
        return {"base": p["base"]["sha"], "head": p["head"]["sha"], "title": p["title"]}

    def changed_files(self, number: int) -> list[str]:
        return [f["filename"] for f in self._req(f"/repos/{self.repo}/pulls/{number}/files?per_page=100")]

    def list_tz(self, ref: str) -> list[str]:
        tree = self._req(f"/repos/{self.repo}/git/trees/{ref}?recursive=1")
        return [t["path"] for t in tree.get("tree", []) if t["path"].endswith(".tz")]

    def read(self, path: str, ref: str) -> str:
        import base64
        c = self._req(f"/repos/{self.repo}/contents/{urllib.parse.quote(path)}?ref={ref}")
        return base64.b64decode(c["content"]).decode("utf-8")

    def comment(self, number: int, body: str) -> None:
        self._req(f"/repos/{self.repo}/issues/{number}/comments", "POST", {"body": body})


class GitLab(_Provider):
    token_env, default_api = "GITLAB_TOKEN", "https://gitlab.com/api/v4"

    def _headers(self) -> dict:
        return {"PRIVATE-TOKEN": self._token(), "User-Agent": "threadzero"}

    def _pid(self) -> str:
        return urllib.parse.quote(self.repo, safe="")

    def pr(self, number: int) -> dict:
        m = self._req(f"/projects/{self._pid()}/merge_requests/{number}")
        return {"base": m["diff_refs"]["base_sha"], "head": m["diff_refs"]["head_sha"], "title": m["title"]}

    def changed_files(self, number: int) -> list[str]:
        return [c["new_path"] for c in self._req(f"/projects/{self._pid()}/merge_requests/{number}/changes")["changes"]]

    def list_tz(self, ref: str) -> list[str]:
        tree = self._req(f"/projects/{self._pid()}/repository/tree?recursive=true&per_page=100&ref={ref}")
        return [t["path"] for t in tree if t["path"].endswith(".tz")]

    def read(self, path: str, ref: str) -> str:
        import base64
        c = self._req(f"/projects/{self._pid()}/repository/files/{urllib.parse.quote(path, safe='')}?ref={ref}")
        return base64.b64decode(c["content"]).decode("utf-8")

    def comment(self, number: int, body: str) -> None:
        self._req(f"/projects/{self._pid()}/merge_requests/{number}/notes", "POST", {"body": body})


def bundle_from_files(files: dict[str, str], main: str) -> Bundle:
    """Resolve imports inside an in-memory file set (used for PR analysis at a given git ref)."""
    order: list[str] = []
    seen: set[str] = set()

    def visit(p: str, stack: tuple[str, ...] = ()) -> None:
        if p in stack:
            raise core.CoreError("circular import: " + " -> ".join(stack + (p,)))
        if p in seen:
            return
        for rel in core.IMPORT_RE.findall(files[p]):
            dep = os.path.normpath(os.path.join(os.path.dirname(p), rel)).replace("\\", "/")
            if dep not in files:
                raise core.CoreError(f"{p}: import not found: {rel}")
            visit(dep, stack + (p,))
        seen.add(p)
        order.append(p)
    visit(main)
    ordered = {p: files[p] for p in order}
    return Bundle(bundle_text(ordered), ordered, "")


def pull_request_report(provider: _Provider, number: int, model: str, post: bool = False) -> dict:
    info = provider.pr(number)
    changed = [f for f in provider.changed_files(number) if f.endswith(".tz")]
    if not changed:
        return {"changed": [], "markdown": "No `.tz` architecture files changed in this pull request.", "posted": False}
    def load(ref: str) -> Bundle:
        return bundle_from_files({p: provider.read(p, ref) for p in provider.list_tz(ref)}, model)
    base, head = core.analyze_bundle(load(info["base"])), core.analyze_bundle(load(info["head"]))
    diff = diff_analyses(base, head)
    md = impact_markdown(diff, head)
    if post:
        provider.comment(number, md)
    return {"changed": changed, "diff": diff, "markdown": md, "posted": post}


def impact_markdown(diff: dict, head: dict) -> str:
    g = diff["gate"]
    icon = "🔴" if g["newCritical"] or g["newErrors"] or g["newViolatedAssertions"] else "🟠" if g["newHigh"] else "🟢"
    lines = [f"### {icon} THREADZERO security change impact — {head['project']['name']}", "",
             f"**New findings:** {len(diff['findings']['new'])} · **Fixed:** {len(diff['findings']['fixed'])} · **Remaining:** {len(diff['findings']['remaining'])}", ""]
    for title, key in (("New", "new"), ("Fixed", "fixed")):
        items = diff["findings"][key]
        if items:
            lines += [f"<details><summary>{title} findings ({len(items)})</summary>", ""] + [f"- **{f['severity']}** `{f['category']}` — {f['message']}" for f in items[:25]] + ["", "</details>", ""]
    if g["regressedProperties"]:
        lines.append("**Regressed properties:** " + ", ".join(g["regressedProperties"]))
    if g["newViolatedAssertions"]:
        lines.append("**Newly violated assertions:** " + ", ".join(g["newViolatedAssertions"]))
    lines.append(f"\nPolicy coverage: {diff['coverage']['base']}% → {diff['coverage']['head']}% · boundary crossings: {diff['graph']['crossingsBase']} → {diff['graph']['crossingsHead']}")
    return "\n".join(lines)


# ------------------------------------------------------------------ code-to-architecture mapping
PATTERNS = {
    "endpoint": {
        "python": [r'@\w+\.(get|post|put|patch|delete)\(\s*["\']([^"\']+)', r'@\w+\.route\(\s*["\']([^"\']+)'],
        "typescript": [r'\b(?:app|router)\.(get|post|put|patch|delete)\(\s*[\'"`]([^\'"`]+)', r'@(Get|Post|Put|Patch|Delete)\(\s*[\'"]?([^\'")]*)'],
        "go": [r'\.(GET|POST|PUT|PATCH|DELETE)\(\s*"([^"]+)"', r'HandleFunc\(\s*"([^"]+)"'],
        "csharp": [r'\[(HttpGet|HttpPost|HttpPut|HttpPatch|HttpDelete)(?:\("([^"]*)"\))?\]', r'\.Map(Get|Post|Put|Delete)\(\s*"([^"]+)"'],
        "java": [r'@(Get|Post|Put|Patch|Delete)Mapping\(\s*(?:value\s*=\s*)?"?([^")]*)', r'@RequestMapping\(\s*"?([^")]*)'],
    },
    "database": [r"sqlalchemy|psycopg2|sqlite3|cursor\.execute|\.query\(|\bSELECT\s|\bINSERT\s+INTO|prisma\.|mongoose|gorm\.|database/sql|sql\.Open|DbContext|JdbcTemplate|EntityManager"],
    "queue": [r"KafkaProducer|producer\.send|kafkajs|basic_publish|sqs\.send_message|\.Publish\(|@KafkaListener|consumer\.subscribe|@RabbitListener|basic_consume|\.ReceiveMessage"],
    "client": [r"requests\.(get|post|put|delete)|httpx\.|\bfetch\(|axios\.|http\.Get\(|HttpClient|RestTemplate|WebClient"],
    "middleware": [r"app\.use\(|add_middleware\(|@app\.middleware|UseMiddleware|OncePerRequestFilter|gin\.Use\("],
}
LANG = {".py": "python", ".ts": "typescript", ".tsx": "typescript", ".js": "typescript", ".mjs": "typescript", ".go": "go", ".cs": "csharp", ".java": "java"}
SKIP = {"node_modules", ".git", "venv", ".venv", "__pycache__", "dist", "build", ".next", "bin", "obj", "target", ".threadzero"}


def scan_tree(root: str | Path, max_files: int = 4000) -> dict:
    root = Path(root)
    out: dict[str, list] = {"endpoints": [], "database": [], "queue": [], "client": [], "middleware": []}
    n = 0
    for p in root.rglob("*"):
        if n >= max_files:
            break
        if p.suffix not in LANG or any(part in SKIP for part in p.parts) or not p.is_file():
            continue
        n += 1
        lang = LANG[p.suffix]
        try:
            lines = p.read_text("utf-8", "replace").splitlines()
        except OSError:
            continue
        rel = p.relative_to(root).as_posix()
        for i, ln in enumerate(lines, 1):
            for pat in PATTERNS["endpoint"][lang]:
                for m in re.finditer(pat, ln):
                    g = [x for x in m.groups() if x is not None]
                    method = g[0].upper() if len(g) > 1 else "ANY"
                    out["endpoints"].append({"file": rel, "line": i, "lang": lang, "method": method, "path": g[-1] if g else ""})
            for kind in ("database", "queue", "client", "middleware"):
                if any(re.search(pat, ln) for pat in PATTERNS[kind]):
                    out[kind].append({"file": rel, "line": i, "lang": lang, "text": ln.strip()[:120]})
    out["filesScanned"] = n
    return out


def map_to_model(scan: dict, A: dict) -> dict:
    """Connect scanned code facts to Architecture nodes (by naming) and suggest missing model entries."""
    apis = [n for n in A["graph"]["nodes"] if n["kind"] in ("api", "service", "application")]
    dbs = [n for n in A["graph"]["nodes"] if n["kind"] == "database"]
    queues = [n for n in A["graph"]["nodes"] if n["kind"] == "queue"]
    mapped, unmapped = [], []
    for e in scan["endpoints"]:
        seg = e["path"].strip("/").split("/")[0].lower()
        hit = next((n for n in apis if n["id"].lower().startswith(seg) or seg in n["id"].lower()), None) if seg else None
        (mapped if hit else unmapped).append({**e, "node": hit["id"] if hit else None})
    suggestions = []
    if unmapped:
        suggestions.append("# Endpoints found in code but not in the model — add an api node per service:\n"
                           + "\n".join(f"# {u['method']} {u['path']}  ({u['file']}:{u['line']})" for u in unmapped[:15])
                           + "\napi ScannedApi in Backend { controls: [authentication, authorization, audit]; }")
    if scan["database"] and not dbs:
        suggestions.append("# Database access detected but the model has no database node:\ndatabase AppDb in DatabaseZone { controls: [authentication, encryption]; }")
    if scan["queue"] and not queues:
        suggestions.append("# Queue usage detected but the model has no queue node:\nqueue EventBus in Backend { controls: [authentication, authorization]; }")
    return {"mapped": mapped, "unmapped": unmapped, "databaseAccess": scan["database"][:50], "queueUse": scan["queue"][:50], "clients": scan["client"][:50],
            "middleware": scan["middleware"][:50], "suggestedDsl": "\n\n".join(suggestions)}


def traceability(A: dict, mapping: dict | None = None) -> dict:
    """Policy -> rule -> generated guard -> source code / deployment target."""
    nodes, edges = [], []
    guards = {g["node"]: g for g in A["guards"]}
    files = {"http_middleware": "guards/http_middleware.py", "grpc_interceptor": "guards/grpc_interceptor.py", "service_wrapper": "guards/grpc_interceptor.py",
             "queue_guard": "guards/queue_guard.py", "storage_guard": "guards/storage_guard.py", "data_access_guard": "guards/storage_guard.py", "egress_guard": "guards/http_middleware.py"}
    sym = A["symbols"]

    def add(i: str, t: str, label: str) -> None:
        if all(n["id"] != i for n in nodes):
            nodes.append({"id": i, "type": t, "label": label})
    for r in A["policy"]["rules"]:
        add(f"policy:{r['policy']}", "policy", r["policy"])
        add(f"rule:{r['id']}", "rule", r["name"])
        edges.append({"from": f"policy:{r['policy']}", "to": f"rule:{r['id']}"})
        resources = set()
        stack = [r["cond"]]
        while stack:
            e = stack.pop()
            for k in ("args",):
                stack += e.get(k, [])
            if "arg" in e:
                stack.append(e["arg"])
            if e.get("op") == "eq" and e.get("slot") == "res":
                resources.add(next((n["name"] for n in sym["nodes"] if n["id"] == e["val"]), None))
        for res in filter(None, resources) or [g for g in guards]:
            g = guards.get(res)
            if not g:
                continue
            add(f"guard:{res}", "guard", f"{g['guard']}({res})")
            edges.append({"from": f"rule:{r['id']}", "to": f"guard:{res}"})
            add(f"artifact:{files.get(g['guard'], 'guards/http_middleware.py')}", "artifact", files.get(g["guard"], "guards/http_middleware.py"))
            edges.append({"from": f"guard:{res}", "to": f"artifact:{files.get(g['guard'], 'guards/http_middleware.py')}"})
            for m in (mapping or {}).get("mapped", []):
                if m["node"] == res:
                    add(f"code:{m['file']}:{m['line']}", "code", f"{m['method']} {m['path']} — {m['file']}:{m['line']}")
                    edges.append({"from": f"guard:{res}", "to": f"code:{m['file']}:{m['line']}"})
    return {"nodes": nodes, "edges": edges}


# ------------------------------------------------------------------ Security CI mode
def ci_evaluate(A: dict, fail_on: str = "high", tests: dict | None = None, baseline: dict | None = None) -> dict:
    thr = SEV_ORDER.get(fail_on.capitalize(), 3)
    findings = A["findings"]
    if baseline:
        old = {f["fingerprint"] for f in baseline["findings"]}
        findings = [f for f in findings if f["fingerprint"] not in old]
    blocking = [f for f in findings if SEV_ORDER[f["severity"]] >= thr]
    errors = [d for d in A["diagnostics"] if d["severity"] == "error"]
    violated = [a["name"] for a in A["assertions"] if a["status"] == "violated"]
    unsat = [c["name"] for c in A["constraints"] if not c["satisfied"]]
    failed_tests = [c for c in (tests or {"cases": []})["cases"] if not c["ok"] and c["section"] not in ("assertions", "constraints")]
    reasons = []
    if errors:
        reasons.append(f"{len(errors)} compiler error(s)")
    if blocking:
        reasons.append(f"{len(blocking)} {'new ' if baseline else ''}finding(s) at or above {fail_on}")
    if violated:
        reasons.append("violated assertions: " + ", ".join(violated))
    if unsat:
        reasons.append("unsatisfied constraints: " + ", ".join(unsat))
    if failed_tests:
        reasons.append(f"{len(failed_tests)} failing generated test(s)")
    return {"passed": not reasons, "reasons": reasons, "blocking": blocking, "errors": errors}


def to_sarif(A: dict) -> dict:
    rules = {}
    results = []
    lvl = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Info": "note"}
    for f in A["findings"]:
        rules.setdefault(f["ruleId"], {"id": f["ruleId"], "name": f["category"], "shortDescription": {"text": f["title"]}, "help": {"text": f["suggestedFix"]}})
        results.append({"ruleId": f["ruleId"], "level": lvl[f["severity"]], "message": {"text": f["message"]},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"] or "model.tz"}, "region": {"startLine": max(1, f["line"])}}}],
                        "partialFingerprints": {"threadzero/v1": f["fingerprint"]}})
    for d in A["diagnostics"]:
        if d["severity"] == "error":
            rules.setdefault(d["code"], {"id": d["code"], "name": "compiler-error", "shortDescription": {"text": "THREADZERO compiler error"}})
            results.append({"ruleId": d["code"], "level": "error", "message": {"text": d["message"]},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": d["file"] or "model.tz"}, "region": {"startLine": max(1, d["line"]), "startColumn": max(1, d["col"])}}}]})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "THREADZERO", "version": A["tool"]["version"], "rules": list(rules.values())}}, "results": results}]}


def to_junit(A: dict, tests: dict | None) -> str:
    from xml.sax.saxutils import escape
    cases = (tests or {"cases": []})["cases"]
    fails = [c for c in cases if not c["ok"]]
    out = [f'<testsuite name="threadzero" tests="{len(cases)}" failures="{len(fails)}">']
    for c in cases:
        out.append(f'<testcase classname="{escape(c["section"])}" name="{escape(c["name"])}">' + (f'<failure message="{escape(json.dumps(c["actual"])[:300])}"/>' if not c["ok"] else "") + "</testcase>")
    return "\n".join(out + ["</testsuite>"])
