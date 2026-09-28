"""AI Security Architecture Assistant. The assistant can only *propose*; every proposal is produced by
a compiler tool, verified by the Haskell core, and linked to real nodes/edges/rules. It has no tool that
changes production. An LLM is optional (THREADZERO_LLM_URL, Ollama-compatible) and only phrases evidence."""
from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Any

from . import core
from .explain import explain_decision
from .impact import dependency_impact, diff_analyses
from .runtime import PolicyEngine


class Tools:
    def __init__(self, A: dict, bundle: core.Bundle | None = None, engine: PolicyEngine | None = None):
        self.A, self.bundle, self.engine = A, bundle, engine

    # 1
    def inspect_graph(self, node: str | None = None) -> dict:
        g = self.A["graph"]
        if not node:
            return {"nodes": len(g["nodes"]), "edges": len(g["edges"]), "zones": [z["id"] for z in g["zones"]], "evidence": [{"type": "graph", "ref": "graph"}]}
        n = next((x for x in g["nodes"] if x["id"] == node), None)
        if not n:
            return {"error": f"unknown node {node}"}
        return {"node": n, "inbound": [e for e in g["edges"] if e["to"] == node], "outbound": [e for e in g["edges"] if e["from"] == node],
                "evidence": [{"type": "node", "ref": node}] + [{"type": "edge", "ref": e["id"]} for e in g["edges"] if node in (e["from"], e["to"])]}

    # 2
    def trace_data_flow(self, data: str) -> dict:
        lin = next((x for x in self.A["lineage"] if x["data"] == data), None)
        if not lin:
            return {"error": f"unknown data type {data}"}
        return {**lin, "evidence": [{"type": "data", "ref": data}] + [{"type": "edge", "ref": f["flow"]} for f in lin["flows"]]}

    # 3
    def find_boundary_violations(self) -> dict:
        cats = {"TrustBoundaryViolation", "SensitiveDataEscape", "SecurityControlGap", "MissingAuthentication", "MissingAuthorization", "UncontrolledThirdPartyFlow"}
        fs = [f for f in self.A["findings"] if f["category"] in cats]
        return {"count": len(fs), "findings": fs, "evidence": [{"type": "finding", "ref": f["id"]} for f in fs]}

    # 4
    def explain_policy(self, name: str) -> dict:
        rs = [r for r in self.A["policy"]["rules"] if name in (r["id"], r["policy"], r["name"])]
        if not rs:
            return {"error": f"unknown policy or rule {name}"}
        return {"rules": rs, "conflicts": [c for c in self.A["policy"]["conflicts"] if name in (c["allow"], c["deny"]) or any(name == r["policy"] for r in rs)],
                "evidence": [{"type": "rule", "ref": r["id"]} for r in rs]}

    # 5
    def propose_refactoring(self, finding_id: str) -> dict:
        if not self.bundle:
            return {"error": "no source bundle available"}
        res = core.refactor(self.bundle, finding_id)
        cands = [c for c in res.get("candidates", []) if c["valid"]]
        for c in cands:
            c["verified"] = all(p["holds"] for p in c["postconditions"] if "removed" in p["text"] or "semantic" in p["text"] or "connected" in p["text"])
        return {"finding": res.get("finding"), "proposals": [{k: v for k, v in c.items() if k != "dsl"} for c in cands],
                "notice": "Proposals only. Nothing is applied; review the DSL diff and re-run verification before merging.",
                "evidence": [{"type": "finding", "ref": finding_id}]}

    # 6
    def compare_architectures(self, other: dict) -> dict:
        d = diff_analyses(self.A, other)
        return {"gate": d["gate"], "findings": {k: len(v) for k, v in d["findings"].items()}, "graph": d["graph"], "coverage": d["coverage"]}

    # 7
    def generate_tests(self, rule: str | None = None) -> dict:
        ts = [t for t in self.A["policy"]["tests"] if rule is None or t["rule"] == rule or t["rule"].endswith("." + rule)]
        return {"count": len(ts), "tests": ts[:50], "evidence": [{"type": "rule", "ref": t["rule"]} for t in ts[:10]]}

    # 8
    def explain_runtime_decision(self, request: dict) -> dict:
        if not self.engine:
            return {"error": "no compiled policy engine"}
        return explain_decision(self.engine, request)


INTENTS = [
    ("propose", r"refactor|fix|remediat|improve|propose|suggest|بازسازی|رفع|پیشنهاد|修复|重构|建议"),
    ("trace", r"trace|journey|lineage|flow of|where does|مسیر|داده|追踪|数据流"),
    ("boundary", r"boundar|violation|escape|cross|مرز|نقض|边界|违规"),
    ("policy", r"polic|rule|why|deny|allow|سیاست|قانون|策略|规则"),
    ("tests", r"test|تست|测试"),
    ("inspect", r"node|graph|inspect|گراف|图"),
]


class Assistant:
    def __init__(self, tools: Tools, llm: bool | None = None):
        self.t = tools
        self.llm_url = os.environ.get("THREADZERO_LLM_URL") if llm is None else (os.environ.get("THREADZERO_LLM_URL") if llm else None)

    def _known(self) -> set[str]:
        A = self.t.A
        return {n["id"] for n in A["graph"]["nodes"]} | {e["id"] for e in A["graph"]["edges"]} | {r["id"] for r in A["policy"]["rules"]} | {f["id"] for f in A["findings"]} | {d["name"] for d in A["symbols"]["data"]}

    def ask(self, question: str, request: dict | None = None) -> dict:
        A, q = self.t.A, question
        words = set(re.findall(r"[A-Za-z_][A-Za-z0-9_\.\-]*", q))
        known = self._known()
        refs = [w for w in words if w in known]
        intent = next((k for k, pat in INTENTS if re.search(pat, q, re.I)), "boundary")
        fid = next((w for w in words if re.fullmatch(r"F-\d{3}", w)), None)
        data = next((w for w in refs if w in {d["name"] for d in A["symbols"]["data"]}), None)
        node = next((w for w in refs if w in {n["id"] for n in A["graph"]["nodes"]}), None)
        rule = next((w for w in refs if w in {r["id"] for r in A["policy"]["rules"]}), None) or next((w for w in words if w in {r["policy"] for r in A["policy"]["rules"]}), None)
        calls: list[tuple[str, dict, dict]] = []
        if request and self.t.engine:
            calls.append(("explain_runtime_decision", {"request": request}, self.t.explain_runtime_decision(request)))
        elif intent == "propose":
            fid = fid or (A["findings"][0]["id"] if A["findings"] else None)
            if fid:
                calls.append(("propose_refactoring", {"finding_id": fid}, self.t.propose_refactoring(fid)))
        elif intent == "trace" and data:
            calls.append(("trace_data_flow", {"data": data}, self.t.trace_data_flow(data)))
        elif intent == "policy" and rule:
            calls.append(("explain_policy", {"name": rule}, self.t.explain_policy(rule)))
        elif intent == "tests":
            calls.append(("generate_tests", {"rule": rule}, self.t.generate_tests(rule)))
        elif intent == "inspect" or node:
            calls.append(("inspect_graph", {"node": node}, self.t.inspect_graph(node)))
        else:
            calls.append(("find_boundary_violations", {}, self.t.find_boundary_violations()))
        evidence = [e for _, _, r in calls for e in r.get("evidence", [])]
        answer = self._summarize(question, calls)
        return {"intent": intent, "tools": [{"tool": n, "args": a} for n, a, _ in calls], "results": [r for _, _, r in calls], "answer": answer,
                "evidence": [e for e in evidence if e.get("ref") in known or e["type"] in ("graph",)], "productionChanges": 0}

    def _summarize(self, question: str, calls: list) -> str:
        name, _, res = calls[0]
        if "error" in res:
            return res["error"]
        if name == "propose_refactoring":
            ps = res.get("proposals", [])
            f = res.get("finding") or {}
            return f"For finding {f.get('id')} ({f.get('category')}) the compiler verified {len(ps)} candidate architecture(s): " + "; ".join(
                f"{p['id']} {p['title']} (removes {len(p['securityImpact']['removed'])} finding(s), adds {len(p['securityImpact']['added'])}, equivalent={p['functionalImpact']['equivalent']})" for p in ps)
        if name == "find_boundary_violations":
            return f"{res['count']} boundary-related finding(s): " + "; ".join(f"{f['id']} {f['category']} ({f['severity']}): {f['message']}" for f in res["findings"][:6])
        if name == "trace_data_flow":
            return f"{res['data']} ({res['class']}) originates at {', '.join(res['origins']) or 'n/a'} and flows through {len(res['flows'])} flow(s); stored in {', '.join(res['stores']) or 'no store'}."
        if name == "explain_policy":
            return "; ".join(f"{r['id']}: {r['effect']} when {r['condText']}" for r in res["rules"][:5])
        if name == "generate_tests":
            return f"{res['count']} generated tests available (positive, negative, boundary, context)."
        if name == "explain_runtime_decision":
            return " → ".join(res["steps"])
        if name == "inspect_graph":
            if "node" in res:
                return f"{res['node']['id']} is a {res['node']['kind']} in {res['node']['zone']} with {len(res['inbound'])} inbound and {len(res['outbound'])} outbound flow(s)."
            return f"{res['nodes']} nodes, {res['edges']} flows, zones: {', '.join(res['zones'])}."
        return ""

    def llm_rephrase(self, question: str, result: dict) -> str | None:
        """Optional: ask a local LLM to phrase the verified evidence. Output is discarded if it cites unknown entities."""
        if not self.llm_url:
            return None
        body = {"model": os.environ.get("THREADZERO_LLM_MODEL", "llama3"), "stream": False,
                "messages": [{"role": "system", "content": "You explain THREADZERO compiler results. Use ONLY the provided JSON evidence. Never invent nodes, flows or rules."},
                             {"role": "user", "content": json.dumps({"question": question, "evidence": result["results"]})[:12000]}]}
        try:
            req = urllib.request.Request(self.llm_url.rstrip("/") + "/api/chat", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=60) as r:
                text = json.loads(r.read())["message"]["content"]
        except Exception:
            return None
        known = self._known()
        cited = set(re.findall(r"\b[A-Z][A-Za-z0-9_]{3,}\b", text))
        return text if all(c in known or c in {"The", "This", "These", "Flow", "Data", "Policy"} or c.lower() in text.lower()[:0] for c in cited if c in known or c not in _COMMON) else None


_COMMON = {"The", "This", "These", "That", "Flow", "Data", "Policy", "Rule", "Node", "Zone", "Restricted", "Confidential", "Internal", "Public", "Secret", "Personal", "Financial", "High", "Medium", "Low", "Critical", "Info"}
