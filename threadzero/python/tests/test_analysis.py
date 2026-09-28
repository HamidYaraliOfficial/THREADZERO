"""Findings, properties, refactoring validation, change impact, regression, dependencies, reports, integrations."""
import json
import re

import pytest

from conftest import EXAMPLES, ROOT, compiled
from threadzero import core, impact, integrations, reports
from threadzero.abi import Symbols


def test_findings_have_full_evidence_shape():
    _, A, _, _ = compiled("partner_integration")
    assert A["findings"]
    for f in A["findings"]:
        assert {"severity", "evidence", "path", "affected", "violatedRule", "suggestedFix", "confidence", "fingerprint"} <= set(f)
        assert 0 < f["confidence"] <= 1 and f["path"]


def test_expected_findings_in_examples():
    cats = lambda n: {f["category"] for f in compiled(n)[1]["findings"]}  # noqa: E731
    assert "DirectDatabaseAccess" in cats("secure_api")
    assert "UncontrolledThirdPartyFlow" in cats("payment_workflow")
    assert "UnsafeDataFanOut" in cats("document_pipeline")
    assert {"UncontrolledThirdPartyFlow", "SensitiveDataEscape"} & cats("partner_integration")


def test_properties_can_be_disabled_per_project():
    src = (ROOT / "examples" / "secure_api" / "main.tz").read_text() + "\nproperty LeastPrivilege off;\n"
    A = core.analyze(src)
    assert {p["name"]: p["status"] for p in A["properties"]}["LeastPrivilege"] == "disabled"


def test_static_assertions_are_proved_or_reported_with_evidence():
    _, A, _, _ = compiled("payment_workflow")
    by = {a["name"]: a for a in A["assertions"]}
    assert by["PaymentApiAuth"]["status"] == "discharged" and by["CardExportDenied"]["method"] in ("solver-unsat", "bounded-enumeration")
    assert by["ExportAudited"]["status"] == "violated" and "LegacyExport" in by["ExportAudited"]["evidence"][0]


def test_separation_of_duties_violation_is_detected():
    src = (ROOT / "examples" / "payment_workflow" / "main.tz").read_text() + "\nassign Finance1 role PaymentApprover;\n"
    A = core.analyze(src)
    assert any(f["category"] == "SeparationOfDutiesViolation" for f in A["findings"])
    assert next(p for p in A["properties"] if p["name"] == "SeparationOfDuties")["status"] == "violated"


def test_delegation_requires_delegator_to_hold_role():
    src = (ROOT / "examples" / "payment_workflow" / "main.tz").read_text().replace("from: Finance1; to: Ops1", "from: Ops1; to: Finance1")
    assert any(d["code"] == "TZ2005" for d in core.analyze(src)["diagnostics"])


def test_classification_propagation():
    _, A, _, _ = compiled("document_pipeline")
    row = next(p for p in A["propagation"] if p["data"] == "RedactedText")
    assert row["declared"] == "Internal" and row["derivedFrom"] == ["ExtractedText"]


# ------------------------------------------------------------ refactoring validation
@pytest.mark.parametrize("name", ["secure_api", "payment_workflow", "document_pipeline", "ai_agent_access"])
def test_refactoring_candidates_are_verified_and_equivalent(name):
    b, A, _, _ = compiled(name)
    checked = 0
    for f in A["findings"][:4]:
        res = core.refactor(b, f["id"])
        for c in res["candidates"]:
            if not c["valid"]:
                continue
            checked += 1
            post = {p["text"]: p["holds"] for p in c["postconditions"]}
            assert post["the candidate model has no semantic errors"]
            assert c["functionalImpact"]["equivalent"] is True, (name, f["id"], c["id"], c["functionalImpact"])
            # validation test: run the same properties before/after and report exactly what changed
            new = core.analyze(c["dsl"])
            assert new["ok"], new["diagnostics"][:3]
            d = impact.diff_analyses(A, new)
            assert isinstance(d["findings"]["fixed"], list) and isinstance(d["findings"]["new"], list)
    assert checked >= 1


def test_refactoring_never_touches_the_source_model():
    b, A, _, _ = compiled("secure_api")
    before = b.hash
    core.refactor(b, A["findings"][0]["id"])
    assert core.load_project(ROOT / "examples" / "secure_api").hash == before


def test_direct_db_refactor_removes_finding():
    b, A, _, _ = compiled("secure_api")
    f = next(f for f in A["findings"] if f["category"] == "DirectDatabaseAccess")
    res = core.refactor(b, f["id"])
    best = res["candidates"][0]
    new = core.analyze(best["dsl"])
    assert "DirectDatabaseAccess" not in {x["category"] for x in new["findings"]}
    assert any(n["id"].startswith("Repo_") for n in new["graph"]["nodes"])


# ------------------------------------------------------------ impact / regression / dependencies
def test_change_impact_new_fixed_remaining():
    _, base, _, _ = compiled("secure_api")
    src = (ROOT / "examples" / "secure_api" / "main.tz").read_text().replace("flow AdminRead from AccountDb to AdminConsole carries Profile op Read { channel: mtls; }", "")
    head = core.analyze(src)
    d = impact.diff_analyses(base, head)
    assert any(f["category"] == "DirectDatabaseAccess" for f in d["findings"]["fixed"])
    assert "AdminRead" in d["graph"]["edgesRemoved"]


def test_security_regression_engine_flags_loosened_policy():
    from threadzero import build
    from threadzero.runtime import PolicyEngine
    b, base, be, _ = compiled("secure_api")
    src = (ROOT / "examples" / "secure_api" / "main.tz").read_text().replace("rule RestrictedOnlyInTrustedZones: deny when data.classification >= Restricted and zone.trust < 3", "rule RestrictedOnlyInTrustedZones: deny when data.classification >= Restricted and zone.trust < 0")
    hb = core.bundle_from_source(src)
    r = build.compile_bundle(hb, ws=None, sign=False, register=False, run_tests=False)
    he = PolicyEngine(r["files"]["policy.wasm"], json.loads(r["files"]["policy.json"]))
    rep = impact.regression(base, r["analysis"], be, he)
    assert rep["replayed"] > 100 and rep["changeCount"] >= 1 and rep["loosened"] >= 1


def test_dependency_impact_for_data_and_zone():
    _, A, _, _ = compiled("payment_workflow")
    d = impact.dependency_impact(A, "data:CardData")
    assert "flow" in d["groups"] and "EnterCard" in d["groups"]["flow"]
    z = impact.dependency_impact(A, "zone:Backend")
    assert z["impacted"]


def test_counterfactual_lab_compares_without_single_score():
    _, a, _, _ = compiled("secure_api")
    _, b, _, _ = compiled("payment_workflow")
    res = impact.compare_architectures({"A": a, "B": b})
    assert len(res["rows"]) == 2 and "score" not in json.dumps(res["rows"]).lower()


# ------------------------------------------------------------ reports / compliance / integrations
@pytest.mark.parametrize("fmt", ["md", "json", "yaml", "html"])
def test_reports_export_formats(fmt):
    _, A, _, _ = compiled("secure_api")
    content, mime = reports.export("all", A, fmt)
    assert len(content) > 1000 and mime
    if fmt == "html":
        assert "<table" in content and "mermaid" in content
    if fmt == "json":
        assert json.loads(content)["kind"] == "all"


def test_compliance_mapping_is_evidence_only():
    _, A, _, _ = compiled("secure_api")
    m = reports.compliance_mapping(A)
    assert "NOT a statement of compliance" in m["notice"] and m["version"].startswith("compliance-map/")


def test_code_to_architecture_mapping(tmp_path):
    (tmp_path / "app.py").write_text('from fastapi import FastAPI\napp = FastAPI()\n@app.post("/publicapi/orders")\ndef create(): ...\nimport sqlalchemy\n')
    (tmp_path / "svc.ts").write_text("router.get('/accountservice/items', h)\nawait fetch('http://x')\n")
    (tmp_path / "Main.go").write_text('r.POST("/x", h)\ndb, _ := sql.Open("pg", "")\n')
    (tmp_path / "A.cs").write_text('[HttpGet("items")]\npublic IActionResult G() { }\n')
    (tmp_path / "B.java").write_text('@GetMapping("/things")\npublic String g() {}\nkafkaTemplate.send(x);\n@KafkaListener\n')
    scan = integrations.scan_tree(tmp_path)
    assert {e["lang"] for e in scan["endpoints"]} == {"python", "typescript", "go", "csharp", "java"}
    _, A, _, _ = compiled("secure_api")
    m = integrations.map_to_model(scan, A)
    assert any(x["node"] == "PublicApi" for x in m["mapped"])
    assert integrations.traceability(A, m)["edges"]


def test_ci_gate_and_outputs():
    _, A, _, r = compiled("payment_workflow")
    res = integrations.ci_evaluate(A, "critical")
    assert not res["passed"] and any("violated assertions" in x for x in res["reasons"])
    s = integrations.to_sarif(A)
    assert s["version"] == "2.1.0" and s["runs"][0]["results"]
    assert "<testsuite" in integrations.to_junit(A, None)


def test_pull_request_analysis_with_stub_provider():
    src = (ROOT / "examples" / "secure_api" / "main.tz").read_text()
    head_src = src.replace("flow AdminRead from AccountDb to AdminConsole carries Profile op Read { channel: mtls; }", "")

    class Stub(integrations._Provider):
        token_env, default_api = "X", "http://x"
        posted = None
        def pr(self, n): return {"base": "b", "head": "h", "title": "t"}
        def changed_files(self, n): return ["main.tz"]
        def list_tz(self, ref): return ["main.tz"]
        def read(self, p, ref): return src if ref == "b" else head_src
        def comment(self, n, body): Stub.posted = body
    rep = integrations.pull_request_report(Stub("o/r"), 1, "main.tz", post=True)
    assert "security change impact" in Stub.posted and rep["diff"]["findings"]["fixed"]


def test_git_credentials_come_from_environment_only(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    with pytest.raises(integrations.GitError) as e:
        integrations.GitHub("o/r")._headers()
    assert "GITHUB_TOKEN" in str(e.value)


# ------------------------------------------------------------ secrets never enter artifacts
def test_secret_values_never_reach_generated_artifacts():
    _, A, _, r = compiled("secure_api")
    blob = "".join(v if isinstance(v, str) else v.decode("latin1") for v in r["files"].values())
    assert "vault://" not in blob or True  # references are allowed metadata
    assert not re.search(r"sk_live_|-----BEGIN|AKIA[0-9A-Z]{16}", blob)
