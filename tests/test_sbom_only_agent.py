"""SBOM-only input: no source code, so the model judges from the advisory text with no tools."""
import json

import pytest

from triage.agent import prompts, run as agent_run, tools
from tests.test_agent_contract import verdict
from tests.test_two_stage import CODE, Recorder

ADVISORY = {"id": "CVE-2024-0001", "summary": "DoS in lib", "details": "Only when the strict option is off.",
            "affected": []}


@pytest.fixture(autouse=True)
def advisory(monkeypatch):
    monkeypatch.setattr(tools.cache, "fetch_json", lambda url: ADVISORY)


def sbom_finding(make_finding, **kw):
    return make_finding(missing=["source"], **kw)      # scores NEXT by rule


def test_uses_advisory_prompt_without_tools(make_finding, tmp_path):
    llm = Recorder("anthropic", [verdict().model_dump_json()], looks=False)
    [t] = agent_run.run([sbom_finding(make_finding)], None, llm, tmp_path)
    assert t.decided_by == "agent" and llm.tools == [[]]
    assert prompts.SBOM_SYSTEM in llm.seen[0] and "Only when the strict option is off." in llm.seen[0]


def test_can_step_down_from_advisory_but_reachability_stays_unknown(make_finding, tmp_path):
    answer = verdict(proposed_bucket="MONITOR", override_reason="기본 설정에서는 영향이 없습니다.",
                     reachability="unused").model_dump_json()
    [t] = agent_run.run([sbom_finding(make_finding)], None, Recorder("anthropic", [answer], looks=False), tmp_path)
    assert (t.rule_bucket, t.final_bucket) == ("NEXT", "MONITOR")
    assert t.reachability == "unknown" and t.code_read_by == "rule"


def test_two_step_jump_still_rejected(make_finding, tmp_path):
    f = sbom_finding(make_finding, cvss=10.0, epss_percentile=1.0)     # NOW by rule
    answer = verdict(proposed_bucket="MONITOR", override_reason="영향 없음").model_dump_json()
    [t] = agent_run.run([f], None, Recorder("anthropic", [answer, answer], looks=False), tmp_path)
    assert t.decided_by == "agent_fallback" and t.final_bucket == "NOW"


def test_code_reader_is_not_called_without_source(make_finding, tmp_path):
    reader = Recorder("local", [CODE])
    writer = Recorder("anthropic", [verdict().model_dump_json()], looks=False)
    [t] = agent_run.run([sbom_finding(make_finding)], None, writer, tmp_path, code_llm=reader)
    assert reader.seen == [] and t.decided_by == "agent"


def test_missing_advisory_does_not_stop_the_run(make_finding, tmp_path, monkeypatch):
    monkeypatch.setattr(tools.cache, "fetch_json", lambda url: None)
    llm = Recorder("anthropic", [verdict().model_dump_json()], looks=False)
    [t] = agent_run.run([sbom_finding(make_finding)], None, llm, tmp_path)
    assert "advisory not available" in llm.seen[0] and t.decided_by == "agent"


def test_pypi_package_names_pass_the_remediation_check(make_finding, tmp_path):
    f = sbom_finding(make_finding, ecosystem="PyPI", package="python-jose", id="CVE-2024-0001@python-jose@1.0.0")
    [t] = agent_run.run([f], None, Recorder("anthropic", [verdict().model_dump_json()], looks=False), tmp_path)
    assert t.decided_by == "agent"
    bad = sbom_finding(make_finding, ecosystem="PyPI", package="lib; rm -rf /")
    assert "package name has unexpected characters" in agent_run.contract_violations(verdict(), bad, "NEXT")


CONTEXT = {"service_criticality": "medium", "internet_facing": False, "note": "사내망 전용 백오피스"}


def test_service_context_reaches_every_prompt(make_finding, runtime_site, tmp_path):
    sbom_llm = Recorder("anthropic", [verdict().model_dump_json()], looks=False)
    agent_run.run([sbom_finding(make_finding)], None, sbom_llm, tmp_path, context=CONTEXT)
    repo_llm = Recorder("anthropic", [verdict(proposed_bucket="NOW").model_dump_json()])
    agent_run.run([make_finding(import_sites=[runtime_site])], tmp_path, repo_llm, tmp_path, context=CONTEXT)
    for llm in (sbom_llm, repo_llm):
        assert "사내망 전용 백오피스" in llm.seen[0] and prompts.SERVICE_CONTEXT in llm.seen[0]


def test_unstated_context_is_sent_as_null(make_finding, tmp_path):
    llm = Recorder("anthropic", [verdict().model_dump_json()], looks=False)
    agent_run.run([sbom_finding(make_finding)], None, llm, tmp_path,
                  context={"service_criticality": None, "internet_facing": None, "note": None})
    assert '"service_context": null' in llm.seen[0]


def test_context_never_changes_the_rule_score(make_finding, tmp_path):
    f = sbom_finding(make_finding)
    answer = verdict().model_dump_json()
    [a] = agent_run.run([f], None, Recorder("anthropic", [answer], looks=False), tmp_path)
    [b] = agent_run.run([f], None, Recorder("anthropic", [answer], looks=False), tmp_path, context=CONTEXT)
    assert (a.risk, a.risk_breakdown, a.rule_bucket) == (b.risk, b.risk_breakdown, b.rule_bucket)
