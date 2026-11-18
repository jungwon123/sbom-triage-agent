import json

from triage import score
from triage.agent import run as agent_run
from triage.agent.llm import LLMError
from triage.models import AgentVerdict


def verdict(**kw) -> AgentVerdict:
    base = dict(reachability="imported_only", proposed_bucket="NEXT", override_reason=None,
                rationale=["CVSS {cvss}이고 {scope} 의존성입니다."],
                remediation=dict(kind="upgrade_direct", to_version="1.2.0", mitigation=None,
                                 breaking_risk="low", notes=None))
    base.update(kw)
    return AgentVerdict.model_validate(base)


def test_ok(make_finding):
    assert agent_run.contract_violations(verdict(), make_finding(), "NEXT") == []


def test_two_step_jump_rejected(make_finding):
    v = verdict(proposed_bucket="MONITOR", override_reason="미사용")
    assert "bucket moved more than one step" in agent_run.contract_violations(v, make_finding(), "NOW")


def test_override_reason_required(make_finding):
    v = verdict(proposed_bucket="MONITOR")
    assert "override_reason missing" in agent_run.contract_violations(v, make_finding(), "NEXT")


def test_kev_downgrade_rejected(make_finding):
    v = verdict(proposed_bucket="NEXT", override_reason="미사용")
    assert "KEV item downgraded" in agent_run.contract_violations(v, make_finding(kev=True), "NOW")


def test_raw_number_in_rationale_rejected(make_finding):
    v = verdict(rationale=["CVSS 9.8로 매우 위험합니다."])
    assert any("number" in p for p in agent_run.contract_violations(v, make_finding(), "NEXT"))


def test_unknown_placeholder_rejected(make_finding):
    v = verdict(rationale=["{secret} 값"])
    assert any("placeholder" in p for p in agent_run.contract_violations(v, make_finding(), "NEXT"))


def test_placeholders_filled_from_finding(make_finding):
    f = make_finding(cvss=7.5)
    t = agent_run.merge(f, score.score(f), verdict(), "agent")
    assert t.rationale == ["CVSS 7.5이고 운영 의존성입니다."]


def test_needs_review_blocks_downgrade(make_finding, runtime_site):
    f = make_finding(cvss=9.8, epss_percentile=0.95, import_sites=[runtime_site])
    r = score.score(f)
    assert r.bucket == "NOW"
    t = agent_run.merge(f, r, verdict(proposed_bucket="NEXT", override_reason="취약 함수 미사용"), "agent")
    assert t.final_bucket == "NOW" and t.needs_review and t.override_reason is None


def test_triage_scores_come_from_rule(make_finding):
    f = make_finding()
    r = score.score(f)
    t = agent_run.merge(f, r, verdict(), "agent")
    assert t.risk == round(r.risk) and t.rule_bucket == r.bucket


class FakeSession:
    def __init__(self, answers):
        self.answers, self.followups = list(answers), []

    def run(self, call_tool):
        a = self.answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a

    def followup(self, message, call_tool):
        self.followups.append(message)
        return self.run(call_tool)


class FakeLLM:
    name = "fake"

    def __init__(self, answers):
        self.session = FakeSession(answers)

    def start(self, *a, **k):
        return self.session


GOOD = verdict().model_dump_json()
BAD = json.dumps({"reachability": "maybe"})


def test_retry_once_then_accept(make_finding, tmp_path):
    f = make_finding()
    llm = FakeLLM([BAD, GOOD])
    [t] = agent_run.run([f], None, llm, tmp_path)
    assert t.decided_by == "agent" and len(llm.session.followups) == 1


def test_two_failures_fall_back_to_rule(make_finding, tmp_path):
    f = make_finding()
    [t] = agent_run.run([f], None, FakeLLM([BAD, BAD]), tmp_path)
    assert t.decided_by == "agent_fallback" and t.final_bucket == t.rule_bucket
    assert t.reachability == score.score(f).reachability


def test_llm_error_falls_back(make_finding, tmp_path):
    [t] = agent_run.run([make_finding()], None, FakeLLM([LLMError("down")]), tmp_path)
    assert t.decided_by == "agent_fallback"


def test_monitor_items_skip_the_llm(make_finding, tmp_path):
    f = make_finding(cvss=2.0, epss_percentile=0.01, scope="dev")
    llm = FakeLLM([])
    [t] = agent_run.run([f], None, llm, tmp_path)
    assert t.rule_bucket == "MONITOR" and t.decided_by == "rule"


def test_high_epss_now_is_not_downgraded_without_runtime_import(make_finding):
    f = make_finding(cvss=9.8, epss_percentile=0.95, direct=False)   # transitive: no import sites
    r = score.score(f)
    assert r.bucket == "NOW"
    t = agent_run.merge(f, r, verdict(proposed_bucket="NEXT", override_reason="import 없음"), "agent")
    assert t.final_bucket == "NOW" and t.needs_review


def test_override_reason_placeholders_filled(make_finding):
    f = make_finding(cvss=5.0, epss_percentile=0.89, package="lodash")
    r = score.score(f)
    down = {"NOW": "NEXT", "NEXT": "MONITOR"}[r.bucket]
    t = agent_run.merge(f, r, verdict(proposed_bucket=down, override_reason="{package}를 쓰지 않습니다"), "agent")
    assert t.override_reason == "lodash를 쓰지 않습니다"
