import json

from triage.agent import run as agent_run
from triage.agent.llm_replay import ReplayLLM
from tests.test_agent_contract import GOOD


def test_replay_reads_recorded_answers(make_finding, tmp_path):
    f = make_finding()
    (tmp_path / "agent_answers.json").write_text(json.dumps({f.id: [GOOD]}))
    [t] = agent_run.run([f], None, ReplayLLM(str(tmp_path)), tmp_path)
    assert t.decided_by == "agent"


def test_replay_cache_miss_returns_none(monkeypatch, tmp_path):
    from triage import cache
    monkeypatch.setenv("DEMO_MODE", "replay")
    monkeypatch.setattr(cache, "CACHE_DIR", tmp_path)
    assert cache.fetch_json("https://example.invalid/x") is None


def test_rescore_reapplies_rules_and_keeps_recorded_answers(tmp_path, make_finding, monkeypatch):
    import json
    from triage import runner
    from triage.agent import tools
    monkeypatch.setattr(tools.cache, "fetch_json", lambda url: None)
    from triage.models import Triage
    from tests.test_agent_contract import verdict
    answered, plain = make_finding(id="a", missing=["source"], epss_percentile=0.85), make_finding(id="b", scope="dev", cvss=2.0)
    r = runner.Run(tmp_path)
    r.write("meta.json", {"name": "x", "repo": None, "stages": ["scan", "agent"], "llm": {"provider": "anthropic", "model": "m"}})
    r.write("findings.json", [f.model_dump() for f in (answered, plain)])
    stale = [Triage(finding_id=f.id, risk=99, risk_breakdown={}, effort="low", rule_bucket="NOW", reachability="unknown",
                    final_bucket="NOW", override_reason=None, rationale=["old"], remediation=None) for f in (answered, plain)]
    r.save_triage(stale)
    answer = verdict(proposed_bucket="MONITOR", override_reason="기본 설정에서는 영향이 없습니다.").model_dump_json()
    (tmp_path / "agent_answers.json").write_text(json.dumps({"a": [answer], "b": []}))
    t = {x.finding_id: x for x in runner.rescore(r).triage()}
    assert (t["a"].rule_bucket, t["a"].final_bucket, t["a"].decided_by) == ("NEXT", "MONITOR", "agent")
    assert (t["b"].rule_bucket, t["b"].final_bucket, t["b"].decided_by) == ("MONITOR", "MONITOR", "rule")
    assert r.meta["llm"] == {"provider": "anthropic", "model": "m"}
