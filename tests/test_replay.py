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
