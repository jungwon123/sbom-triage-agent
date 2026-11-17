import json

from triage import notify, score
from triage.agent import run as agent_run

SECRET = "INTERNAL_SECRET_TOKEN_abc"


def triage_of(f):
    return agent_run.merge(f, score.score(f), None, "rule")


def test_message_lists_now_items_without_code(make_finding, runtime_site):
    site = runtime_site.model_copy(update={"snippet": f"const k = '{SECRET}'", "file": "src/secret/path.ts"})
    now = make_finding(id="A@lib@1.0.0", cvss=9.8, kev=True, import_sites=[site])
    low = make_finding(id="B@other@1.0.0", package="other", cvss=2.0, epss_percentile=0.01, scope="dev")
    payload = notify.build_message("shop", [now, low], [triage_of(now), triage_of(low)], "http://x/?run=1")
    text = json.dumps(payload, ensure_ascii=False)
    assert "이번 주에 고칠 것은 1건" in payload["text"]
    assert "*lib* 1.0.0" in text and "KEV 등재" in text and "other" not in text
    assert SECRET not in text and "src/secret/path.ts" not in text
    assert "http://x/?run=1" in text


def test_not_sent_without_url_or_in_replay(monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    assert notify.send({"text": "x"}) == (False, "SLACK_WEBHOOK_URL is not set")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.example.invalid/x")
    monkeypatch.setenv("DEMO_MODE", "replay")
    assert notify.send({"text": "x"})[0] is False
    monkeypatch.setenv("DEMO_MODE", "live")
    assert notify.send({"text": "x"}, dry_run=True) == (False, "dry run")
