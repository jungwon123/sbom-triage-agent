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


def job(kind, status="done", result=None, error=None):
    return {"id": "j1", "run_id": "20261124-000000-shop", "kind": kind, "status": status, "result": result, "error": error,
            "payload": {"requested_by": "kim@example.com"}}


def test_job_message_says_what_finished_and_how_it_went():
    summary = {"final": {"NOW": 3, "NEXT": 2, "MONITOR": 9}, "verified": 3}
    v = notify.build_job_message(job("verify", result={"summary": summary, "skipped": None}), "shop", "http://x/?run=1")
    assert "샌드박스 검증" in v["text"] and "완료" in v["text"] and "shop" in v["text"]
    body = json.dumps(v, ensure_ascii=False)
    assert "검증을 통과한 조치안 3건" in body and "http://x/?run=1" in body
    a = notify.build_job_message(job("agent", result={"summary": summary, "skipped": None, "judged": 5, "fallbacks": 1}), "shop")
    assert "AI 판단" in a["text"] and "5건" in json.dumps(a, ensure_ascii=False) and "규칙 결과로 남은 항목 1건" in json.dumps(a, ensure_ascii=False)
    e = notify.build_job_message(job("export_together", result={"approved": 2, "combined": {"verdict": "failed", "tests_run": 27, "targets": ["a@1", "b@2"]},
                                                                "combined_skipped": None}), "shop")
    assert "검증 실패" in json.dumps(e, ensure_ascii=False) and "테스트 27개" in json.dumps(e, ensure_ascii=False)


def test_job_message_for_a_skipped_job_gives_the_reason():
    m = notify.build_job_message(job("verify", result={"summary": {}, "skipped": "docker unavailable"}), "shop")
    assert "실행하지 않음" in m["text"] and "Docker" in json.dumps(m, ensure_ascii=False)


def test_job_message_never_carries_the_error_text_or_who_asked():
    """An exception message can hold file paths or a log tail, and the requester is a person's address."""
    m = notify.build_job_message(job("verify", status="failed", error=f"boom at /repos/shop/src/pay.ts {SECRET}"), "shop")
    text = json.dumps(m, ensure_ascii=False)
    assert "실패" in m["text"] and SECRET not in text and "pay.ts" not in text and "kim@example.com" not in text
    assert "작업 기록" in text
    i = notify.build_job_message(job("agent", status="interrupted", error="cut off"), "shop")
    assert "중단" in i["text"]
