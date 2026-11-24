"""Slack (or any Slack-compatible incoming webhook, e.g. an in-house Mattermost) notification.

The message is a summary for people to act on. It carries package names, vulnerability ids, buckets
and verification verdicts only: no source code, no file names, no rationale text from the LLM.
SLACK_WEBHOOK_URL comes from .env. Nothing is sent in replay mode or with dry_run.
"""
from __future__ import annotations

import logging
import os

import httpx

from . import cache
from .models import Finding, Triage

log = logging.getLogger(__name__)
MAX_ITEMS = 10
VERDICT = {"verified": "검증 통과", "failed": "검증 실패", "inconclusive": "판단 불가"}


def _line(f: Finding, t: Triage) -> str:
    parts = [f"*{f.package}* {f.version}", f.vuln_id]
    if f.cvss is not None:
        parts.append(f"CVSS {f.cvss:.1f}")
    if f.kev:
        parts.append("KEV 등재")
    r = t.remediation
    if r and r.to_version:
        parts.append(f"→ {r.to_version}")
    if t.verification:
        v = t.verification
        parts.append(f"{VERDICT[v.verdict]} (테스트 {v.tests_run}개)")
    if t.needs_review:
        parts.append("담당자 확인 필요")
    return "• " + ", ".join(parts)


def build_message(name: str, findings: list[Finding], triage: list[Triage], link: str | None = None) -> dict:
    """Pure function: run result -> Slack payload (text + blocks)."""
    by_id = {f.id: f for f in findings}
    count = {b: sum(t.final_bucket == b for t in triage) for b in ("NOW", "NEXT", "MONITOR")}
    now = sorted((t for t in triage if t.final_bucket == "NOW"), key=lambda t: -t.risk)
    review = [t for t in triage if t.needs_review and t.final_bucket != "NOW"]
    head = f"[SBOM Triage] {name}: 취약점 {len(triage)}건 가운데 이번 주에 고칠 것은 {count['NOW']}건입니다."
    blocks: list[dict] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*{head}*"}},
        {"type": "context", "elements": [{"type": "mrkdwn",
                                          "text": f"NOW {count['NOW']}  |  NEXT {count['NEXT']}  |  MONITOR {count['MONITOR']}"}]},
    ]
    if now:
        lines = [_line(by_id[t.finding_id], t) for t in now[:MAX_ITEMS]]
        if len(now) > MAX_ITEMS:
            lines.append(f"외 {len(now) - MAX_ITEMS}건")
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "*이번 주에 조치*\n" + "\n".join(lines)}})
    if review:
        lines = [_line(by_id[t.finding_id], t) for t in review[:MAX_ITEMS]]
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "*담당자 확인 필요*\n" + "\n".join(lines)}})
    if link:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"<{link}|대시보드에서 근거와 조치안 보기>"}})
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn",
                                                    "text": "원본 코드는 담당자가 승인한 뒤에만 수정합니다."}]})
    return {"text": head, "blocks": blocks}


CHANGE = {"added": "새로 발견", "raised": "등급 상승", "kev_added": "KEV 등재", "fix_released": "수정 버전 공개",
          "lowered": "등급 하락", "removed": "해소"}


def build_change_message(name: str, changes: list, total: int, link: str | None = None) -> dict:
    """Pure function: what a scheduled re-check found -> Slack payload. `changes` are models.Change rows
    worth an alert; `total` is every change of that check."""
    head = f"[SBOM Triage] {name}: 다시 확인한 결과 바로 볼 변경이 {len(changes)}건 있습니다."
    lines = []
    for c in changes[:MAX_ITEMS]:
        parts = [f"*{c.package}* {c.version}", c.vuln_id, CHANGE[c.kind]]
        if c.before and c.after and c.before != c.after:
            parts.append(f"{c.before} → {c.after}")
        elif c.after:
            parts.append(c.after)
        lines.append("• " + ", ".join(parts))
    if len(changes) > MAX_ITEMS:
        lines.append(f"외 {len(changes) - MAX_ITEMS}건")
    blocks: list[dict] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*{head}*"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"이번 확인의 전체 변경 {total}건. 새 항목은 규칙 결과이며 AI 판단은 아직 하지 않았습니다."}]},
    ]
    if link:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"<{link}|대시보드에서 변경 내용 보기>"}})
    return {"text": head, "blocks": blocks}


JOB_KIND = {"verify": "샌드박스 검증", "agent": "AI 판단", "export_together": "승인분 함께 검증",
            "service_check": "서비스 다시 확인"}
JOB_STATUS = {"done": "완료", "failed": "실패", "interrupted": "중단"}
JOB_SKIPPED = {"replay mode": "재생 모드라 실행하지 않았습니다.", "no repo": "원본 저장소가 없는 실행입니다.",
               "docker unavailable": "작업자에 Docker가 없습니다.", "no model": "작업자에 모델이 설정되어 있지 않습니다.",
               "nothing to judge": "다시 판단할 항목이 없습니다."}


def _buckets(summary: dict | None) -> str | None:
    final = (summary or {}).get("final") or {}
    return f"NOW {final.get('NOW', 0)}  |  NEXT {final.get('NEXT', 0)}  |  MONITOR {final.get('MONITOR', 0)}" if final else None


def build_job_message(job: dict, name: str, link: str | None = None) -> dict:
    """Pure function: a finished queue job -> Slack payload.

    Says which job ended and how, with counts. It never carries the job's error text (an exception
    message can hold file paths or a log tail) or who asked for it (a person's address).
    """
    kind, status, result = JOB_KIND.get(job["kind"], job["kind"]), job["status"], job.get("result") or {}
    skipped = result.get("skipped") or (result.get("combined_skipped") if result.get("combined") is None else None)
    lines: list[str] = []
    if status != "done":
        state = JOB_STATUS.get(status, status)
        lines.append("원인은 대시보드의 작업 기록에서 확인합니다." if status == "failed"
                     else "작업자가 도중에 멈췄습니다. 다시 실행해야 합니다.")
    elif skipped:
        state = "실행하지 않음"
        lines.append(JOB_SKIPPED.get(skipped, "실행 조건이 맞지 않았습니다."))
    else:
        state = JOB_STATUS["done"]
        if job["kind"] == "verify":
            lines.append(f"검증을 통과한 조치안 {(result.get('summary') or {}).get('verified', 0)}건")
        elif job["kind"] == "agent":
            lines.append(f"판단 {result.get('judged', 0)}건")
            if result.get("fallbacks"):
                lines.append(f"모델 호출이 실패해 규칙 결과로 남은 항목 {result['fallbacks']}건")
        elif job["kind"] == "export_together":
            combined = result.get("combined") or {}
            if combined:
                lines.append(f"승인한 변경 {len(combined.get('targets') or [])}건을 함께 적용: "
                             f"{VERDICT.get(combined.get('verdict'), '판단 불가')} (테스트 {combined.get('tests_run', 0)}개)")
            else:
                lines.append(f"승인한 변경 {result.get('approved', 0)}건의 패치를 만들었습니다.")
    head = f"[SBOM Triage] {name}: {kind} {state}"
    blocks: list[dict] = [{"type": "section", "text": {"type": "mrkdwn", "text": f"*{head}*"}}]
    if lines:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "\n".join("• " + x for x in lines)}})
    counts = _buckets(result.get("summary")) if status == "done" and not skipped else None
    if counts:
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": counts}]})
    if link:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"<{link}|대시보드에서 결과 보기>"}})
    return {"text": head, "blocks": blocks}


def send(payload: dict, dry_run: bool = False) -> tuple[bool, str]:
    """-> (sent, detail). Never raises: a failed notification must not fail the run."""
    url = os.environ.get("SLACK_WEBHOOK_URL", "")
    if dry_run:
        return False, "dry run"
    if cache.replay_mode():
        return False, "replay mode: not sent"
    if not url:
        return False, "SLACK_WEBHOOK_URL is not set"
    if not url.startswith("https://") and not url.startswith("http://"):
        return False, "SLACK_WEBHOOK_URL is not a URL"
    try:
        res = httpx.post(url, json=payload, timeout=15)
    except httpx.HTTPError as e:
        log.warning("slack notify failed: %s", type(e).__name__)
        return False, f"request failed: {type(e).__name__}"
    return (res.status_code == 200), f"http {res.status_code}"
