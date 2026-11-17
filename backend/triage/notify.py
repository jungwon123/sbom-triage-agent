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
