"""Proposals, the owner's decisions and the export of approved changes (HANDOFF D41).

The agent proposes, a person decides. A proposal is one change set per package@version: the
remediation, its sandbox verification and the diff taken from the sandbox copy. Decisions are an
append-only log kept by the storage layer. Export writes files under out/<run>/export/ only;
nothing here touches the original repository or pushes anywhere (CLAUDE.md rule 4).
"""
from __future__ import annotations

import datetime as dt
import json
import pathlib
import re

from . import cache, store
from .models import BUCKET_ORDER, CombinedCheck, Decision, Finding, Proposal, Triage, VerifyStep
from .verify import run as verify_run, sandbox

LOG = "decisions.jsonl"
STATUS_KO = {"approved": "승인", "rejected": "반려", "held": "보류"}
VERDICT_KO = {"verified": "검증 통과", "failed": "검증 실패", "inconclusive": "판정 보류"}


class DecisionError(ValueError):
    """The decision cannot be recorded as asked. The message is shown to the person."""


def target_of(f: Finding) -> str:
    return f"{f.package}@{f.version}"


def decisions(run_dir: pathlib.Path) -> dict[str, Decision]:
    """Latest decision per target."""
    out: dict[str, Decision] = {}
    for row in store.get().decisions(run_dir):
        d = Decision.model_validate(row)
        out[d.target] = d
    return out


def history(run_dir: pathlib.Path, target: str) -> list[Decision]:
    return [d for d in map(Decision.model_validate, store.get().decisions(run_dir)) if d.target == target]


def proposals(run) -> list[Proposal]:
    """One proposal per package@version that has a remediation, most urgent first."""
    findings = {f.id: f for f in run.findings()}
    latest = decisions(run.dir)
    groups: dict[str, list[Triage]] = {}
    for t in run.triage():
        if t.remediation is not None:
            groups.setdefault(target_of(findings[t.finding_id]), []).append(t)
    out = []
    for target, items in groups.items():
        # the verified change is the one to show; otherwise the highest proposed version (F8-12)
        lead = next((t for t in items if t.verification is not None), None) or max(
            items, key=lambda t: (t.remediation.to_version is not None, BUCKET_ORDER.index(t.final_bucket)))
        f = findings[lead.finding_id]
        out.append(Proposal(
            target=target, package=f.package, from_version=f.version,
            finding_ids=[t.finding_id for t in items],
            bucket=max((t.final_bucket for t in items), key=BUCKET_ORDER.index),
            remediation=lead.verification.remediation_applied if lead.verification else lead.remediation,
            verification=lead.verification, decision=latest.get(target)))
    out.sort(key=lambda p: (-BUCKET_ORDER.index(p.bucket), p.target))
    return out


def record(run, target: str, status: str, by: str, reason: str = "", by_id: str | None = None) -> Decision:
    """Append one decision. Approval needs something a person can actually apply. by_id is the
    signed-in account when login is on; without it `by` is a name somebody typed."""
    p = next((x for x in proposals(run) if x.target == target), None)
    if p is None:
        raise DecisionError("이 실행에 없는 수정안입니다.")
    by, reason = by.strip(), reason.strip()
    if not by:
        raise DecisionError("결정한 사람의 이름이 필요합니다.")
    v = p.verification
    if status == "approved":
        if v is None or not v.patch_file:
            raise DecisionError("샌드박스에서 만든 변경 내용이 없는 수정안은 승인할 수 없습니다. 먼저 검증을 실행하세요.")
        if v.verdict != "verified" and not reason:
            raise DecisionError("검증을 통과하지 못한 수정안을 승인하려면 사유를 적어야 합니다.")
    elif not reason:
        raise DecisionError("반려와 보류에는 사유를 적어야 합니다.")
    d = Decision(target=target, status=status, by=by, by_id=by_id, reason=reason,
                 at=dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds"),
                 to_version=p.remediation.to_version, verdict=v.verdict if v else None)
    store.get().append_decision(run.dir, d.model_dump())
    run.emit({"type": "decision", "target": target, "status": status, "by": by})
    return d


def patch_text(run, target: str) -> str | None:
    p = next((x for x in proposals(run) if x.target == target), None)
    name = p.verification.patch_file if p and p.verification else None
    if not name or not re.fullmatch(r"[A-Za-z0-9@._+-]+\.patch", name):
        return None
    path = run.dir / "verify" / name
    return path.read_text() if path.is_file() else None


def pr_draft(run, approved: list[Proposal], combined: CombinedCheck | None = None) -> str:
    findings = {f.id: f for f in run.findings()}
    triage = {t.finding_id: t for t in run.triage()}
    lines = [f"# 취약 의존성 조치 {len(approved)}건 ({run.meta.get('name')})", "",
             "SBOM Triage가 제안하고 담당자가 승인한 변경입니다. 원본 저장소에는 아직 아무것도 반영되지 않았습니다.", ""]
    for p in approved:
        r, v, d = p.remediation, p.verification, p.decision
        lines += [f"## {p.package} {p.from_version} → {r.to_version}", ""]
        for fid in p.finding_ids:
            f, t = findings[fid], triage[fid]
            lines.append(f"- {f.vuln_id} ({t.final_bucket}): {f.summary or '요약 없음'}")
        lines += ["", "변경 방법"]
        lines += [f"- `{c}`" for c in r.commands]
        if r.package_json_patch:
            lines.append("- package.json에 추가: `" + json.dumps(r.package_json_patch, ensure_ascii=False) + "`")
        tests = f"기존 테스트 {v.tests_run}개에서 새 실패 없음" if v.tests_run else "실행된 테스트 없음(설치와 재스캔만 확인)"
        lines += ["", "샌드박스 확인",
                  f"- 판정: {VERDICT_KO[v.verdict]} ({v.reason})",
                  f"- 대상 취약점 제거: {'예' if v.target_resolved else '아니요'}, 새로 생긴 취약점 {len(v.new_findings)}건",
                  f"- {tests}",
                  f"- 변경 파일: `{v.patch_file}` (lockfile {v.lockfile_lines_changed}줄 변경)",
                  "", "결정 기록",
                  f"- {STATUS_KO[d.status]}: {d.by}, {d.at}" + (f", 사유: {d.reason}" if d.reason else ""), ""]
    if combined is not None:
        tests = (f"기존 테스트 {combined.tests_run}개에서 새 실패 없음" if combined.tests_run and not combined.regressions
                 else f"새로 실패: {', '.join(combined.regressions)}" if combined.regressions else "실행된 테스트 없음")
        lines += ["## 함께 적용한 결과", "",
                  f"승인한 {len(combined.targets)}건을 샌드박스에서 한 번에 적용했습니다.",
                  f"- 판정: {VERDICT_KO[combined.verdict]} ({combined.reason})",
                  f"- 대상 취약점 {len(combined.finding_ids)}건 중 남은 것 {len(combined.remaining)}건, 새로 생긴 취약점 {len(combined.new_findings)}건",
                  f"- {tests}",
                  f"- 적용할 파일: `{combined.patch_file}` 하나 (lockfile {combined.lockfile_lines_changed}줄 변경)", ""]
        if combined.verdict != "verified":
            lines += ["함께 적용한 상태가 검증을 통과하지 못했습니다. 이 패치를 그대로 반영하지 말고 건별로 나눠 확인하세요.", ""]
    else:
        lines += ["## 적용할 때 주의", "",
                  "- 각 패치는 원본 기준으로 따로 만들었습니다. 여러 건을 함께 적용하면 lockfile이 겹치므로, 위 명령을 순서대로 실행해 lockfile을 다시 만드는 쪽이 안전합니다.",
                  "- 함께 적용한 상태의 빌드와 테스트는 이 도구가 확인하지 않았습니다. 저장소의 CI에서 확인하세요.", ""]
    return "\n".join(lines)


def check_together(run, approved: list[Proposal], setup_cmd: str | None) -> tuple[CombinedCheck | None, str, str | None]:
    """-> (check, patch text, why it was skipped). Needs the repo, Docker and the stored baseline."""
    repo = run.repo()
    base_path = run.dir / "verify" / "baseline.json"
    if cache.replay_mode():
        return None, "", "재생 모드에서는 샌드박스를 실행하지 않습니다."
    if repo is None:
        return None, "", "원본 레포가 없는 실행입니다."
    if not base_path.exists():
        return None, "", "조치 전 기준선이 없습니다. 먼저 검증을 실행하세요."
    if not sandbox.available():
        return None, "", "Docker를 사용할 수 없습니다."
    baseline = [VerifyStep.model_validate(s) for s in json.loads(base_path.read_text())]
    items = [(p.target, p.remediation, p.finding_ids) for p in approved]
    check, patch = verify_run.verify_together(repo, items, {f.id for f in run.findings()}, baseline, setup_cmd)
    return check, patch, None


def export(run, together: bool = False, setup_cmd: str | None = None) -> dict:
    """Write approved patches and a PR draft under out/<run>/export/. -> what was written.

    together=True applies every approved change in one sandbox pass and exports that single patch
    instead of one patch per change.
    """
    out_dir = run.dir / "export"
    out_dir.mkdir(exist_ok=True)
    for old in out_dir.iterdir():
        if old.is_file():
            old.unlink()
    approved = [p for p in proposals(run) if p.decision and p.decision.status == "approved"
                and p.verification and p.verification.patch_file]
    files = []
    combined, skipped = None, None
    if together and approved:
        if setup_cmd and run.meta.get("verify_setup") != setup_cmd:   # remember it for the dashboard button
            run.write("meta.json", {**run.meta, "verify_setup": setup_cmd})
        setup_cmd = setup_cmd or run.meta.get("verify_setup")
        combined, patch, skipped = check_together(run, approved, setup_cmd)
        if combined is not None and patch:
            combined.patch_file = "combined.patch"
            (out_dir / combined.patch_file).write_text(patch)
            (out_dir / "combined.json").write_text(combined.model_dump_json(indent=1))
            files += [combined.patch_file, "combined.json"]
    if combined is None or not combined.patch_file:
        for p in approved:
            text = patch_text(run, p.target)
            if text:
                (out_dir / p.verification.patch_file).write_text(text)
                files.append(p.verification.patch_file)
    if approved:
        (out_dir / "PR_DRAFT.md").write_text(pr_draft(run, approved, combined))
        files.append("PR_DRAFT.md")
    run.emit({"type": "export", "approved": [p.target for p in approved], "files": files,
              "combined": combined.verdict if combined else None})
    return {"dir": str(out_dir), "approved": [p.target for p in approved], "files": files,
            "combined": combined.model_dump() if combined else None, "combined_skipped": skipped}


def export_view(run, together: bool) -> dict:
    """export() plus the PR draft text: what the dashboard shows. Also the result of the queued job."""
    out = export(run, together)
    draft = run.dir / "export" / "PR_DRAFT.md"
    return {"approved": out["approved"], "files": out["files"], "dir": f"out/{run.dir.name}/export",
            "combined": out["combined"], "combined_skipped": out["combined_skipped"],
            "pr_draft": draft.read_text() if draft.exists() else None}
