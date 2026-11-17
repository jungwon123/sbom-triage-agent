"""⑥ Verification loop and verdict (REQUIREMENTS F8, HARNESS 4).

NOW items are grouped per package@version and verified once with one remediation (F8-12).
The target counts as resolved only if the rescan no longer reports it (F8-14).
"""
from __future__ import annotations

import json
import pathlib
from collections.abc import Callable

from .. import sbom, scan, score
from ..models import Finding, Remediation, Triage, Verification, VerifyStep
from . import apply, sandbox

MAX_ATTEMPTS = 3


def verdict(steps: list[VerifyStep], base: list[VerifyStep], target_left: bool, new_now: bool,
            mitigation_only: bool = False) -> tuple[str, str, list[str]]:
    """-> (verdict, reason, regressions). Pure function."""
    def get(seq: list[VerifyStep], name: str) -> VerifyStep | None:
        return next((s for s in seq if s.name == name), None)

    if mitigation_only:
        return "inconclusive", "mitigation_only", []
    timed_out = any(s.timed_out for s in steps)
    for name in ("copy", "apply", "install", "setup"):
        s = get(steps, name)
        if s and s.status == "failed" and not s.timed_out:
            return "failed", f"{name}_failed", [name]
    if not timed_out or get(steps, "rescan"):
        if target_left:
            return "failed", "target_remains", []
        if new_now:
            return "failed", "new_now", []
    regressions: list[str] = []
    b0, b1 = get(base, "build"), get(steps, "build")
    if b0 and b1 and b0.status == "passed" and b1.status == "failed" and not b1.timed_out:
        regressions.append("build")
    t0, t1 = get(base, "test"), get(steps, "test")
    uncomparable = False
    if t0 and t1 and not t1.timed_out:
        if t0.status == "passed" and t1.status == "failed":
            regressions += t1.failed_tests or ["test"]
        elif t0.status == "failed":
            if not t0.failed_tests:
                uncomparable = True
            else:
                regressions += sorted(set(t1.failed_tests) - set(t0.failed_tests))
    if regressions:
        return "failed", "regression", regressions
    if timed_out:
        return "inconclusive", "timeout", []
    if uncomparable:
        return "inconclusive", "baseline_test_uncomparable", []
    if b0 and b0.status == "failed":
        return "inconclusive", "baseline_build_failed", []
    return "verified", "ok", []


def rescan(repo: pathlib.Path, lockfile: str) -> dict[str, tuple[Finding, str]]:
    """Scan the post-change lockfile. -> finding id -> (finding, rule bucket)."""
    comps = sbom.components_from_cyclonedx(sbom.to_cyclonedx(sbom.npm_lock_components(json.loads(lockfile)), "rescan"))
    findings, _ = scan.scan(comps, repo)
    return {f.id: (f, score.score(f).bucket) for f in findings}


def verify_one(repo: pathlib.Path, r: Remediation, targets: list[str], before: set[str],
               baseline: list[VerifyStep], setup_cmd: str | None, attempt: int) -> Verification:
    cmd = apply.sandbox_command(r)
    if cmd is None:
        v, why, reg = verdict([], baseline, False, False, mitigation_only=True)
        return Verification(finding_id=targets[0], attempt=attempt, remediation_applied=r, steps=[],
                            target_resolved=False, new_findings=[], new_now_findings=[], regressions=reg,
                            tests_run=0, verdict=v, reason=why)
    res = sandbox.run(repo, cmd, setup_cmd)
    steps = list(res.steps)
    left, added, new_now = True, [], []
    if res.lockfile and res.step("install") and res.step("install").status == "passed":
        try:
            after = rescan(repo, res.lockfile)
            left = any(t in after for t in targets)
            added = sorted(k for k in after if k not in before)
            new_now = [k for k in added if after[k][1] == "NOW"]
            steps.append(VerifyStep(name="rescan", status="passed", duration_ms=0, log_tail=f"{len(after)} findings"))
        except Exception as e:  # rescan must not crash the run
            steps.append(VerifyStep(name="rescan", status="failed", duration_ms=0, log_tail=str(e)[:300]))
    v, why, reg = verdict(steps, baseline, left, bool(new_now))
    t = res.step("test")
    return Verification(finding_id=targets[0], attempt=attempt, remediation_applied=r, steps=steps,
                        target_resolved=not left, new_findings=added, new_now_findings=new_now, regressions=reg,
                        tests_run=t.tests_run if t else 0, verdict=v, reason=why)


def run(repo: pathlib.Path, findings: list[Finding], triage: list[Triage], run_dir: pathlib.Path,
        setup_cmd: str | None = None,
        revise: Callable[[Finding, dict, list[dict]], object] | None = None,
        emit: Callable[[dict], None] = lambda e: None) -> list[Triage]:
    by_id = {f.id: f for f in findings}
    now = [t for t in triage if t.final_bucket == "NOW" and by_id[t.finding_id].ecosystem == "npm"]
    if not now:
        return triage
    out_dir = run_dir / "verify"
    out_dir.mkdir(exist_ok=True)
    emit({"type": "verify_baseline_start"})
    base = sandbox.run(repo, None, setup_cmd)
    (out_dir / "baseline.json").write_text(json.dumps([s.model_dump() for s in base.steps], ensure_ascii=False, indent=1))
    before = set(by_id)

    groups: dict[tuple[str, str], list[Triage]] = {}
    for t in now:
        f = by_id[t.finding_id]
        groups.setdefault((f.package, f.version), []).append(t)

    for (pkg, ver), items in groups.items():
        # highest fix among the group's remediations covers every finding of this package (F8-12)
        lead = max(items, key=lambda t: apply.semver.parse(t.remediation.to_version or "0"))
        f = by_id[lead.finding_id]
        remediation, targets = lead.remediation, [t.finding_id for t in items]
        result = None
        for attempt in range(1, MAX_ATTEMPTS + 1):
            emit({"type": "verify_start", "package": pkg, "version": ver, "attempt": attempt,
                  "to_version": remediation.to_version})
            result = verify_one(repo, remediation, targets, before, base.steps, setup_cmd, attempt)
            emit({"type": "verify_done", "package": pkg, "verdict": result.verdict, "reason": result.reason})
            if result.verdict != "failed" or attempt == MAX_ATTEMPTS or revise is None:
                break
            proposal = revise(f, remediation.model_dump(), [s.model_dump() for s in result.steps])
            if proposal is None:
                break
            remediation = apply.build(proposal, f)   # already passed apply.violations in revise
        safe = pkg.replace("/", "_")
        (out_dir / f"{safe}@{ver}.json").write_text(result.model_dump_json(indent=1))
        for t in items:
            t.verification = result.model_copy(update={"finding_id": t.finding_id})
            t.remediation = remediation
    return triage
