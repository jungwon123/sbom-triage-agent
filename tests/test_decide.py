"""Proposals, decisions and export: the agent proposes, a person decides, nothing is pushed."""
import json

import pytest

from triage import decide, runner
from triage.models import Remediation, Triage, Verification
from triage.verify import run as verify_run


def remediation(to="1.0.1"):
    return Remediation(kind="upgrade_direct", package="lib", from_version="1.0.0", to_version=to,
                       commands=[f"npm install lib@{to}"], package_json_patch=None, mitigation=None,
                       breaking_risk="low", notes=None)


def verification(fid, verdict="verified", patch="lib@1.0.0.patch"):
    return Verification(finding_id=fid, attempt=1, remediation_applied=remediation(), steps=[], target_resolved=True,
                        new_findings=[], new_now_findings=[], regressions=[], tests_run=27, verdict=verdict,
                        reason="ok", patch_file=patch, package_json_diff="--- a/package.json", lockfile_lines_changed=4)


@pytest.fixture
def run(tmp_path, make_finding):
    def make(verify: Verification | None = "default", bucket="NOW"):
        a, b = make_finding(), make_finding(id="CVE-2024-0002@lib@1.0.0", vuln_id="CVE-2024-0002")
        v = verification(a.id) if verify == "default" else verify
        triage = [Triage(finding_id=f.id, risk=70, risk_breakdown={}, effort="low", rule_bucket=bucket,
                         reachability="imported_only", final_bucket=bucket, override_reason=None, rationale=["r"],
                         remediation=remediation(), verification=v if f is a else None) for f in (a, b)]
        r = runner.Run(tmp_path)
        r.write("meta.json", {"name": "demo"})
        r.write("findings.json", [f.model_dump() for f in (a, b)])
        r.save_triage(triage)
        (tmp_path / "verify").mkdir(exist_ok=True)
        (tmp_path / "verify" / "lib@1.0.0.patch").write_text("--- a/package.json\n+++ b/package.json\n")
        return r
    return make


def test_one_proposal_per_package_version(run):
    [p] = decide.proposals(run())
    assert p.target == "lib@1.0.0" and len(p.finding_ids) == 2 and p.verification.verdict == "verified"
    assert p.decision is None


def test_approve_then_latest_decision_wins(run):
    r = run()
    decide.record(r, "lib@1.0.0", "held", "kim", "배포 일정 확인 필요")
    d = decide.record(r, "lib@1.0.0", "approved", "kim")
    assert d.to_version == "1.0.1" and d.verdict == "verified"
    assert decide.proposals(r)[0].decision.status == "approved"
    assert [x.status for x in decide.history(r.dir, "lib@1.0.0")] == ["held", "approved"]


def test_cannot_approve_without_a_sandbox_patch(run):
    with pytest.raises(decide.DecisionError):
        decide.record(run(verify=None), "lib@1.0.0", "approved", "kim")


def test_unverified_approval_and_any_rejection_need_a_reason(run, make_finding):
    r = run(verify=verification(make_finding().id, verdict="inconclusive"))
    with pytest.raises(decide.DecisionError):
        decide.record(r, "lib@1.0.0", "approved", "kim")
    assert decide.record(r, "lib@1.0.0", "approved", "kim", "테스트는 CI에서 확인").status == "approved"
    with pytest.raises(decide.DecisionError):
        decide.record(r, "lib@1.0.0", "rejected", "kim")
    with pytest.raises(decide.DecisionError):
        decide.record(r, "nope@9.9.9", "held", "kim", "x")


def test_export_writes_only_approved_changes_inside_the_run(run):
    r = run()
    assert decide.export(r)["files"] == []
    decide.record(r, "lib@1.0.0", "approved", "kim")
    out = decide.export(r)
    assert sorted(out["files"]) == ["PR_DRAFT.md", "lib@1.0.0.patch"]
    draft = (r.dir / "export" / "PR_DRAFT.md").read_text()
    assert "CVE-2024-0001" in draft and "CVE-2024-0002" in draft and "승인: kim" in draft
    decide.record(r, "lib@1.0.0", "rejected", "lee", "메이저 업그레이드와 함께 처리")
    assert decide.export(r)["files"] == [] and not (r.dir / "export" / "PR_DRAFT.md").exists()


def test_patch_name_cannot_leave_the_verify_folder(run, make_finding):
    r = run(verify=verification(make_finding().id, patch="../../meta.json"))
    assert decide.patch_text(r, "lib@1.0.0") is None


def test_diff_is_git_apply_format(tmp_path):
    (tmp_path / "package.json").write_text('{\n "dependencies": {"lib": "1.0.0"}\n}\n')
    out = verify_run.diff(tmp_path, "package.json", '{\n "dependencies": {"lib": "1.0.1"}\n}\n')
    assert out[:2] == ["--- a/package.json", "+++ b/package.json"]
    assert '- "dependencies": {"lib": "1.0.0"}' in out and '+ "dependencies": {"lib": "1.0.1"}' in out
    assert verify_run.diff(tmp_path, "package.json", (tmp_path / "package.json").read_text()) == []


def test_api_records_decisions(run, monkeypatch):
    from fastapi.testclient import TestClient
    from triage import api
    r = run()
    monkeypatch.setattr(runner, "OUT", r.dir.parent)
    c, rid = TestClient(api.app), r.dir.name
    assert c.get(f"/api/runs/{rid}/proposals").json()[0]["target"] == "lib@1.0.0"
    assert c.post(f"/api/runs/{rid}/decisions", json={"target": "lib@1.0.0", "status": "rejected", "by": "kim"}).status_code == 422
    ok = c.post(f"/api/runs/{rid}/decisions", json={"target": "lib@1.0.0", "status": "approved", "by": "kim"})
    assert ok.status_code == 200 and ok.json()["status"] == "approved"
    assert "PR_DRAFT.md" in c.post(f"/api/runs/{rid}/export").json()["files"]
    assert c.get(f"/api/runs/{rid}/patch", params={"target": "lib@1.0.0"}).text.startswith("--- a/package.json")


def step(name, status="passed", **kw):
    from triage.models import VerifyStep
    return VerifyStep(name=name, status=status, duration_ms=1, log_tail="", **kw)


def test_fewer_tests_than_the_baseline_is_not_verified():
    base = [step("test", "failed", failed_tests=["a › b"], tests_run=27)]
    died = [step("install"), step("test", "failed", failed_tests=[], tests_run=0), step("rescan")]
    assert verify_run.verdict(died, base, False, False)[:2] == ("inconclusive", "fewer_tests_ran")
    same = [step("install"), step("test", "failed", failed_tests=["a › b"], tests_run=27), step("rescan")]
    assert verify_run.verdict(same, base, False, False)[:2] == ("verified", "ok")


def test_export_together_writes_one_patch_from_one_sandbox_pass(run, monkeypatch):
    from triage.models import CombinedCheck
    r = run()
    decide.record(r, "lib@1.0.0", "approved", "kim")
    seen = {}

    def fake(run_, approved, setup_cmd):
        seen["targets"], seen["setup"] = [p.target for p in approved], setup_cmd
        check = CombinedCheck(targets=seen["targets"], finding_ids=approved[0].finding_ids, steps=[], remaining=[],
                              new_findings=[], regressions=[], tests_run=27, verdict="verified", reason="ok",
                              lockfile_lines_changed=8)
        return check, "--- a/package.json\n+++ b/package.json\n", None

    monkeypatch.setattr(decide, "check_together", fake)
    out = decide.export(r, together=True, setup_cmd="npx prisma generate")
    assert seen == {"targets": ["lib@1.0.0"], "setup": "npx prisma generate"}
    assert sorted(out["files"]) == ["PR_DRAFT.md", "combined.json", "combined.patch"]
    assert out["combined"]["verdict"] == "verified"
    assert "함께 적용한 결과" in (r.dir / "export" / "PR_DRAFT.md").read_text()


def test_export_together_falls_back_to_single_patches_when_the_sandbox_cannot_run(run, monkeypatch):
    r = run()
    decide.record(r, "lib@1.0.0", "approved", "kim")
    monkeypatch.setattr(decide, "check_together", lambda *a: (None, "", "Docker를 사용할 수 없습니다."))
    out = decide.export(r, together=True)
    assert sorted(out["files"]) == ["PR_DRAFT.md", "lib@1.0.0.patch"] and out["combined_skipped"]


def test_combined_command_orders_direct_upgrades_before_overrides(monkeypatch, tmp_path):
    from triage.verify import sandbox
    seen = {}

    def fake_run(repo, cmd, setup, scale=1.0):
        seen["cmd"] = cmd
        return sandbox.Result()

    monkeypatch.setattr(sandbox, "run", fake_run)
    over = remediation().model_copy(update={"kind": "override_transitive", "package": "aaa"})
    check, patch = verify_run.verify_together(tmp_path, [("aaa@1.0.0", over, ["x"]), ("lib@1.0.0", remediation(), ["y"])],
                                              set(), [], None)
    assert seen["cmd"].index("npm install lib@1.0.1") < seen["cmd"].index("aaa@1.0.0")
    assert check.targets == ["lib@1.0.0", "aaa@1.0.0"] and check.remaining == ["y", "x"] and patch == ""


def test_same_package_at_two_versions_becomes_one_command():
    from triage.verify import apply
    direct = remediation("1.0.9")
    other = remediation("1.0.5").model_copy(update={"kind": "override_transitive", "from_version": "0.9.0"})
    cmd = apply.same_package_command(direct, [other])
    assert cmd.startswith("npm install lib@1.0.9 ") and "'lib':'\\$lib'" in cmd
    assert "version==='1.0.0'" in cmd and "version==='0.9.0'" in cmd
    with pytest.raises(ValueError):
        apply.same_package_command(direct, [other.model_copy(update={"package": "x; rm -rf /"})])
    with pytest.raises(ValueError):
        apply.same_package_command(direct, [other.model_copy(update={"package": "lib", "to_version": "1.0.5 && curl"})])


def test_api_queues_the_combined_export_and_reports_the_job(run, monkeypatch):
    import time
    from fastapi.testclient import TestClient
    from triage import api
    r = run()
    decide.record(r, "lib@1.0.0", "approved", "kim")
    monkeypatch.setattr(runner, "OUT", r.dir.parent)
    monkeypatch.setattr(decide, "check_together", lambda *a: (None, "", "Docker를 사용할 수 없습니다."))
    c, rid = TestClient(api.app), r.dir.name
    assert c.get(f"/api/runs/{rid}/jobs/latest").json() is None
    res = c.post(f"/api/runs/{rid}/export/together")
    assert res.status_code == 202 and res.json()["status"] in ("queued", "running", "done")
    job_id = res.json()["id"]
    for _ in range(100):
        job = c.get(f"/api/runs/{rid}/jobs/{job_id}").json()
        if job["status"] == "done":
            break
        time.sleep(0.05)
    assert job["status"] == "done" and job["result"]["combined_skipped"] and "PR_DRAFT.md" in job["result"]["files"]
    assert c.get(f"/api/runs/{rid}/jobs/latest").json()["id"] == job_id
    assert c.get(f"/api/runs/{rid}/jobs/zzz").status_code == 404
