"""Registered services and re-triage (services.py, HANDOFF D48). Same behaviour on both stores. No network:
the scan is replaced by a function that returns the findings the test wants."""
import datetime as dt
import json
import time

import pytest
from fastapi.testclient import TestClient

from tests.test_agent_contract import GOOD
from tests.test_auth import idp, sign_in  # noqa: F401
from tests.test_store import st  # noqa: F401  (the two-store fixture)
from triage import jobs, notify, runner, services
from triage.agent import run as agent_run
from triage.models import Change


@pytest.fixture(autouse=True)
def quiet(monkeypatch):
    monkeypatch.setenv("TRIAGE_WORKER", "external")       # tests drive the worker by hand
    monkeypatch.delenv("DEMO_MODE", raising=False)
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("TRIAGE_AUTH", raising=False)


@pytest.fixture
def world(st, tmp_path, monkeypatch, make_finding):  # noqa: F811
    """A registered service whose next scan returns `world.findings`."""
    class World:
        root = tmp_path / "out"
        repo = tmp_path / "repos" / "shop"
        findings: list = []
        scans = 0

        def finding(self, n: int, **kw):
            return make_finding(id=f"CVE-2024-000{n}@lib@1.0.0", vuln_id=f"CVE-2024-000{n}", **kw)

    w = World()
    w.repo.mkdir(parents=True)
    w.root.mkdir()

    def collect(target, emit, use_syft=True):
        w.scans += 1
        emit({"type": "stage", "stage": "scan", "status": "done"})
        return runner.Scanned(target, target, {"components": []}, "test", list(w.findings),
                              agent_run.run(w.findings, None, None, target), {"components": 0}, 0.1)

    monkeypatch.setattr(runner, "collect", collect)
    monkeypatch.setattr(runner, "OUT", w.root)
    monkeypatch.setenv("TRIAGE_SERVICE_ROOTS", str(tmp_path / "repos"))
    services.register(w.root, "shop", "쇼핑몰", str(w.repo), owner="결제팀")
    return w


def test_service_records_behave_the_same_on_both_stores(st, tmp_path):  # noqa: F811
    row = {"id": "shop", "name": "쇼핑몰", "target": "/srv/shop", "current_run": None}
    assert st.service_add(tmp_path, row) and not st.service_add(tmp_path, {**row, "name": "다른 이름"})
    assert st.service_add(tmp_path, {**row, "id": "auth"})
    assert [s["id"] for s in st.service_list(tmp_path)] == ["auth", "shop"] and st.service_get(tmp_path, "shop") == row
    assert st.service_update(tmp_path, "shop", {"current_run": "r1"}) == {**row, "current_run": "r1"}
    assert st.service_update(tmp_path, "nope", {"x": 1}) is None and st.service_get(tmp_path, "nope") is None
    assert st.service_delete(tmp_path, "shop") and not st.service_delete(tmp_path, "shop")
    assert st.list_runs(tmp_path) == []                    # a service record is never mistaken for a run


def test_diff_names_what_moved(make_finding, tmp_path):
    def f(n, **kw):
        return make_finding(id=f"v{n}", vuln_id=f"v{n}", **kw)
    rule = lambda fs: agent_run.run(fs, None, None, tmp_path)  # noqa: E731
    old = [f(1), f(2, scope="dev", cvss=2.0), f(3, fixed_in=None, fixed_max=None, bump="none"), f(4)]
    new = [f(1), f(2, scope="dev", cvss=2.0, kev=True), f(3), f(5)]
    kinds = {(c.finding_id, c.kind) for c in services.diff(old, rule(old), new, rule(new))}
    assert ("v5", "added") in kinds and ("v4", "removed") in kinds and ("v2", "kev_added") in kinds
    assert ("v2", "raised") in kinds and ("v3", "fix_released") in kinds and not any(i == "v1" for i, _ in kinds)
    assert services.diff(old, rule(old), old, rule(old)) == []


def test_first_check_records_a_run_and_an_unchanged_one_records_nothing(world):
    world.findings = [world.finding(1)]
    first = services.check(world.root, "shop")
    assert first.result == "first" and first.run_id and runner.Run(world.root / first.run_id).meta["service"] == "shop"
    world.findings = [world.finding(1, epss=0.11)]         # a score that drifts inside its bucket is not a change
    again = services.check(world.root, "shop")
    assert again.result == "no_change" and again.run_id == first.run_id and world.scans == 2
    assert [r["id"] for r in runner.store.get().list_runs(world.root)] == [first.run_id]
    svc = services.get(world.root, "shop")
    assert svc.current_run == first.run_id and svc.last_check.result == "no_change"


def test_a_change_makes_a_new_run_and_reuses_earlier_ai_judgments(world):
    world.findings = [world.finding(1), world.finding(2, scope="dev", cvss=2.0)]
    base = runner.Run(world.root / services.check(world.root, "shop").run_id)
    kept = world.findings[0].id
    (base.dir / "agent_answers.json").write_text(json.dumps({kept: [GOOD]}))
    runner.agent(base, writer="replay", code_reader="none")
    assert {t.finding_id: t.decided_by for t in base.triage()}[kept] == "agent"

    world.findings = [world.finding(1), world.finding(2, scope="dev", cvss=2.0, kev=True), world.finding(3)]
    res = services.check(world.root, "shop")
    assert res.result == "changed" and res.compared_to == base.id and res.run_id != base.id
    assert res.counts == {"added": 1, "kev_added": 1, "raised": 1} and res.carried == 1 and res.needs_judgment == 2
    run = runner.Run(world.root / res.run_id)
    by = {t.finding_id: t for t in run.triage()}
    assert by[kept].decided_by == "agent" and by[kept].rationale == {t.finding_id: t for t in base.triage()}[kept].rationale
    assert by[world.findings[2].id].decided_by == "rule" and by[kept].verification is None
    meta = run.meta
    assert meta["previous_run"] == base.id and {c["kind"] for c in meta["changes"]} == {"added", "kev_added", "raised"}
    assert services.get(world.root, "shop").current_run == run.id
    assert "not sent" in res.notified                      # KEV and NOW changes ask for an alert; no webhook is set
    assert base.triage()[0].finding_id == kept             # the earlier run is left as it was


def test_a_failed_scan_is_recorded_and_keeps_the_current_run(world, monkeypatch):
    world.findings = [world.finding(1)]
    first = services.check(world.root, "shop")

    def boom(target, emit, use_syft=True):
        raise RuntimeError("OSV unavailable")
    monkeypatch.setattr(runner, "collect", boom)
    res = services.check(world.root, "shop")
    assert res.result == "failed" and "OSV unavailable" in res.error and res.run_id == first.run_id
    assert services.get(world.root, "shop").current_run == first.run_id


def test_due_services_are_queued_once_and_the_worker_runs_the_check(world, monkeypatch):
    world.findings = [world.finding(1)]
    assert [s.id for s in services.due(world.root)] == ["shop"]             # never checked
    assert services.submit_due(world.root) == 1 and services.submit_due(world.root) == 1
    assert len(runner.store.get().job_list(world.root, jobs.ACTIVE)) == 1    # the second ask found the queued job
    done = jobs.work_once(world.root, "w1")
    assert done.status == "done" and done.kind == "service_check" and done.result["result"] == "first"
    assert services.due(world.root) == [] and services.latest_job(world.root, "shop").status == "done"
    later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=25)
    assert [s.id for s in services.due(world.root, later)] == ["shop"]
    runner.store.get().service_update(world.root, "shop", {"check_hours": None})
    assert services.due(world.root, later) == []                             # only on request
    monkeypatch.setenv("DEMO_MODE", "replay")
    runner.store.get().service_update(world.root, "shop", {"check_hours": 1, "last_check": None})
    assert services.submit_due(world.root) == 0                              # replay has nothing new to compare


def test_the_worker_loop_queues_due_checks_by_itself(world):
    world.findings = [world.finding(1)]
    assert jobs.serve(world.root, me="w1", once=True) == 1
    assert services.get(world.root, "shop").last_check.result == "first"


def test_a_target_over_the_api_must_be_under_an_allowed_root(world, tmp_path):
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (tmp_path / "repos" / "link").symlink_to(outside)
    for bad in (str(outside), str(tmp_path / "repos" / "link"), str(tmp_path / "repos" / ".." / "elsewhere"), "/etc"):
        with pytest.raises(services.ServiceError):
            services.resolve_target(bad, restricted=True)
    assert services.resolve_target(str(world.repo), restricted=True) == world.repo.resolve()
    assert services.resolve_target(str(outside), restricted=False) == outside.resolve()     # the operator's own CLI
    with pytest.raises(services.ServiceError):
        services.register(world.root, "shop", "또", str(world.repo))                          # id taken
    with pytest.raises(services.ServiceError):
        services.register(world.root, "Bad Id", "x", str(world.repo))


def test_the_alert_names_packages_and_buckets_only():
    changes = [Change(finding_id="CVE-1@lib@1.0.0", package="lib", version="1.0.0", vuln_id="CVE-1", kind="raised",
                      before="NEXT", after="NOW"),
               Change(finding_id="CVE-2@lib@1.0.0", package="lib", version="1.0.0", vuln_id="CVE-2", kind="added", after="MONITOR"),
               Change(finding_id="CVE-3@lib@1.0.0", package="lib", version="1.0.0", vuln_id="CVE-3", kind="kev_added",
                      before="NEXT", after="NEXT", kev=True)]
    hot = services.worth_alerting(changes)
    assert [c.vuln_id for c in hot] == ["CVE-1", "CVE-3"]
    text = json.dumps(notify.build_change_message("쇼핑몰", hot, 3, "https://t.example/?run=r"), ensure_ascii=False)
    assert "NEXT → NOW" in text and "KEV 등재" in text and "CVE-2" not in text and "/?run=r" in text


# ---------- API ----------

def client(world):
    from triage import api
    return TestClient(api.app, follow_redirects=False)


def test_with_login_off_services_can_be_registered_checked_and_removed(world, tmp_path):
    c = client(world)
    other = tmp_path / "repos" / "pay"
    other.mkdir()
    body = {"id": "pay", "name": "결제", "target": str(other), "check_hours": None, "context": {"service_criticality": "high"}}
    made = c.post("/api/services", json=body)
    assert made.status_code == 201 and made.json()["context"]["service_criticality"] == "high" and made.json()["created_by"] is None
    assert c.post("/api/services", json=body).status_code == 422                       # id taken
    assert c.post("/api/services", json={**body, "id": "x", "target": "/etc"}).status_code == 422
    world.findings = [world.finding(1)]
    queued = c.post("/api/services/shop/check")
    assert queued.status_code == 202 and queued.json()["job"]["status"] == "queued"
    jobs.work_once(world.root, "w1")
    rows = {s["id"]: s for s in c.get("/api/services").json()}
    assert rows["shop"]["last_check"]["result"] == "first" and rows["shop"]["summary"]["findings"] == 1
    assert rows["shop"]["job"]["status"] == "done" and rows["pay"]["summary"] is None
    assert c.delete("/api/services/pay").json() == {"ok": True} and c.delete("/api/services/pay").status_code == 404
    assert c.post("/api/services/nope/check").status_code == 404


def test_registering_needs_admin_and_checking_needs_approver(world, idp):  # noqa: F811
    c = client(world)
    body = {"id": "pay", "name": "결제", "target": str(world.repo)}
    assert c.get("/api/services").status_code == 401 and c.post("/api/services", json=body).status_code == 401
    sign_in(c, idp, groups=["dev"])
    assert c.get("/api/services").status_code == 200
    assert c.post("/api/services/shop/check").status_code == 403 and c.post("/api/services", json=body).status_code == 403
    sign_in(c, idp, groups=["sec-approvers"])
    assert c.post("/api/services/shop/check").status_code == 202
    assert c.post("/api/services", json=body).status_code == 403 and c.delete("/api/services/shop").status_code == 403
    sign_in(c, idp, groups=["sec-admins"])
    made = c.post("/api/services", json=body)
    assert made.status_code == 201 and made.json()["created_by"] == "kim@example.com"
    assert c.delete("/api/services/pay").status_code == 200
