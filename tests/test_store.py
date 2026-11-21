"""Both stores must behave the same. PostgreSQL tests need the compose database:
docker compose -f deploy/docker-compose.yml up -d postgres   (skipped when it is not reachable)."""
import json
import os
import time

import pytest

from triage import cache, decide, runner, store
from triage.store.files import FileStore

TEST_URL = os.environ.get("TEST_DATABASE_URL", "postgresql://triage:triage_dev@127.0.0.1:54329/triage")
TABLES = "runs, findings, triage, events, decisions, http_cache, jobs, workers"


def postgres():
    try:
        import psycopg
        from triage.store.postgres import PostgresStore
        psycopg.connect(TEST_URL, connect_timeout=2).close()
    except Exception:
        pytest.skip("PostgreSQL is not reachable")
    # tests own a schema of their own so they never touch imported runs
    pg = PostgresStore(TEST_URL, schema="triage_test")
    pg.init()
    pg._conn().execute(f"TRUNCATE {TABLES} RESTART IDENTITY CASCADE")
    return pg


@pytest.fixture(params=["file", "postgres"])
def st(request, tmp_path, monkeypatch):
    monkeypatch.setattr(cache, "CACHE_DIR", tmp_path / "cache")
    s = FileStore() if request.param == "file" else postgres()
    store.use(s)
    yield s
    store.use(None)
    if request.param == "postgres":
        s.close()


def finding(make_finding, i, **kw):
    return make_finding(id=f"CVE-2024-000{i}@lib@1.0.0", vuln_id=f"CVE-2024-000{i}", **kw).model_dump()


def triage_row(fid, bucket="NEXT"):
    return {"finding_id": fid, "risk": 50, "risk_breakdown": {}, "effort": "low", "rule_bucket": bucket,
            "reachability": "unknown", "final_bucket": bucket, "override_reason": None, "rationale": ["r"],
            "remediation": None, "verification": None, "needs_review": False, "decided_by": "rule",
            "evidence_files": [], "code_read_by": "rule"}


def test_documents_round_trip_in_order(st, tmp_path, make_finding):
    d = tmp_path / "20261119-000000-svc"
    assert not st.has_run(d)
    with pytest.raises(KeyError):
        st.get_doc(d, "meta")
    fs = [finding(make_finding, i) for i in (3, 1, 2)]
    st.put_doc(d, "meta", {"name": "svc", "summary": {"findings": 3}, "stages": ["scan"]})
    st.put_doc(d, "findings", fs)
    st.put_doc(d, "triage", [triage_row(f["id"]) for f in fs])
    assert st.has_run(d) and st.get_doc(d, "meta")["name"] == "svc"
    assert [f["id"] for f in st.get_doc(d, "findings")] == [f["id"] for f in fs]
    assert st.get_doc(d, "findings")[0] == fs[0]
    st.put_doc(d, "triage", [triage_row(fs[0]["id"], "NOW")])          # a rewrite replaces, never appends
    assert [t["final_bucket"] for t in st.get_doc(d, "triage")] == ["NOW"]
    assert st.list_runs(tmp_path) == [{"id": d.name, "name": "svc", "summary": {"findings": 3}, "stages": ["scan"]}]


def test_events_and_decisions_are_append_only_logs(st, tmp_path):
    d = tmp_path / "20261119-000000-svc"
    st.put_doc(d, "meta", {"name": "svc"})
    for i in range(3):
        st.append_event(d, {"ts": 1.0 + i, "type": "stage", "n": i})
    assert [e["n"] for e in st.events(d)] == [0, 1, 2]
    row = {"target": "lib@1.0.0", "status": "held", "by": "kim", "reason": "확인 필요",
           "at": "2026-11-19T22:00:00+09:00", "to_version": "1.0.1", "verdict": "verified"}
    st.append_decision(d, row)
    st.append_decision(d, {**row, "status": "approved", "reason": ""})
    assert [x["status"] for x in st.decisions(d)] == ["held", "approved"] and st.decisions(d)[0] == row


def test_cache_keeps_the_fetch_time(st):
    assert st.cache_get("k1") is None
    st.cache_put("k1", "https://x/feed", {"v": 1})
    body, at = st.cache_get("k1")
    assert body == {"v": 1} and abs(at - time.time()) < 5
    st.cache_put("k1", "https://x/feed", {"v": 2})
    assert st.cache_get("k1")[0] == {"v": 2}


def test_search_finds_a_package_in_the_latest_run_of_each_service(st, tmp_path, make_finding):
    old, new, other = tmp_path / "20261101-000000-shop", tmp_path / "20261119-000000-shop", tmp_path / "20261110-000000-pay"
    for d, name, fs in ((old, "shop", [finding(make_finding, 1)]),
                        (new, "shop", [finding(make_finding, 2, package="Log4J", kev=True)]),
                        (other, "pay", [finding(make_finding, 3, package="log4j"), finding(make_finding, 4)])):
        st.put_doc(d, "meta", {"name": name, "summary": {}, "stages": []})
        st.put_doc(d, "findings", fs)
        st.put_doc(d, "triage", [triage_row(f["id"], "NOW" if f["kev"] else "NEXT") for f in fs])
    hits = st.search(tmp_path, package="log4j")
    assert [(h["run_name"], h["vuln_id"], h["final_bucket"], h["kev"]) for h in hits] == [
        ("shop", "CVE-2024-0002", "NOW", True), ("pay", "CVE-2024-0003", "NEXT", False)]
    assert [h["run_id"] for h in st.search(tmp_path, vuln_id="CVE-2024-0001")] == []      # only in the older shop run
    assert [h["run_name"] for h in st.search(tmp_path, vuln_id="CVE-2024-0004")] == ["pay"]


def test_run_object_and_decisions_work_on_either_store(st, tmp_path, make_finding):
    from tests.test_decide import remediation, verification
    from triage.models import Triage
    f = make_finding()
    r = runner.Run(tmp_path / "20261119-000000-svc")
    r.write("meta.json", {"name": "svc"})
    r.write("findings.json", [f.model_dump()])
    r.save_triage([Triage(finding_id=f.id, risk=70, risk_breakdown={}, effort="low", rule_bucket="NOW",
                          reachability="imported_only", final_bucket="NOW", override_reason=None, rationale=["r"],
                          remediation=remediation(), verification=verification(f.id))])
    r.emit({"type": "stage", "stage": "scan"})
    r.write("compare.json", {"x": 1})                                     # an artifact, stays a file
    assert (r.dir / "compare.json").exists() and r.read("compare.json") == {"x": 1}
    assert r.findings()[0].id == f.id and r.triage()[0].verification.verdict == "verified"
    decide.record(r, "lib@1.0.0", "approved", "kim")
    assert decide.proposals(r)[0].decision.status == "approved"
    assert [e["type"] for e in r.events()] == ["stage", "decision"]
    if st.name == "postgres":
        assert not (r.dir / "meta.json").exists() and not (r.dir / "decisions.jsonl").exists()


def test_import_copies_a_file_run_into_postgres(tmp_path, make_finding, monkeypatch):
    from triage.store import migrate
    monkeypatch.setattr(cache, "CACHE_DIR", tmp_path / "cache")
    src, pg = FileStore(), postgres()
    d = tmp_path / "20261119-000000-svc"
    fs = [finding(make_finding, 1), finding(make_finding, 2)]
    src.put_doc(d, "meta", {"name": "svc", "summary": {}, "stages": ["scan"]})
    src.put_doc(d, "findings", fs)
    src.put_doc(d, "triage", [triage_row(f["id"]) for f in fs])
    src.append_event(d, {"ts": 1.0, "type": "stage"})
    src.append_decision(d, {"target": "lib@1.0.0", "status": "approved", "by": "kim", "reason": "",
                            "at": "2026-11-19T22:00:00+09:00", "to_version": "1.0.1", "verdict": "verified"})
    src.cache_put("abc", "https://x", {"v": 1})
    assert migrate.import_run(src, pg, d) == {"meta": 1, "findings": 2, "triage": 2, "events": 1, "decisions": 1}
    assert migrate.import_run(src, pg, d)["decisions"] == 1 and len(pg.decisions(d)) == 1      # importing twice is safe
    assert pg.get_doc(d, "findings") == fs and migrate.import_cache(pg) == 1 and pg.cache_get("abc")[0] == {"v": 1}
    pg.close()


def test_writes_are_visible_to_another_connection(tmp_path):
    """Guards against writes that sit in an open transaction and vanish when the process exits."""
    import psycopg
    pg = postgres()
    d = tmp_path / "20261119-000000-svc"
    pg.put_doc(d, "meta", {"name": "svc"})
    pg.append_event(d, {"ts": 1.0, "type": "stage"})
    pg.cache_put("k", "https://x", {"v": 1})
    with psycopg.connect(TEST_URL, autocommit=True) as other:
        other.execute("SET search_path TO triage_test")
        n = other.execute("SELECT (SELECT count(*) FROM runs) + (SELECT count(*) FROM events) + (SELECT count(*) FROM http_cache)").fetchone()[0]
    assert n == 3
    pg.close()
