from triage import eval as ev, score
from triage.agent import run as agent_run


def test_agreement_and_now_miss(make_finding):
    a = make_finding(id="A@lib@1.0.0", cvss=9.8)                                    # cvss sort says NOW
    b = make_finding(id="B@lib@1.0.0", cvss=2.0, epss_percentile=0.01, scope="dev")  # everything says MONITOR
    triage = [agent_run.merge(f, score.score(f), None, "rule") for f in (a, b)]
    r = ev.evaluate([a, b], triage, {"A@lib@1.0.0": "NEXT", "B@lib@1.0.0": "NOW", "Z@x@1": "NOW"})
    assert r["matched"] == 2
    assert r["rule_only"]["now_missed"] == ["B@lib@1.0.0"]
    assert r["cvss_sort"]["agreement_pct"] == 0.0 and r["rule_only"]["agreement_pct"] == 50.0


def test_sheet_without_labels_is_empty(tmp_path):
    p = tmp_path / "sheet.csv"
    p.write_text("item,repo,package,version,advisory,label(NOW/NEXT/MONITOR)\nG01,r,lib,1.0.0,CVE-1,\nG02,r,lib,1.0.0,CVE-2,now\n", encoding="utf-8-sig")
    assert ev.load_golden(p) == {"CVE-2@lib@1.0.0": "NOW"}
