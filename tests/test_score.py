from triage import score


def test_deterministic(make_finding):
    f = make_finding()
    assert score.score(f) == score.score(f)


def test_weights_sum(make_finding, runtime_site):
    f = make_finding(cvss=10.0, kev=True, import_sites=[runtime_site])
    r = score.score(f)
    assert r.risk_breakdown == {"severity": 25.0, "exploit": 25.0, "exposure": 30.0}   # imported_only 0.6
    assert r.bucket == "NOW"


def test_boundaries():
    assert score.bucket(60, "low") == "NOW"
    assert score.bucket(59.99, "low") == "NEXT"
    assert score.bucket(30, "low") == "NEXT"
    assert score.bucket(29.99, "low") == "MONITOR"
    assert score.bucket(90, "high") == "NEXT"       # no fix: mitigation first


def test_unused_dev_critical_is_not_now(make_finding):
    f = make_finding(cvss=9.8, epss_percentile=0.9, scope="dev")
    assert score.score(f).bucket != "NOW"


def test_transitive_is_unknown_not_unused(make_finding):
    assert score.score(make_finding(direct=False)).reachability == "unknown"


def test_test_only_import_counts_as_unused(make_finding, runtime_site):
    site = runtime_site.model_copy(update={"kind": "test"})
    assert score.score(make_finding(import_sites=[site])).reachability == "unused"


def test_effort(make_finding):
    assert score.effort(make_finding(bump="none", fixed_in=None)) == "high"
    assert score.effort(make_finding(bump="major")) == "medium"
    assert score.effort(make_finding(direct=False)) == "medium"
    assert score.effort(make_finding()) == "low"


def test_needs_review(make_finding, runtime_site):
    assert score.needs_review(make_finding(kev=True))
    assert score.needs_review(make_finding(epss_percentile=0.95, import_sites=[runtime_site]))
    assert not score.needs_review(make_finding(epss_percentile=0.95))


def test_sbom_only_input_is_unknown(make_finding):
    assert score.score(make_finding(missing=["source"])).reachability == "unknown"


def test_needs_review_high_epss_now_without_import(make_finding):
    f = make_finding(epss_percentile=0.95)
    assert score.needs_review(f, "NOW")
    assert not score.needs_review(f, "NEXT")
    assert not score.needs_review(make_finding(epss_percentile=0.5), "NOW")
