from triage.models import VerifyStep
from triage.verify.run import verdict


def s(name, status="passed", failed=(), timed_out=False):
    return VerifyStep(name=name, status=status, duration_ms=1, log_tail="", failed_tests=list(failed), timed_out=timed_out)


BASE = [s("install"), s("build"), s("test")]


def test_verified():
    assert verdict(BASE + [s("rescan")], BASE, False, False)[0] == "verified"


def test_target_remains_and_new_now():
    assert verdict(BASE, BASE, True, False)[:2] == ("failed", "target_remains")
    assert verdict(BASE, BASE, False, True)[:2] == ("failed", "new_now")


def test_build_and_test_regression():
    assert verdict([s("install"), s("build", "failed"), s("test")], BASE, False, False)[2] == ["build"]
    v = verdict([s("install"), s("build"), s("test", "failed", ["A › b"])], BASE, False, False)
    assert v[0] == "failed" and v[2] == ["A › b"]


def test_existing_failures_are_not_regressions():
    base = [s("install"), s("build"), s("test", "failed", ["Auth › login"])]
    same = [s("install"), s("build"), s("test", "failed", ["Auth › login"])]
    more = [s("install"), s("build"), s("test", "failed", ["Auth › login", "Api › get"])]
    assert verdict(same, base, False, False)[0] == "verified"
    assert verdict(more, base, False, False)[2] == ["Api › get"]


def test_uncomparable_baseline_is_inconclusive():
    base = [s("install"), s("build"), s("test", "failed")]
    assert verdict([s("install"), s("build"), s("test", "failed")], base, False, False)[:2] == ("inconclusive", "baseline_test_uncomparable")


def test_timeout_is_inconclusive():
    steps = [s("install"), s("build"), s("test", "failed", timed_out=True)]
    assert verdict(steps, BASE, False, False)[:2] == ("inconclusive", "timeout")


def test_mitigation_only_is_inconclusive():
    assert verdict([], BASE, False, False, mitigation_only=True)[0] == "inconclusive"


def test_install_failure():
    assert verdict([s("install", "failed")], BASE, True, False)[:2] == ("failed", "install_failed")


def test_skipped_steps_allowed():
    steps = [s("install"), s("build", "skipped"), s("test", "skipped")]
    assert verdict(steps, steps, False, False)[0] == "verified"
