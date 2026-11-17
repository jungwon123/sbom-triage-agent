import pytest

from triage.models import CodeRef, Finding


@pytest.fixture
def make_finding():
    def make(**kw) -> Finding:
        base = dict(id="CVE-2024-0001@lib@1.0.0", vuln_id="CVE-2024-0001", aliases=[], ecosystem="npm",
                    package="lib", version="1.0.0", scope="prod", direct=True, paths=[["lib"]], cvss=7.5,
                    epss=0.1, epss_percentile=0.5, kev=False, fixed_in="1.0.1", fixed_max="1.2.0",
                    bump="patch", import_sites=[])
        base.update(kw)
        return Finding(**base)
    return make


@pytest.fixture
def runtime_site():
    return CodeRef(file="src/app.ts", line=3, kind="runtime", snippet="import lib from 'lib'")
