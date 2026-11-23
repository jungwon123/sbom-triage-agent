"""Input formats (ingest.py): each sample is a cut-down version of what the tool or file really looks like."""
import json
import pathlib

import pytest

from triage import cache, ingest, sbom, scan
from triage.models import Component, Reported


def names(parsed):
    return {(c.ecosystem, c.name, c.version) for c in parsed.components}


def test_yarn_lock_classic_and_berry():
    classic = '''# yarn lockfile v1

"@babel/core@^7.0.0", "@babel/core@^7.1.0":
  version "7.24.0"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.24.0.tgz"

lodash@^4.17.20:
  version "4.17.20"
  dependencies:
    left-pad "^1.0.0"
'''
    berry = '''__metadata:
  version: 8

"lodash@npm:^4.17.20":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"

"my-app@workspace:.":
  version: 0.0.0-use.local
'''
    assert names(ingest.parse_yarn_lock(classic)) == {("npm", "@babel/core", "7.24.0"), ("npm", "lodash", "4.17.20")}
    assert names(ingest.parse_yarn_lock(berry)) == {("npm", "lodash", "4.17.21")}


def test_pnpm_lock_old_and_new_keys():
    text = '''lockfileVersion: '6.0'
dependencies:
  express:
    specifier: ^4.18.0
    version: 4.18.2
devDependencies:
  jest:
    specifier: ^29.0.0
    version: 29.7.0
packages:
  /express@4.18.2:
    resolution: {integrity: sha512-x}
  /jest@29.7.0:
    dev: true
  /@scope/util@1.0.0(react@18.2.0):
    dev: false
  qs@6.5.2:
    resolution: {integrity: sha512-y}
'''
    c = {x.name: x for x in ingest.parse_pnpm_lock(text).components}
    assert c["express"].direct and c["express"].scope == "prod" and c["jest"].scope == "dev"
    assert c["@scope/util"].version == "1.0.0" and c["qs"].version == "6.5.2" and not c["qs"].direct


def test_python_files():
    req = "Django==4.2.1  # web\nrequests[socks]==2.31.0 ; python_version > '3'\nflask>=2.0\n-r base.txt\nMy_Pkg.Name==1.0\n"
    p = ingest.parse_requirements(req)
    assert names(p) == {("PyPI", "django", "4.2.1"), ("PyPI", "requests", "2.31.0"), ("PyPI", "my-pkg-name", "1.0")}
    assert any("1개" in n for n in p.notes)                            # the unpinned line is counted, not silently dropped
    poetry = '[[package]]\nname = "urllib3"\nversion = "1.26.5"\ncategory = "main"\n\n[[package]]\nname = "pytest"\nversion = "7.0.0"\ncategory = "dev"\n'
    c = {x.name: x for x in ingest.parse_poetry_lock(poetry).components}
    assert c["urllib3"].scope == "prod" and c["pytest"].scope == "dev"
    pipfile = json.dumps({"default": {"jinja2": {"version": "==3.1.2"}}, "develop": {"black": {"version": "==23.1.0"}}})
    assert names(ingest.parse_pipfile_lock(pipfile)) == {("PyPI", "jinja2", "3.1.2"), ("PyPI", "black", "23.1.0")}
    uv = '[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { virtual = "." }\n\n[[package]]\nname = "httpx"\nversion = "0.27.0"\nsource = { registry = "https://pypi.org/simple" }\n'
    assert names(ingest.parse_uv_lock(uv)) == {("PyPI", "httpx", "0.27.0")}


def test_go_rust_ruby_php_dotnet_gradle():
    gomod = "module example.com/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgolang.org/x/net v0.7.0 // indirect\n)\nrequire github.com/pkg/errors v0.9.1\n"
    c = {x.name: x for x in ingest.parse_go_mod(gomod).components}
    assert c["github.com/gin-gonic/gin"].version == "1.9.0" and c["github.com/gin-gonic/gin"].direct
    assert not c["golang.org/x/net"].direct and c["github.com/pkg/errors"].purl == "pkg:golang/github.com/pkg/errors@0.9.1"
    gosum = "github.com/pkg/errors v0.9.1 h1:abc=\ngithub.com/pkg/errors v0.9.1/go.mod h1:def=\n"
    assert names(ingest.parse_go_sum(gosum)) == {("Go", "github.com/pkg/errors", "0.9.1")}
    cargo = '[[package]]\nname = "app"\nversion = "0.1.0"\n\n[[package]]\nname = "serde"\nversion = "1.0.190"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
    assert names(ingest.parse_cargo_lock(cargo)) == {("crates.io", "serde", "1.0.190")}
    gem = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.3)\n      something (>= 1.0)\n    rails (6.1.0)\n\nDEPENDENCIES\n  rails\n"
    assert names(ingest.parse_gemfile_lock(gem)) == {("RubyGems", "rack", "2.2.3"), ("RubyGems", "rails", "6.1.0")}
    composer = json.dumps({"packages": [{"name": "monolog/monolog", "version": "v2.9.1"}], "packages-dev": [{"name": "phpunit/phpunit", "version": "9.6.0"}]})
    c = {x.name: x for x in ingest.parse_composer_lock(composer).components}
    assert c["monolog/monolog"].version == "2.9.1" and c["phpunit/phpunit"].scope == "dev"
    nuget = json.dumps({"version": 1, "dependencies": {"net8.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "12.0.1"},
                                                                  "System.Text.Json": {"type": "Transitive", "resolved": "8.0.0"}}}})
    c = {x.name: x for x in ingest.parse_nuget_lock(nuget).components}
    assert c["Newtonsoft.Json"].direct and not c["System.Text.Json"].direct
    gradle = "# comment\norg.apache.logging.log4j:log4j-core:2.14.1=compileClasspath,runtimeClasspath\njunit:junit:4.13=testCompileClasspath\nempty=\n"
    c = {x.name: x for x in ingest.parse_gradle_lockfile(gradle).components}
    assert c["org.apache.logging.log4j:log4j-core"].purl == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    assert c["junit:junit"].scope == "dev"


TRIVY = {"SchemaVersion": 2, "ArtifactName": "shop", "Results": [
    {"Target": "package-lock.json", "Type": "npm", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2024-45590", "PkgName": "body-parser", "InstalledVersion": "1.20.2", "FixedVersion": "1.20.3",
         "Severity": "HIGH", "CVSS": {"nvd": {"V3Score": 7.5}, "ghsa": {"V3Score": 7.5}},
         "PkgIdentifier": {"PURL": "pkg:npm/body-parser@1.20.2"}},
        {"VulnerabilityID": "CVE-2022-24999", "PkgName": "qs", "InstalledVersion": "6.5.2", "FixedVersion": "6.5.3, 6.2.4", "Severity": "HIGH"}]},
    {"Target": "app.jar", "Type": "jar", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2021-44228", "PkgName": "org.apache.logging.log4j:log4j-core", "InstalledVersion": "2.14.1", "Severity": "CRITICAL"}]},
    {"Target": "alpine", "Type": "alpine", "Vulnerabilities": [{"VulnerabilityID": "CVE-2023-0001", "PkgName": "musl", "InstalledVersion": "1.2.3-r0"}]}]}


def test_trivy_keeps_what_it_reported_and_says_what_it_dropped():
    p = ingest.parse_trivy(TRIVY)
    c = {x.name: x for x in p.components}
    assert set(c) == {"body-parser", "qs", "org.apache.logging.log4j:log4j-core"}
    assert c["body-parser"].reported == [Reported(id="CVE-2024-45590", cvss=7.5, severity="HIGH", fixed="1.20.3")]
    assert c["qs"].reported[0].fixed == "6.5.3" and c["org.apache.logging.log4j:log4j-core"].ecosystem == "Maven"
    assert any("alpine" in n for n in p.notes)


def test_grype_osv_scanner_snyk_and_dependency_check():
    grype = {"descriptor": {"name": "grype"}, "matches": [
        {"artifact": {"name": "lodash", "version": "4.17.20", "type": "npm", "purl": "pkg:npm/lodash@4.17.20"},
         "vulnerability": {"id": "GHSA-35jh-r3h4-6jhm", "severity": "High", "fix": {"versions": ["4.17.21"]},
                           "cvss": [{"metrics": {"baseScore": 7.2}}]}},
        {"artifact": {"name": "openssl", "version": "3.0.1-r0", "type": "apk"}, "vulnerability": {"id": "CVE-2023-1"}}]}
    p = ingest.parse_grype(grype)
    assert [(c.name, c.reported[0].id, c.reported[0].cvss, c.reported[0].fixed) for c in p.components] == [
        ("lodash", "GHSA-35jh-r3h4-6jhm", 7.2, "4.17.21")] and any("1건" in n for n in p.notes)
    osv = {"results": [{"source": {"path": "go.mod"}, "packages": [
        {"package": {"name": "golang.org/x/net", "version": "0.7.0", "ecosystem": "Go"}, "vulnerabilities": [{"id": "GO-2023-1571"}]}]}]}
    [c] = ingest.parse_osv_scanner(osv).components
    assert (c.ecosystem, c.version, c.reported[0].id) == ("Go", "0.7.0", "GO-2023-1571")
    snyk = {"packageManager": "maven", "projectName": "x", "vulnerabilities": [
        {"id": "SNYK-JAVA-1", "packageName": "com.fasterxml.jackson.core:jackson-databind", "version": "2.9.8",
         "identifiers": {"CVE": ["CVE-2019-12086"]}, "cvssScore": 7.5, "severity": "high", "fixedIn": ["2.9.9"]}]}
    [c] = ingest.parse_snyk(snyk).components
    assert c.ecosystem == "Maven" and c.reported == [Reported(id="CVE-2019-12086", cvss=7.5, severity="high", fixed="2.9.9")]
    odc = {"reportSchema": "1.1", "dependencies": [
        {"fileName": "a.jar", "packages": [{"id": "pkg:maven/commons-io/commons-io@2.6"}],
         "vulnerabilities": [{"name": "CVE-2021-29425", "severity": "MEDIUM", "cvssv3": {"baseScore": 4.8}}]},
        {"fileName": "b.dll", "vulnerabilities": [{"name": "CVE-2020-1"}]}]}
    p = ingest.parse_dependency_check(odc)
    assert p.components[0].reported[0].cvss == 4.8 and any("1개" in n for n in p.notes)


def test_cyclonedx_xml_and_spdx_tag_value(tmp_path):
    xml = '''<?xml version="1.0"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <metadata><component type="application" bom-ref="app"><name>shop</name></component></metadata>
  <components>
    <component type="library" bom-ref="e"><name>express</name><version>4.18.0</version><purl>pkg:npm/express@4.18.0</purl></component>
    <component type="library" bom-ref="q"><name>qs</name><version>6.5.2</version><purl>pkg:npm/qs@6.5.2</purl><scope>optional</scope></component>
  </components>
  <dependencies><dependency ref="app"><dependency ref="e"/></dependency><dependency ref="e"><dependency ref="q"/></dependency></dependencies>
  <vulnerabilities><vulnerability><id>CVE-2022-24999</id><ratings><rating><score>7.5</score><severity>high</severity></rating></ratings>
    <affects><target><ref>q</ref></target></affects></vulnerability></vulnerabilities>
</bom>'''
    (tmp_path / "bom.xml").write_text(xml)
    bom, source, _ = ingest.load(tmp_path / "bom.xml")
    c = {x.name: x for x in sbom.components_from_cyclonedx(bom)}
    assert source == "file:cyclonedx-xml" and c["express"].direct and c["qs"].paths == [["express", "qs"]] and c["qs"].scope == "dev"
    assert c["qs"].reported == [Reported(id="CVE-2022-24999", cvss=7.5, severity="HIGH")]
    spdx = '''SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: shop

PackageName: shop
SPDXID: SPDXRef-root
PackageVersion: 1.0.0

PackageName: flask
SPDXID: SPDXRef-flask
PackageVersion: 2.0.1
ExternalRef: PACKAGE-MANAGER purl pkg:pypi/flask@2.0.1

Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-root
Relationship: SPDXRef-root DEPENDS_ON SPDXRef-flask
'''
    (tmp_path / "bom.spdx").write_text(spdx)
    bom, source, _ = ingest.load(tmp_path / "bom.spdx")
    [c] = sbom.components_from_cyclonedx(bom)
    assert source == "file:spdx-tag-value" and (c.ecosystem, c.name, c.version, c.direct) == ("PyPI", "flask", "2.0.1", True)


def test_a_table_is_read_by_its_headers_korean_included(tmp_path):
    text = "오픈소스명,버전,언어,CVE 번호,심각도,조치 버전\nlodash,4.17.20,JavaScript,CVE-2021-23337,High,4.17.21\nlog4j-core,2.14.1,Java,CVE-2021-44228,Critical,2.15.0\nrequests,2.25.0,Python,\"CVE-2023-32681, CVE-2024-35195\",Medium,\n,1.0,Python,,,\n"
    p = ingest.parse_table(text)
    c = {x.name: x for x in p.components}
    assert set(c) == {"lodash", "requests"}                        # Maven needs a group; that row is counted as skipped
    assert c["lodash"].reported == [Reported(id="CVE-2021-23337", severity="High", fixed="4.17.21")]
    assert [r.id for r in c["requests"].reported] == ["CVE-2023-32681", "CVE-2024-35195"] and c["requests"].ecosystem == "PyPI"
    assert any("뺐습니다" in n for n in p.notes) and any("name=오픈소스명" in n for n in p.notes)
    (tmp_path / "list.csv").write_bytes("패키지;버전\nexpress;4.18.0\n".encode("cp949"))
    with pytest.raises(ingest.UnsupportedInput):                   # no ecosystem anywhere: say so instead of guessing
        ingest.parse_file(tmp_path / "list.csv")
    assert names(ingest.parse_file(tmp_path / "list.csv", ecosystem="npm")) == {("npm", "express", "4.18.0")}


def test_columns_can_be_named_for_a_format_nobody_has_seen(tmp_path):
    rows = {"items": [{"lib": "jackson-databind", "grp": "com.fasterxml.jackson.core", "v": "2.9.8", "kind": "maven", "issue": "CVE-2019-12086"},
                      {"lib": "left-pad", "grp": "", "v": "1.3.0", "kind": "npm", "issue": ""}]}
    (tmp_path / "export.json").write_text(json.dumps(rows))
    with pytest.raises(ingest.UnsupportedInput) as e:
        ingest.parse_file(tmp_path / "export.json")
    assert "--columns" in str(e.value) and "lib" in str(e.value)    # the message lists the columns it found
    cols = {"name": "lib", "group": "grp", "version": "v", "ecosystem": "kind", "vuln": "issue"}
    c = {x.name: x for x in ingest.parse_file(tmp_path / "export.json", columns=cols).components}
    assert c["com.fasterxml.jackson.core:jackson-databind"].reported[0].id == "CVE-2019-12086" and c["left-pad"].ecosystem == "npm"
    with pytest.raises(ingest.UnsupportedInput):
        ingest.parse_file(tmp_path / "export.json", columns={"name": "nope", "version": "v"})


def test_unreadable_inputs_say_what_to_do(tmp_path):
    cases = {"audit.json": json.dumps({"auditReportVersion": 2, "vulnerabilities": {}}), "x.sarif.json": json.dumps({"runs": []}),
             "kev.json": json.dumps({"catalogVersion": "1", "vulnerabilities": []}), "odd.json": json.dumps({"a": 1}),
             "broken.json": "{not json", "page.xml": "<html></html>", "notes.dat": "hello"}
    for name, text in cases.items():
        (tmp_path / name).write_text(text)
        d = ingest.describe(tmp_path / name)
        assert d["supported"] is False and d["why"], name
    assert "package-lock.json" in ingest.describe(tmp_path / "audit.json")["why"]
    assert "seed --kev" in ingest.describe(tmp_path / "kev.json")["why"]
    (tmp_path / "book.xlsx").write_bytes(b"PK\x03\x04")
    assert "CSV" in ingest.describe(tmp_path / "book.xlsx")["why"]


def test_a_repository_without_package_lock_is_still_read(tmp_path):
    (tmp_path / "yarn.lock").write_text('lodash@^4.17.20:\n  version "4.17.20"\n')
    assert [c.name for c in sbom.lockfile_components(tmp_path)] == ["lodash"]
    mono = tmp_path / "mono"
    (mono / "api").mkdir(parents=True)
    (mono / "web" / "node_modules" / "x").mkdir(parents=True)
    (mono / "api" / "requirements.txt").write_text("flask==2.0.1\n")
    (mono / "api" / "go.mod").write_text("require github.com/pkg/errors v0.9.1\n")
    (mono / "api" / "go.sum").write_text("github.com/pkg/errors v0.9.0 h1:x=\n")           # shadowed by go.mod
    (mono / "web" / "yarn.lock").write_text('qs@6.5.2:\n  version "6.5.2"\n')
    (mono / "web" / "node_modules" / "x" / "yarn.lock").write_text('evil@1:\n  version "1.0.0"\n')
    comps, notes = ingest.repo_components(mono)
    assert {(c.ecosystem, c.name, c.version) for c in comps} == {("PyPI", "flask", "2.0.1"), ("Go", "github.com/pkg/errors", "0.9.1"), ("npm", "qs", "6.5.2")}
    assert "여러 개" in notes[0]
    bom, source = sbom.generate(mono, use_syft=False)
    assert source == "lockfile" and len(bom["components"]) == 3


def test_reported_vulnerabilities_survive_the_cyclonedx_round_trip():
    comp = ingest.component("npm", "qs", "6.5.2", reported=[Reported(id="CVE-2022-24999", cvss=7.5, severity="HIGH", fixed="6.5.3")])
    bom = sbom.to_cyclonedx([comp], "trivy")
    assert bom["vulnerabilities"][0]["affects"] == [{"ref": "pkg:npm/qs@6.5.2"}]
    [back] = sbom.components_from_cyclonedx(bom)
    assert back.reported == comp.reported
    vex = {"bomFormat": "CycloneDX", "components": [{"bom-ref": "c1", "name": "qs", "version": "6.5.2", "purl": "pkg:npm/qs@6.5.2"}],
           "vulnerabilities": [{"id": "CVE-2022-24999", "ratings": [{"severity": "high"}], "affects": [{"ref": "urn:cdx:abc/1#c1"}]}]}
    assert sbom.components_from_cyclonedx(vex)[0].reported == [Reported(id="CVE-2022-24999", severity="HIGH")]


def offline(monkeypatch, responses):
    monkeypatch.setattr(cache, "fetch_json", lambda url, data=None, **kw: responses(url, data))


def test_scan_keeps_what_the_input_reported_when_osv_is_unreachable(monkeypatch):
    offline(monkeypatch, lambda url, data: None)                    # no network, empty cache
    comp = ingest.component("npm", "qs", "6.5.2", reported=[Reported(id="CVE-2022-24999", severity="HIGH", fixed="6.5.3")])
    findings, coverage = scan.scan([comp], None)
    [f] = findings
    assert (f.id, f.cvss, f.cvss_source, f.fixed_in, f.bump) == ("CVE-2022-24999@qs@6.5.2", 7.5, "label", "6.5.3", "patch")
    assert {"osv_detail", "epss", "kev", "source"} <= set(f.missing)
    assert coverage["osv"] is False and coverage["reported_by_input"] == 1 and coverage["only_in_input"] == 1
    with pytest.raises(RuntimeError):                               # nothing reported and no OSV: still an error
        scan.scan([ingest.component("npm", "qs", "6.5.2")], None)


def test_scan_does_not_double_count_what_osv_already_found(monkeypatch):
    detail = {"id": "GHSA-hrpp-h998-j3pp", "aliases": ["CVE-2022-24999"], "summary": "qs", "severity": [],
              "database_specific": {"severity": "HIGH"},
              "affected": [{"package": {"ecosystem": "npm", "name": "qs"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "6.5.3"}]}]}]}

    def responses(url, data):
        if url == scan.OSV_BATCH:
            return {"results": [{"vulns": [{"id": "GHSA-hrpp-h998-j3pp"}]}]}
        if url.endswith("GHSA-hrpp-h998-j3pp"):
            return detail
        return None                                                 # OSV has no record under the CVE id; EPSS and KEV are down
    offline(monkeypatch, responses)
    comp = ingest.component("npm", "qs", "6.5.2", reported=[Reported(id="CVE-2022-24999"), Reported(id="CVE-2099-0001", cvss=9.8)])
    findings, coverage = scan.scan([comp], None)
    assert [f.vuln_id for f in findings] == ["CVE-2022-24999", "CVE-2099-0001"]
    assert findings[0].summary == "qs" and findings[1].cvss == 9.8 and coverage["only_in_input"] == 1


def test_seeded_epss_file_fills_what_the_api_did_not_answer(monkeypatch, tmp_path):
    from triage import store
    from triage.enrich import epss
    from triage.store.files import FileStore
    monkeypatch.setattr(cache, "CACHE_DIR", tmp_path)
    monkeypatch.setenv("DEMO_MODE", "replay")
    store.use(FileStore())
    try:
        rows = epss.parse_csv("#model_version:v2025,score_date:2026-11-23\ncve,epss,percentile\nCVE-2022-24999,0.01234,0.85\nbad,row\n")
        assert rows == {"CVE-2022-24999": [0.01234, 0.85]}
        assert epss.lookup(["CVE-2022-24999"]) == {}
        cache.snapshot_put("epss", rows)
        assert epss.lookup(["CVE-2022-24999", "CVE-2000-0001"]) == {"CVE-2022-24999": (0.01234, 0.85)}
    finally:
        store.use(None)


def test_a_table_goes_through_the_whole_scan_and_the_run_says_what_the_input_lacked(monkeypatch, tmp_path):
    from triage import runner, store
    from triage.store.files import FileStore
    offline(monkeypatch, lambda url, data=None: None)
    monkeypatch.setattr(runner, "OUT", tmp_path / "out")
    store.use(FileStore())
    try:
        src = tmp_path / "list.csv"
        src.write_text("package,version,type,cve,severity\nqs,6.5.2,npm,CVE-2022-24999,CRITICAL\n")
        run = runner.scan(src, name="handed-over")
        meta = run.meta
        assert meta["sbom_source"] == "file:table" and meta["summary"]["findings"] == 1 and meta["repo"] is None
        assert meta["coverage"]["osv"] is False and any("name=package" in n for n in meta["coverage"]["input_notes"])
        assert run.findings()[0].cvss == 9.5 and run.triage()[0].rule_bucket in ("NOW", "NEXT", "MONITOR")
        assert src.read_text().startswith("package,version")          # the handed-over file is only read
    finally:
        store.use(None)


# ---------- review 2 (docs/reviews/design-critique-2.md) ----------

def test_osv_answers_are_refreshed_only_when_a_caller_asks(monkeypatch):
    seen = []

    def fetch(url, data=None, **kw):
        seen.append((url.split("/v1/")[-1].split("/")[0], kw.get("max_age")))
        return {"results": [{"vulns": []}]} if url == scan.OSV_BATCH else None
    monkeypatch.setattr(cache, "fetch_json", fetch)
    comp = ingest.component("npm", "qs", "6.5.2", reported=[Reported(id="CVE-2022-24999")])
    scan.scan([comp], None)
    assert ("querybatch", None) in seen and ("vulns", None) in seen           # a plain scan keeps cached answers
    seen.clear()
    scan.scan([comp], None, max_age=3600)
    assert ("querybatch", 3600) in seen and ("vulns", 3600) in seen            # a re-check asks again after an hour


def test_cached_osv_answer_is_fetched_again_once_it_is_older_than_max_age(monkeypatch, tmp_path):
    import os, time
    from triage import store
    from triage.store.files import FileStore
    monkeypatch.setattr(cache, "CACHE_DIR", tmp_path)
    monkeypatch.delenv("DEMO_MODE", raising=False)
    store.use(FileStore())
    try:
        body = {"queries": [{"package": {"ecosystem": "npm", "name": "qs"}, "version": "6.5.2"}]}
        cache.seed(scan.OSV_BATCH, {"results": [{"vulns": []}]}, body)
        path = tmp_path / f"{cache.key(scan.OSV_BATCH, body)}.json"
        os.utime(path, (time.time() - 40 * 86400,) * 2)

        class Client:
            def __init__(self, **kw): pass
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def post(self, url, json=None):
                class R:
                    def raise_for_status(self): pass
                    def json(self): return {"results": [{"vulns": [{"id": "GHSA-new"}]}]}
                return R()
        monkeypatch.setattr(cache.httpx, "Client", Client)
        comp = ingest.component("npm", "qs", "6.5.2")
        assert scan.query_osv([comp]) == []                                    # forty days old, still used
        assert [v for _, v in scan.query_osv([comp], max_age=3600)] == ["GHSA-new"]
    finally:
        store.use(None)


def test_dependency_files_below_the_root_and_beside_each_other_are_all_read(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"devDependencies": {"husky": "^8"}}, "node_modules/husky": {"version": "8.0.0", "dev": True}}}))
    pom = '<project><dependencies><dependency><groupId>g</groupId><artifactId>{a}</artifactId><version>1.0</version></dependency></dependencies></project>'
    (tmp_path / "pom.xml").write_text("<project><modules><module>api</module></modules></project>")   # parent of a multi-module build
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "pom.xml").write_text(pom.format(a="api-lib"))
    (tmp_path / "py").mkdir()
    (tmp_path / "py" / "requirements.txt").write_text("-r base.txt\nflask==2.0.1\n")
    (tmp_path / "jvm").mkdir()
    (tmp_path / "jvm" / "pom.xml").write_text(pom.format(a="ignored"))
    (tmp_path / "jvm" / "gradle.lockfile").write_text("g:resolved:2.0=runtimeClasspath\n")
    comps, notes = ingest.repo_components(tmp_path)
    assert {c.name for c in comps} == {"husky", "g:api-lib", "flask", "g:resolved"}
    assert any("-r, -c" in n for n in notes) and "여러 개" in notes[0] and "api/pom.xml" in notes[0]


def test_yarn_lock_uses_the_package_json_beside_it(tmp_path):
    (tmp_path / "yarn.lock").write_text('ejs@^3.1.6:\n  version "3.1.6"\n\njest@^29.0.0:\n  version "29.0.0"\n\nansi@^1:\n  version "1.0.0"\n')
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"ejs": "^3.1.6"}, "devDependencies": {"jest": "^29.0.0"}}))
    c = {x.name: x for x in ingest.repo_components(tmp_path)[0]}
    assert (c["ejs"].scope, c["ejs"].direct) == ("prod", True) and (c["jest"].scope, c["jest"].direct) == ("dev", True)
    assert (c["ansi"].scope, c["ansi"].direct) == ("prod", False)
    berry = '"resolve@patch:resolve@^1.20.0#~builtin<compat/resolve>":\n  version: 1.22.0\n\n"lodash4@npm:lodash@^4.17.20":\n  version: 4.17.21\n'
    assert names(ingest.parse_yarn_lock(berry)) == {("npm", "lodash", "4.17.21")}


def test_go_mod_blocks_and_gem_platforms():
    gomod = "module x\n\nrequire a.io/used v1.2.0\n\nreplace (\n\ta.io/b v1.0.0 => a.io/c v1.1.0\n)\n\nexclude (\n\tx.io/y v0.9.0\n)\nreplace a.io/d v1.0.0 => ../d\n"
    assert names(ingest.parse_go_mod(gomod)) == {("Go", "a.io/used", "1.2.0")}
    gem = "GEM\n  specs:\n    nokogiri (1.15.4-x86_64-linux)\n    rails (7.0.0.rc1)\n"
    assert names(ingest.parse_gemfile_lock(gem)) == {("RubyGems", "nokogiri", "1.15.4"), ("RubyGems", "rails", "7.0.0.rc1")}


def test_trivy_package_list_gives_scope_and_direct_to_the_vulnerability_rows():
    doc = {"SchemaVersion": 2, "Results": [{"Type": "npm", "Packages": [
        {"Name": "jest", "Version": "29.0.0", "Dev": True, "Relationship": "direct", "Identifier": {"PURL": "pkg:npm/jest@29.0.0"}},
        {"Name": "qs", "Version": "6.5.2", "Relationship": "indirect", "Identifier": {"PURL": "pkg:npm/qs@6.5.2"}}],
        "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-1", "PkgName": "jest", "InstalledVersion": "29.0.0",
                             "PkgIdentifier": {"PURL": "pkg:npm/jest@29.0.0"}}]}]}
    p = ingest.parse_trivy(doc)
    c = {x.name: x for x in p.components}
    assert (c["jest"].scope, c["jest"].direct, c["jest"].reported[0].id) == ("dev", True, "CVE-2024-1")
    assert (c["qs"].scope, c["qs"].direct) == ("prod", False) and not any("구분" in n for n in p.notes)


def test_snyk_licence_items_and_unknown_managers_are_counted_not_turned_into_findings():
    doc = {"packageManager": "gomodules", "projectName": "x", "vulnerabilities": [
        {"id": "snyk:lic:golang:foo:GPL-3.0", "type": "license", "packageName": "foo", "version": "1.0.0", "severity": "medium"},
        {"id": "SNYK-GOLANG-1", "packageName": "golang.org/x/net", "version": "0.7.0", "identifiers": {"CVE": ["CVE-2023-44487"]},
         "from": ["app@1.0.0", "golang.org/x/net@0.7.0"]},
        {"id": "SNYK-X-2", "packageName": "thing", "version": "1.0.0", "packageManager": "cocoapods"}]}
    p = ingest.parse_snyk(doc)
    [c] = p.components
    assert (c.ecosystem, c.name, c.direct, c.reported[0].id) == ("Go", "golang.org/x/net", True, "CVE-2023-44487")
    assert any("라이선스" in n and "1건" in n for n in p.notes) and any("cocoapods" in n for n in p.notes)


def test_a_table_keeps_vulnerability_numbers_of_other_schemes_and_says_so():
    text = "package,version,type,vuln,severity\nejs,3.1.6,npm,KVE-2023-0001,High\nlodash,4.17.20,npm,\"SNYK-JS-LODASH-1, ghsa-35JH-r3h4-6jhm\",High\nqs,6.5.2,npm,없음,\n"
    p = ingest.parse_table(text)
    c = {x.name: x for x in p.components}
    assert [r.id for r in c["ejs"].reported] == ["KVE-2023-0001"] and c["qs"].reported == []
    assert [r.id for r in c["lodash"].reported] == ["GHSA-35jh-r3h4-6jhm", "SNYK-JS-LODASH-1"]
    assert any("2건" in n and "그대로" in n for n in p.notes)


def test_vex_entries_marked_not_affected_are_not_reported(tmp_path):
    bom = {"bomFormat": "CycloneDX", "components": [{"bom-ref": "c1", "name": "log4j-core", "version": "2.14.1",
                                                    "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}],
           "vulnerabilities": [{"id": "CVE-2021-44228", "analysis": {"state": "not_affected"}, "affects": [{"ref": "c1"}]},
                               {"id": "CVE-2021-45046", "analysis": {"state": "exploitable"}, "affects": [{"ref": "c1"}]}]}
    assert [r.id for r in sbom.components_from_cyclonedx(bom)[0].reported] == ["CVE-2021-45046"]
    (tmp_path / "vex.json").write_text(json.dumps(bom))
    assert any("1건" in n for n in ingest.load(tmp_path / "vex.json")[2])
    xml = '''<bom xmlns="http://cyclonedx.org/schema/bom/1.5"><components>
<component type="library" bom-ref="q"><name>qs</name><version>6.5.2</version><purl>pkg:npm/qs@6.5.2</purl></component></components>
<vulnerabilities><vulnerability><id>CVE-2022-24999</id><analysis><state>false_positive</state></analysis>
<affects><target><ref>q</ref></target></affects></vulnerability></vulnerabilities></bom>'''
    (tmp_path / "bom.xml").write_text(xml)
    b, _, notes = ingest.load(tmp_path / "bom.xml")
    assert sbom.components_from_cyclonedx(b)[0].reported == [] and any("1건" in n for n in notes)


LOG4SHELL = {"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"], "summary": "Remote code injection in Log4j",
             "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
             "affected": [{"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"}}]}


def test_a_claim_that_names_another_packages_advisory_is_marked_and_not_raised_by_kev(monkeypatch):
    from triage import score
    from triage.agent import run as agent_run
    from triage.enrich import kev

    def responses(url, data):
        if url == scan.OSV_BATCH:
            return {"results": [{"vulns": []} for _ in data["queries"]]}
        if url.endswith("GHSA-jfh8-c2jp-5v3q"):
            return LOG4SHELL
        if url == kev.URL:
            return {"catalogVersion": "t", "vulnerabilities": [{"cveID": "CVE-2021-44228"}]}
        return None
    offline(monkeypatch, responses)
    wrong = ingest.component("npm", "left-pad", "1.3.0", reported=[Reported(id="GHSA-jfh8-c2jp-5v3q")])
    right = ingest.component("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", reported=[Reported(id="GHSA-jfh8-c2jp-5v3q")])
    fw, fr = scan.scan([wrong, right], None)[0]
    assert (fw.source, fw.kev, "osv_mismatch" in fw.missing) == ("input", True, True)
    assert (fr.source, "osv_mismatch" in fr.missing) == ("input", False)        # the advisory does list this package
    rw, rr = score.score(fw), score.score(fr)
    assert rw.bucket != "NOW" and rw.risk_breakdown["exploit"] < 25 and score.floor(fw) is None
    assert rr.bucket == "NOW" and score.floor(fr) == "NOW"
    tw, tr = agent_run.run([fw, fr], None, None, pathlib.Path("."))
    assert tw.needs_review and tw.final_bucket != "NOW"                         # left to a person, not raised by itself


def test_findings_say_whether_osv_the_input_or_both_reported_them(monkeypatch):
    detail = {"id": "GHSA-hrpp-h998-j3pp", "aliases": ["CVE-2022-24999"], "affected": [{"package": {"ecosystem": "npm", "name": "qs"}}]}

    def responses(url, data):
        if url == scan.OSV_BATCH:
            return {"results": [{"vulns": [{"id": "GHSA-hrpp-h998-j3pp"}]}, {"vulns": [{"id": "GHSA-hrpp-h998-j3pp"}]}]}
        return detail if url.endswith("GHSA-hrpp-h998-j3pp") else None
    offline(monkeypatch, responses)
    a = ingest.component("npm", "qs", "6.5.2", reported=[Reported(id="CVE-2022-24999"), Reported(id="KVE-2023-0001", severity="HIGH")])
    b = ingest.component("npm", "qs", "6.5.1")
    by = {(f.version, f.vuln_id): f.source for f in scan.scan([a, b], None)[0]}
    assert by == {("6.5.2", "CVE-2022-24999"): "both", ("6.5.2", "KVE-2023-0001"): "input", ("6.5.1", "CVE-2022-24999"): "osv"}
