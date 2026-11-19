import json

from triage import sbom
from triage.enrich import semver

LOCK = {"lockfileVersion": 3, "packages": {
    "": {"dependencies": {"express": "^4"}, "devDependencies": {"jest": "^29"}},
    "node_modules/express": {"version": "4.18.0", "dependencies": {"qs": "6.5.2"}},
    "node_modules/qs": {"version": "6.5.2"},
    "node_modules/jest": {"version": "29.0.0", "dev": True, "dependencies": {"@scope/util": "1.0.0"}},
    "node_modules/@scope/util": {"version": "1.0.0", "dev": True},
}}


def by_name(comps):
    return {c.name: c for c in comps}


def test_npm_lock_scope_direct_paths():
    c = by_name(sbom.npm_lock_components(LOCK))
    assert c["express"].direct and c["express"].scope == "prod"
    assert not c["qs"].direct and c["qs"].paths == [["express", "qs"]]
    assert c["jest"].scope == "dev" and c["@scope/util"].paths == [["jest", "@scope/util"]]


def test_cyclonedx_roundtrip_keeps_metadata():
    comps = sbom.npm_lock_components(LOCK)
    back = by_name(sbom.components_from_cyclonedx(sbom.to_cyclonedx(comps, "lockfile")))
    assert back["qs"].paths == [["express", "qs"]] and back["jest"].scope == "dev"
    assert back["@scope/util"].purl == "pkg:npm/%40scope/util@1.0.0"


def test_plain_cyclonedx_uses_dependency_graph():
    bom = {"bomFormat": "CycloneDX", "metadata": {"component": {"bom-ref": "app"}},
           "components": [{"bom-ref": "a", "name": "a", "version": "1.0.0", "purl": "pkg:npm/a@1.0.0"},
                          {"bom-ref": "b", "name": "b", "version": "2.0.0", "purl": "pkg:npm/b@2.0.0", "scope": "optional"}],
           "dependencies": [{"ref": "app", "dependsOn": ["a"]}, {"ref": "a", "dependsOn": ["b"]}]}
    c = by_name(sbom.components_from_cyclonedx(bom))
    assert c["a"].direct and not c["b"].direct and c["b"].paths == [["a", "b"]] and c["b"].scope == "dev"


def test_spdx_file(tmp_path):
    doc = {"spdxVersion": "SPDX-2.3", "documentDescribes": ["SPDXRef-app"],
           "packages": [{"SPDXID": "SPDXRef-app", "name": "app"},
                        {"SPDXID": "SPDXRef-l", "name": "log4j-core", "versionInfo": "2.14.1",
                         "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]}],
           "relationships": [{"spdxElementId": "SPDXRef-app", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-l"}]}
    p = tmp_path / "bom.spdx.json"
    p.write_text(json.dumps(doc))
    bom, source = sbom.load_file(p)
    [c] = sbom.components_from_cyclonedx(bom)
    assert source == "file:spdx" and c.ecosystem == "Maven" and c.name == "org.apache.logging.log4j:log4j-core" and c.direct


POM = """<project xmlns="http://maven.apache.org/POM/4.0.0"><version>1.0</version>
<properties><log4j.version>2.14.1</log4j.version></properties>
<dependencies>
 <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>${log4j.version}</version></dependency>
 <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.12</version><scope>test</scope></dependency>
 <dependency><groupId>x</groupId><artifactId>managed</artifactId></dependency>
</dependencies></project>"""


def test_maven_pom():
    c = by_name(sbom.maven_pom_components(POM))
    assert c["org.apache.logging.log4j:log4j-core"].version == "2.14.1"
    assert c["junit:junit"].scope == "dev" and "x:managed" not in c


def test_semver():
    assert semver.bump("1.2.3", "1.2.9") == "patch" and semver.bump("1.2.3", "2.0.0") == "major"
    assert semver.lt("4.0.4", "4.0.6") and semver.lt("2.0.0-rc.1", "2.0.0")
    assert semver.fixed_in(["1.0.5", "2.0.1", "0.9.0"], "1.0.0") == "1.0.5"
    assert semver.fixed_max(["1.0.5", "2.0.1", "0.9.0"], "1.0.0") == "2.0.1"


def test_purl_ecosystems():
    assert sbom.parse_purl("pkg:pypi/Django_Rest.framework@3.14.0") == ("PyPI", "django-rest-framework", "3.14.0")
    assert sbom.parse_purl("pkg:golang/golang.org/x/net@v0.17.0") == ("Go", "golang.org/x/net", "0.17.0")
    assert sbom.parse_purl("pkg:cargo/tokio@1.28.0") == ("crates.io", "tokio", "1.28.0")
    assert sbom.parse_purl("pkg:nuget/Newtonsoft.Json@12.0.1") == ("NuGet", "Newtonsoft.Json", "12.0.1")
    assert sbom.parse_purl("pkg:npm/%40scope/util@1.0.0?x=1") == ("npm", "@scope/util", "1.0.0")
    assert sbom.parse_purl("pkg:deb/debian/openssl@1.1.1") is None


def test_unsupported_components_are_counted_not_dropped_silently():
    bom = {"components": [{"purl": "pkg:pypi/flask@2.0.0"}, {"purl": "pkg:deb/debian/openssl@1.1.1"},
                          {"purl": "pkg:deb/debian/zlib@1.2"}, {"name": "no-purl"}]}
    assert sbom.unsupported_purls(bom) == {"deb": 2, "none": 1}
    assert [c.ecosystem for c in sbom.components_from_cyclonedx(bom)] == ["PyPI"]


def test_spdx_package_without_purl_is_counted_not_dropped():
    from triage import sbom
    doc = {"packages": [{"SPDXID": "SPDXRef-root", "name": "app", "versionInfo": "1.0.0"},
                        {"SPDXID": "SPDXRef-a", "name": "lodash", "versionInfo": "4.17.20"},
                        {"SPDXID": "SPDXRef-b", "name": "ms", "versionInfo": "2.0.0",
                         "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/ms@2.0.0"}]}],
           "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-root"}]}
    bom = sbom.spdx_to_cyclonedx(doc)
    assert sbom.unsupported_purls(bom) == {"none": 1}
    assert [c.name for c in sbom.components_from_cyclonedx(bom)] == ["ms"]


def test_four_part_versions_and_prerelease_numbers():
    from triage.enrich import semver
    assert semver.fixed_in(["2.13.4.2"], "2.13.4") == "2.13.4.2"
    assert semver.lt("2.13.4.1", "2.13.4.2") and not semver.lt("2.13.4.2", "2.13.4.2")
    assert semver.lt("1.0.0-rc.9", "1.0.0-rc.10") and semver.lt("1.0.0-rc.10", "1.0.0")
    assert semver.lt("5.3.9.RELEASE", "5.3.10.RELEASE") and semver.bump("1.2.3", "2.0.0") == "major"
