"""Input formats beyond CycloneDX and SPDX JSON (finals data may arrive in any shape).

Everything is reduced to the one thing the pipeline needs: a list of package@version with an
ecosystem (`Component`). Vulnerabilities the input itself reports (scanner results, a CycloneDX
`vulnerabilities` section, a CVE column in a table) ride along on the component as `reported`, so
the scan can keep them even when OSV does not know them or cannot be reached.

Three kinds of input:
- dependency files: yarn.lock, pnpm-lock.yaml, requirements.txt, poetry.lock, uv.lock, Pipfile.lock,
  go.mod, go.sum, Cargo.lock, Gemfile.lock, composer.lock, packages.lock.json, gradle.lockfile
  (package-lock.json and pom.xml are in sbom.py)
- SBOM variants and scanner results: CycloneDX XML, SPDX tag-value, Trivy, Grype, OSV-Scanner,
  Snyk, OWASP Dependency-Check
- tables and record lists: CSV, TSV, or a JSON array of objects. Columns are guessed from their
  headers and can be named outright (`columns={"name": "Package", ...}`), which is the way to read
  a format nobody has seen before without writing a parser.

To add a format: write `parse_x(text) -> Parsed`, add a line to BY_NAME (matched by file name) or
to `_sniff` (matched by content), and add a test with a cut-down sample. Parsers are pure: no I/O,
no network, never raise for a row they cannot read (skip it and say so in `notes`).
"""
from __future__ import annotations

import csv
import dataclasses
import io
import json
import pathlib
import re
import tomllib
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Callable

from . import sbom
from .models import Component, Reported

SKIP_DIRS = {".git", "node_modules", "target", "build", "dist", ".gradle", ".venv", "venv", "__pycache__", "vendor"}
MAX_BYTES = 200_000_000

# what people and tools call an ecosystem -> the OSV name the pipeline uses
ECOSYSTEMS = {
    "npm": "npm", "node": "npm", "nodejs": "npm", "node.js": "npm", "javascript": "npm", "js": "npm", "yarn": "npm",
    "pnpm": "npm", "node-pkg": "npm", "typescript": "npm",
    "pypi": "PyPI", "pip": "PyPI", "python": "PyPI", "poetry": "PyPI", "pipenv": "PyPI", "python-pkg": "PyPI", "uv": "PyPI",
    "maven": "Maven", "gradle": "Maven", "java": "Maven", "jar": "Maven", "pom": "Maven", "java-archive": "Maven",
    "kotlin": "Maven", "jvm": "Maven",
    "go": "Go", "golang": "Go", "gomod": "Go", "gobinary": "Go", "go-module": "Go",
    "cargo": "crates.io", "rust": "crates.io", "crates.io": "crates.io", "rust-crate": "crates.io",
    "nuget": "NuGet", "dotnet": "NuGet", ".net": "NuGet", "dotnet-core": "NuGet", "c#": "NuGet",
    "gem": "RubyGems", "bundler": "RubyGems", "ruby": "RubyGems", "rubygems": "RubyGems", "gemspec": "RubyGems",
    "composer": "Packagist", "php": "Packagist", "packagist": "Packagist", "php-composer": "Packagist",
}
PURL_TYPE = {"npm": "npm", "PyPI": "pypi", "Maven": "maven", "Go": "golang", "crates.io": "cargo", "NuGet": "nuget",
             "RubyGems": "gem", "Packagist": "composer"}
VULN_ID = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d+|GO-\d{4}-\d+|RUSTSEC-\d{4}-\d+)\b", re.I)


@dataclasses.dataclass
class Parsed:
    fmt: str
    components: list[Component] = dataclasses.field(default_factory=list)
    notes: list[str] = dataclasses.field(default_factory=list)   # what the input lacks, in the reader's language
    bom: dict | None = None            # set when the input already is (or converts straight to) CycloneDX


class UnsupportedInput(ValueError):
    """The file is not something the pipeline can turn into components; the message says what to do."""


def ecosystem_of(text: str | None) -> str | None:
    return ECOSYSTEMS.get((text or "").strip().lower())


def purl_for(eco: str, name: str, version: str) -> str:
    if eco == "npm":
        return sbom.npm_purl(name, version)
    if eco == "Maven":
        group, _, artifact = name.replace("/", ":").rpartition(":")
        return sbom.maven_purl(group, artifact, version)
    if eco == "PyPI":
        name = re.sub(r"[-_.]+", "-", name).lower()
    return f"pkg:{PURL_TYPE[eco]}/{name}@{version}"


def component(eco: str, name: str, version: str, scope: str = "prod", direct: bool = False,
              reported: list[Reported] | None = None) -> Component | None:
    """None for a row that cannot be looked up (no name, no exact version, Maven without a group)."""
    name, version = (name or "").strip(), (version or "").strip().lstrip("=").strip()
    if eco == "Go":
        version = version.removeprefix("v")
    if eco == "Maven":
        name = name.replace("/", ":")
    if not name or not version or re.search(r"[\s<>^~*|,]", version) or (eco == "Maven" and ":" not in name):
        return None
    if eco == "PyPI":
        name = re.sub(r"[-_.]+", "-", name).lower()
    return Component(name=name, version=version, ecosystem=eco, purl=purl_for(eco, name, version), scope=scope,
                     direct=direct, paths=[[name]] if direct else [], reported=reported or [])


def _merge(components: list[Component | None]) -> list[Component]:
    """One component per purl: prod wins over dev, direct over transitive, reported lists are joined."""
    out: dict[str, Component] = {}
    for c in components:
        if c is None:
            continue
        prev = out.get(c.purl)
        if prev is None:
            out[c.purl] = c
            continue
        seen = {r.id for r in prev.reported}
        out[c.purl] = prev.model_copy(update={
            "scope": "prod" if "prod" in (prev.scope, c.scope) else "dev", "direct": prev.direct or c.direct,
            "paths": prev.paths or c.paths, "reported": prev.reported + [r for r in c.reported if r.id not in seen]})
    return list(out.values())


def _skipped(total: int, kept: int, what: str = "항목") -> list[str]:
    return [f"{what} {total}개 중 {total - kept}개는 이름이나 정확한 버전이 없어 뺐습니다."] if total > kept else []


NO_GRAPH = "의존 관계 정보가 없어 직접 의존성과 간접 의존성을 구분하지 못합니다."
NO_SCOPE = "운영용과 개발용 구분이 없어 모두 운영 의존성으로 봅니다."


# ---------- dependency files ----------

def parse_yarn_lock(text: str) -> Parsed:
    rows, names = [], []
    for line in text.splitlines():
        if line and not line[0].isspace() and not line.startswith("#") and line.rstrip().endswith(":"):
            first = line.rstrip()[:-1].split(",")[0].strip().strip('"')
            at = first.rfind("@")                           # "@scope/name@^1.0.0" or "name@npm:^1.0.0"
            names = [first[:at]] if at > 0 else []
        elif names and (m := re.match(r'^\s+version:?\s+"?([^"\s]+)"?\s*$', line)):
            rows.append((names[0], m.group(1)))
            names = []
    rows = [(n, v) for n, v in rows if n != "__metadata" and not v.startswith("0.0.0-use.local")]
    comps = _merge([component("npm", n, v) for n, v in rows])
    return Parsed("yarn.lock", comps, [NO_GRAPH + " (package.json과 함께 보면 구분할 수 있습니다)", NO_SCOPE])


def parse_pnpm_lock(text: str) -> Parsed:
    import yaml
    doc = yaml.safe_load(text) or {}
    direct: set[str] = set()
    dev: set[str] = set()
    importers = doc.get("importers") or {".": doc}
    for imp in importers.values():
        for key, bucket in (("dependencies", direct), ("optionalDependencies", direct), ("devDependencies", dev)):
            bucket.update((imp or {}).get(key) or {})
    rows = []
    for key, meta in (doc.get("packages") or {}).items():
        key = str(key).lstrip("/").split("(")[0]
        at = key.rfind("@")
        name, version = (key[:at], key[at + 1:]) if at > 0 else key.rsplit("/", 1) if "/" in key else (key, "")
        version = version.split("_")[0]
        is_dev = bool((meta or {}).get("dev")) or (name in dev and name not in direct)
        rows.append(component("npm", name, version, "dev" if is_dev else "prod", name in direct or name in dev))
    return Parsed("pnpm-lock.yaml", _merge(rows), _skipped(len(rows), sum(r is not None for r in rows)))


def parse_requirements(text: str) -> Parsed:
    rows, loose = [], 0
    for line in text.splitlines():
        line = line.split("#")[0].split(";")[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9.!+_-]+)", line)
        if m:
            rows.append(component("PyPI", m.group(1), m.group(2), direct=True))
        else:
            loose += 1
    notes = [f"버전이 고정되지 않은(== 가 아닌) 줄 {loose}개는 어떤 버전이 설치되는지 알 수 없어 뺐습니다."] if loose else []
    return Parsed("requirements.txt", _merge(rows), notes + ["간접 의존성은 pip freeze 결과나 lock 파일이 있어야 보입니다.", NO_SCOPE])


def _toml_packages(text: str, eco: str, fmt: str, dev_key: Callable[[dict], bool] = lambda p: False) -> Parsed:
    pkgs = tomllib.loads(text).get("package", [])
    rows = [component(eco, p.get("name", ""), str(p.get("version", "")), "dev" if dev_key(p) else "prod")
            for p in pkgs if not str(p.get("source", "")).startswith(("path", "{'virtual", "{'editable"))]
    return Parsed(fmt, _merge(rows), [NO_GRAPH] + _skipped(len(rows), sum(r is not None for r in rows)))


def parse_poetry_lock(text: str) -> Parsed:
    return _toml_packages(text, "PyPI", "poetry.lock", lambda p: p.get("category") == "dev")


def parse_uv_lock(text: str) -> Parsed:
    doc = tomllib.loads(text)
    rows = [component("PyPI", p.get("name", ""), str(p.get("version", ""))) for p in doc.get("package", [])
            if not ({"virtual", "editable"} & set(p.get("source") or {}))]
    return Parsed("uv.lock", _merge(rows), [NO_GRAPH, NO_SCOPE])


def parse_cargo_lock(text: str) -> Parsed:
    doc = tomllib.loads(text)
    rows = [component("crates.io", p.get("name", ""), str(p.get("version", ""))) for p in doc.get("package", [])
            if p.get("source")]                                  # no source = the workspace's own crate
    return Parsed("Cargo.lock", _merge(rows), [NO_GRAPH, NO_SCOPE])


def parse_pipfile_lock(text: str) -> Parsed:
    doc = json.loads(text)
    rows = [component("PyPI", name, str((meta or {}).get("version", "")), scope)
            for key, scope in (("default", "prod"), ("develop", "dev")) for name, meta in (doc.get(key) or {}).items()]
    return Parsed("Pipfile.lock", _merge(rows), [NO_GRAPH] + _skipped(len(rows), sum(r is not None for r in rows)))


def parse_go_mod(text: str) -> Parsed:
    rows = []
    for line in re.sub(r"\brequire\s*\(", "", text).splitlines():
        m = re.match(r"^\s*(?:require\s+)?([\w./~-]+\.[\w./~-]+)\s+(v[\w.+-]+)(\s*//\s*indirect)?", line)
        if m:
            rows.append(component("Go", m.group(1), m.group(2), direct=not m.group(3)))
    return Parsed("go.mod", _merge(rows), [NO_SCOPE])


def parse_go_sum(text: str) -> Parsed:
    rows = {(p[0], p[1].removesuffix("/go.mod")) for line in text.splitlines() if len(p := line.split()) >= 2}
    comps = _merge([component("Go", n, v) for n, v in sorted(rows)])
    return Parsed("go.sum", comps, ["go.sum에는 실제로 쓰지 않는 버전도 들어 있어 건수가 부풀 수 있습니다. go.mod가 있으면 그쪽이 정확합니다.",
                                    NO_GRAPH, NO_SCOPE])


def parse_gemfile_lock(text: str) -> Parsed:
    rows = [component("RubyGems", m.group(1), m.group(2)) for line in text.splitlines()
            if (m := re.match(r"^ {4}([A-Za-z0-9_.-]+) \(([^)\s]+)\)\s*$", line))]
    return Parsed("Gemfile.lock", _merge(rows), [NO_GRAPH, NO_SCOPE])


def parse_composer_lock(text: str) -> Parsed:
    doc = json.loads(text)
    rows = [component("Packagist", p.get("name", ""), str(p.get("version", "")).removeprefix("v"), scope)
            for key, scope in (("packages", "prod"), ("packages-dev", "dev")) for p in doc.get(key) or []]
    return Parsed("composer.lock", _merge(rows), [NO_GRAPH] + _skipped(len(rows), sum(r is not None for r in rows)))


def parse_nuget_lock(text: str) -> Parsed:
    doc = json.loads(text)
    rows = [component("NuGet", name, str(meta.get("resolved", "")), direct=meta.get("type") == "Direct")
            for framework in (doc.get("dependencies") or {}).values() for name, meta in (framework or {}).items()
            if (meta or {}).get("type") != "Project"]
    return Parsed("packages.lock.json", _merge(rows), [NO_SCOPE])


def parse_gradle_lockfile(text: str) -> Parsed:
    rows = []
    for line in text.splitlines():
        m = re.match(r"^([\w.-]+):([\w.-]+):([^=\s]+)=(.*)$", line.strip())
        if m:
            test_only = all("test" in c.lower() for c in m.group(4).split(",") if c)
            rows.append(component("Maven", f"{m.group(1)}:{m.group(2)}", m.group(3), "dev" if test_only else "prod"))
    return Parsed("gradle.lockfile", _merge(rows), [NO_GRAPH])


def parse_package_lock(text: str) -> Parsed:
    return Parsed("package-lock.json", sbom.npm_lock_components(json.loads(text)))


def parse_pom(text: str) -> Parsed:
    return Parsed("pom.xml", sbom.maven_pom_components(text), ["pom.xml에서는 직접 의존성만 읽습니다. 간접 의존성은 SBOM 파일이나 Syft가 필요합니다."])


# file name -> parser. Order is the priority when a repository has several.
BY_NAME: dict[str, Callable[[str], Parsed]] = {
    "package-lock.json": parse_package_lock, "npm-shrinkwrap.json": parse_package_lock, "pnpm-lock.yaml": parse_pnpm_lock,
    "yarn.lock": parse_yarn_lock, "poetry.lock": parse_poetry_lock, "uv.lock": parse_uv_lock,
    "Pipfile.lock": parse_pipfile_lock, "requirements.txt": parse_requirements, "go.mod": parse_go_mod,
    "go.sum": parse_go_sum, "Cargo.lock": parse_cargo_lock, "Gemfile.lock": parse_gemfile_lock,
    "composer.lock": parse_composer_lock, "packages.lock.json": parse_nuget_lock, "gradle.lockfile": parse_gradle_lockfile,
    "pom.xml": parse_pom,
}
SHADOWED = {"go.sum": "go.mod", "requirements.txt": "poetry.lock"}   # skipped when the better file sits beside it


# ---------- scanner results ----------

def _score(value) -> float | None:
    try:
        s = float(value)
    except (TypeError, ValueError):
        return None
    return s if 0 <= s <= 10 else None


def _first_version(value) -> str | None:
    if isinstance(value, list):
        value = value[0] if value else None
    m = re.search(r"[0-9][A-Za-z0-9.+_-]*", str(value or ""))
    return m.group(0) if m else None


def _from_purl(purl: str | None, reported: list[Reported] | None = None) -> Component | None:
    parsed = sbom.parse_purl(purl or "")
    return component(parsed[0], parsed[1], parsed[2], reported=reported) if parsed else None


def parse_trivy(doc: dict) -> Parsed:
    rows, lost = [], Counter()
    for res in doc.get("Results") or []:
        eco = ecosystem_of(res.get("Type"))
        for p in res.get("Packages") or []:                      # present with --list-all-pkgs
            c = _from_purl((p.get("Identifier") or {}).get("PURL")) or (
                component(eco, p.get("Name", ""), p.get("Version", "")) if eco else None)
            rows.append(c)
        for v in res.get("Vulnerabilities") or []:
            scores = [_score(x.get("V3Score")) for x in (v.get("CVSS") or {}).values() if isinstance(x, dict)]
            rep = [Reported(id=v.get("VulnerabilityID", ""), cvss=max((s for s in scores if s is not None), default=None),
                            severity=v.get("Severity"), fixed=_first_version(v.get("FixedVersion")))]
            c = _from_purl((v.get("PkgIdentifier") or {}).get("PURL"), rep) or (
                component(eco, v.get("PkgName", ""), v.get("InstalledVersion", ""), reported=rep) if eco else None)
            if c is None:
                lost[res.get("Type") or "?"] += 1
            rows.append(c)
    notes = ["스캐너 결과에는 취약점이 있는 패키지만 들어 있을 수 있습니다(Trivy는 --list-all-pkgs로 전체를 냅니다).", NO_GRAPH, NO_SCOPE]
    if lost:
        notes.append(f"지원하지 않는 종류라 뺀 취약점: {dict(lost)} (OS 패키지 등)")
    return Parsed("trivy", _merge(rows), notes)


def parse_grype(doc: dict) -> Parsed:
    rows, lost = [], 0
    for m in doc.get("matches") or []:
        a, v = m.get("artifact") or {}, m.get("vulnerability") or {}
        scores = [_score((x.get("metrics") or {}).get("baseScore")) for x in v.get("cvss") or []]
        rep = [Reported(id=v.get("id", ""), cvss=max((s for s in scores if s is not None), default=None),
                        severity=v.get("severity"), fixed=_first_version((v.get("fix") or {}).get("versions")))]
        eco = ecosystem_of(a.get("type")) or ecosystem_of(a.get("language"))
        c = _from_purl(a.get("purl"), rep) or (component(eco, a.get("name", ""), a.get("version", ""), reported=rep) if eco else None)
        lost += c is None
        rows.append(c)
    notes = ["스캐너 결과에는 취약점이 있는 패키지만 들어 있습니다.", NO_GRAPH, NO_SCOPE]
    return Parsed("grype", _merge(rows), notes + ([f"지원하지 않는 종류라 뺀 취약점 {lost}건 (OS 패키지 등)"] if lost else []))


def parse_osv_scanner(doc: dict) -> Parsed:
    rows = []
    for res in doc.get("results") or []:
        for p in res.get("packages") or []:
            pkg = p.get("package") or {}
            eco = ecosystem_of(pkg.get("ecosystem")) or (pkg.get("ecosystem") if pkg.get("ecosystem") in PURL_TYPE else None)
            rep = [Reported(id=v.get("id", "")) for v in p.get("vulnerabilities") or [] if v.get("id")]
            rows.append(component(eco, pkg.get("name", ""), pkg.get("version", ""), reported=rep) if eco else None)
    return Parsed("osv-scanner", _merge(rows), [NO_GRAPH, NO_SCOPE] + _skipped(len(rows), sum(r is not None for r in rows)))


def parse_snyk(doc: dict | list) -> Parsed:
    rows = []
    for project in doc if isinstance(doc, list) else [doc]:
        default = ecosystem_of(project.get("packageManager"))
        for v in project.get("vulnerabilities") or []:
            ids = (v.get("identifiers") or {})
            vid = next(iter(ids.get("CVE") or ids.get("GHSA") or []), None) or v.get("id", "")
            rep = [Reported(id=vid, cvss=_score(v.get("cvssScore")), severity=v.get("severity"), fixed=_first_version(v.get("fixedIn")))]
            eco = ecosystem_of(v.get("packageManager")) or default
            rows.append(component(eco, v.get("packageName") or v.get("moduleName") or "", v.get("version", ""),
                                  reported=rep) if eco else None)
    return Parsed("snyk", _merge(rows), ["스캐너 결과에는 취약점이 있는 패키지만 들어 있습니다.", NO_GRAPH, NO_SCOPE]
                  + _skipped(len(rows), sum(r is not None for r in rows), "취약점"))


def parse_dependency_check(doc: dict) -> Parsed:
    rows, lost = [], 0
    for d in doc.get("dependencies") or []:
        vulns = d.get("vulnerabilities") or []
        rep = [Reported(id=v.get("name", ""), cvss=_score((v.get("cvssv3") or {}).get("baseScore")), severity=v.get("severity"))
               for v in vulns if v.get("name")]
        purls = [p.get("id", "") for p in d.get("packages") or [] if str(p.get("id", "")).startswith("pkg:")]
        got = [_from_purl(p, rep) for p in purls[:1]]
        lost += bool(vulns) and not any(got)
        rows += got
    notes = [NO_GRAPH, NO_SCOPE] + ([f"패키지 식별자(purl)가 없어 뺀 취약 파일 {lost}개"] if lost else [])
    return Parsed("dependency-check", _merge(rows), notes)


# ---------- SBOM variants ----------

def parse_cyclonedx_xml(text: str) -> Parsed:
    root = ET.fromstring(text)
    tag = lambda el: el.tag.split("}")[-1]  # noqa: E731
    kid = lambda el, name: next((c for c in el if tag(c) == name), None)  # noqa: E731
    txt = lambda el, name: ((kid(el, name).text or "").strip() if kid(el, name) is not None else None)  # noqa: E731

    def comp(el) -> dict:
        out = {"type": el.get("type", "library"), "bom-ref": el.get("bom-ref") or txt(el, "purl"), "name": txt(el, "name"),
               "version": txt(el, "version"), "scope": txt(el, "scope") or "required"}
        if txt(el, "purl"):
            out["purl"] = txt(el, "purl")
        group = txt(el, "group")
        if group and out["type"] != "application":
            out["group"] = group
        return out

    comps_el, deps_el, meta = kid(root, "components"), kid(root, "dependencies"), kid(root, "metadata")
    comps = [comp(el) for el in (comps_el.iter() if comps_el is not None else []) if tag(el) == "component"]
    deps = [{"ref": d.get("ref"), "dependsOn": [c.get("ref") for c in d if tag(c) == "dependency"]}
            for d in (deps_el if deps_el is not None else []) if tag(d) == "dependency"]
    bom = {"bomFormat": "CycloneDX", "specVersion": root.get("specVersion") or "1.5", "components": comps, "dependencies": deps}
    main = kid(meta, "component") if meta is not None else None
    if main is not None:
        bom["metadata"] = {"component": {"bom-ref": main.get("bom-ref"), "name": txt(main, "name")}}
    vulns_el = kid(root, "vulnerabilities")
    vulns = []
    for v in (vulns_el if vulns_el is not None else []):
        ratings = [{"score": _score(txt(r, "score")), "severity": txt(r, "severity")}
                   for r in (kid(v, "ratings") if kid(v, "ratings") is not None else [])]
        affects = [{"ref": txt(t, "ref")} for t in (kid(v, "affects") if kid(v, "affects") is not None else [])]
        vulns.append({"id": txt(v, "id"), "ratings": ratings, "affects": affects})
    if vulns:
        bom["vulnerabilities"] = vulns
    return Parsed("cyclonedx-xml", bom=bom, notes=[] if deps else [NO_GRAPH])


def parse_spdx_tag_value(text: str) -> Parsed:
    packages, rels, cur = [], [], None
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if not sep:
            continue
        if key == "PackageName":
            cur = {"name": value, "externalRefs": []}
            packages.append(cur)
        elif key == "SPDXID" and cur is not None and "SPDXID" not in cur:
            cur["SPDXID"] = value
        elif key == "PackageVersion" and cur is not None:
            cur["versionInfo"] = value
        elif key == "ExternalRef" and cur is not None:
            parts = value.split()
            if len(parts) >= 3 and parts[1] == "purl":
                cur["externalRefs"].append({"referenceType": "purl", "referenceLocator": parts[2]})
        elif key == "Relationship":
            parts = value.split()
            if len(parts) >= 3:
                rels.append({"spdxElementId": parts[0], "relationshipType": parts[1], "relatedSpdxElement": parts[2]})
    doc = {"packages": [p for p in packages if "SPDXID" in p], "relationships": rels}
    return Parsed("spdx-tag-value", bom=sbom.spdx_to_cyclonedx(doc), notes=[] if rels else [NO_GRAPH])


# ---------- tables and record lists ----------

# field -> header names that mean it (lower case, compared without spaces, dashes and underscores)
ALIASES = {
    "purl": ["purl", "packageurl"],
    "name": ["name", "package", "packagename", "pkgname", "pkg", "component", "componentname", "artifact", "artifactid",
             "library", "module", "dependency", "패키지", "패키지명", "컴포넌트", "컴포넌트명", "라이브러리", "라이브러리명", "모듈",
             "오픈소스", "오픈소스명", "이름"],
    "group": ["group", "groupid", "namespace", "vendor", "그룹", "그룹id"],
    "version": ["version", "installedversion", "currentversion", "packageversion", "pkgversion", "ver", "버전", "현재버전",
                "사용버전", "설치버전"],
    "ecosystem": ["ecosystem", "type", "packagetype", "packagemanager", "manager", "language", "lang", "pkgtype", "생태계",
                  "언어", "유형", "종류", "패키지관리자"],
    "vuln": ["vulnerability", "vulnerabilityid", "vulnid", "cve", "cveid", "cves", "advisory", "id", "취약점", "취약점id",
             "취약점번호", "cve번호"],
    "severity": ["severity", "risk", "level", "심각도", "위험도", "등급"],
    "cvss": ["cvss", "cvssscore", "cvssv3", "cvss3", "score", "basescore", "점수"],
    "fixed": ["fixedversion", "fixedin", "fixversion", "fix", "patchedversion", "patched", "remediation", "수정버전", "패치버전",
              "조치버전", "권고버전"],
    "scope": ["scope", "dev", "environment", "env", "범위", "용도"],
    "direct": ["direct", "isdirect", "dependencytype", "relationship", "직접", "직접의존", "의존유형"],
}


def _norm(header: str) -> str:
    return re.sub(r"[\s_\-./()]+", "", str(header)).lower()


def guess_columns(headers: list[str]) -> dict[str, str]:
    """field -> header. Exact alias matches first, then headers that contain an alias."""
    out: dict[str, str] = {}
    normed = {h: _norm(h) for h in headers}
    for exact in (True, False):
        for field, names in ALIASES.items():
            if field in out:
                continue
            for h, n in normed.items():
                if h in out.values():
                    continue
                if (n in names) if exact else any(len(a) >= 4 and a in n for a in names):
                    out[field] = h
                    break
    return out


def parse_records(records: list[dict], fmt: str, columns: dict[str, str] | None = None,
                  ecosystem: str | None = None) -> Parsed:
    """Rows of a table (or a JSON array of flat objects) -> components. `columns` names the fields outright."""
    headers = list(dict.fromkeys(k for r in records[:200] for k in r))
    cols = {**guess_columns(headers), **(columns or {})}
    unknown = [h for h in (columns or {}).values() if h not in headers]
    if unknown:
        raise UnsupportedInput(f"지정한 열이 파일에 없습니다: {unknown}. 파일의 열: {headers[:20]}")
    default = ecosystem_of(ecosystem) or (ecosystem if ecosystem in PURL_TYPE else None)
    if "purl" not in cols and not ("name" in cols and "version" in cols):
        raise UnsupportedInput(
            f"패키지 이름과 버전 열을 찾지 못했습니다. 파일의 열: {headers[:20]}. "
            "--columns name=<열>,version=<열> 로 지정하세요 (ecosystem, group, vuln, severity, cvss, fixed, scope 도 지정 가능).")
    get = lambda r, f: str(r.get(cols[f]) if f in cols and r.get(cols[f]) is not None else "").strip()  # noqa: E731
    rows, no_eco = [], 0
    for r in records:
        ids = list(dict.fromkeys(m.upper() if m.upper().startswith("CVE") else m for m in VULN_ID.findall(get(r, "vuln"))))
        rep = [Reported(id=i, cvss=_score(get(r, "cvss")), severity=get(r, "severity") or None,
                        fixed=_first_version(get(r, "fixed"))) for i in ids]
        c = _from_purl(get(r, "purl"), rep)
        if c is None and get(r, "name"):
            eco = ecosystem_of(get(r, "ecosystem")) or default
            if eco is None:
                no_eco += 1
            else:
                name = get(r, "name")
                if eco == "Maven" and ":" not in name and get(r, "group"):
                    name = f"{get(r, 'group')}:{name}"
                scope = "dev" if re.search(r"dev|test|개발|테스트|true|^y", get(r, "scope"), re.I) else "prod"
                direct = bool(re.search(r"direct|직접|true|^y", get(r, "direct"), re.I)) and "in" not in get(r, "direct").lower()[:2]
                c = component(eco, name, get(r, "version"), scope, direct, rep)
        rows.append(c)
    notes = [f"읽은 열: {', '.join(f'{k}={v}' for k, v in cols.items())}"]
    if no_eco and not any(rows):
        raise UnsupportedInput("어느 생태계(npm, Maven, PyPI 등)의 패키지인지 알 수 없습니다. --ecosystem <이름>으로 기본값을 주거나 "
                               f"--columns ecosystem=<열>로 지정하세요. 파일의 열: {headers[:20]}")
    if no_eco:
        notes.append(f"{no_eco}행은 생태계(npm, Maven, PyPI 등)를 알 수 없어 뺐습니다. --ecosystem 으로 기본값을 주거나 ecosystem 열을 지정하세요.")
    notes += _skipped(len(rows) - no_eco, sum(r is not None for r in rows), "행")
    if "direct" not in cols:
        notes.append(NO_GRAPH)
    if "scope" not in cols:
        notes.append(NO_SCOPE)
    return Parsed(fmt, _merge(rows), notes)


def parse_table(text: str, columns: dict[str, str] | None = None, ecosystem: str | None = None) -> Parsed:
    text = text.lstrip("﻿")
    head = next((line for line in text.splitlines() if line.strip()), "")
    delim = max(",\t;|", key=head.count)
    records = list(csv.DictReader(io.StringIO(text), delimiter=delim))
    return parse_records(records, "table", columns, ecosystem)


# ---------- detection ----------

def _records_in(doc) -> list[dict] | None:
    """A JSON array of flat objects, at the top or under one obvious key."""
    if isinstance(doc, dict):
        lists = [v for v in doc.values() if isinstance(v, list) and v and all(isinstance(x, dict) for x in v[:20])]
        doc = lists[0] if len(lists) == 1 else None
    if isinstance(doc, list) and doc and all(isinstance(x, dict) for x in doc[:20]):
        return doc
    return None


def _sniff(name: str, text: str, columns: dict[str, str] | None, ecosystem: str | None) -> Parsed:
    """Pick the parser from the content. Raises UnsupportedInput with what to do next."""
    head = text.lstrip("﻿ \t\r\n")[:400]
    if head.startswith(("{", "[")):
        try:
            doc = json.loads(text)
        except ValueError as e:
            raise UnsupportedInput(f"JSON으로 읽지 못했습니다: {e}") from e
        if isinstance(doc, dict):
            if doc.get("bomFormat") == "CycloneDX":
                return Parsed("cyclonedx", bom=doc, notes=[] if doc.get("dependencies") else [NO_GRAPH])
            if str(doc.get("spdxVersion", "")).startswith("SPDX"):
                return Parsed("spdx", bom=sbom.spdx_to_cyclonedx(doc), notes=[] if doc.get("relationships") else [NO_GRAPH])
            if "Results" in doc and ("SchemaVersion" in doc or "ArtifactName" in doc):
                return parse_trivy(doc)
            if "matches" in doc and ("descriptor" in doc or "source" in doc):
                return parse_grype(doc)
            if isinstance(doc.get("results"), list) and any("packages" in r for r in doc["results"] if isinstance(r, dict)):
                return parse_osv_scanner(doc)
            if "vulnerabilities" in doc and ("packageManager" in doc or "projectName" in doc):
                return parse_snyk(doc)
            if "dependencies" in doc and ("scanInfo" in doc or "reportSchema" in doc):
                return parse_dependency_check(doc)
            if "lockfileVersion" in doc and ("packages" in doc or "dependencies" in doc):
                return parse_package_lock(text)
            if "auditReportVersion" in doc or "advisories" in doc:
                raise UnsupportedInput("npm audit 결과에는 설치된 정확한 버전이 없습니다. 같은 프로젝트의 package-lock.json을 입력으로 쓰세요.")
            if "catalogVersion" in doc and "vulnerabilities" in doc:
                raise UnsupportedInput("CISA KEV 목록입니다. 스캔 입력이 아니라 취약점 데이터이므로 `triage seed --kev <파일>`로 넣으세요.")
            if "affected" in doc and "id" in doc:
                raise UnsupportedInput("OSV 권고 한 건입니다. 스캔 입력이 아니라 취약점 데이터입니다.")
            if str(doc.get("$schema", "")).find("sarif") >= 0 or "runs" in doc:
                raise UnsupportedInput("SARIF에는 패키지 버전이 규격화되어 있지 않습니다. 같은 도구의 JSON 결과나 SBOM 파일을 쓰세요.")
        elif isinstance(doc, list) and doc and isinstance(doc[0], dict) and "vulnerabilities" in doc[0]:
            return parse_snyk(doc)
        records = _records_in(doc)
        if records is not None:
            return parse_records(records, "json-records", columns, ecosystem)
        raise UnsupportedInput("알아보지 못한 JSON 구조입니다. 최상위 키: "
                               f"{list(doc)[:15] if isinstance(doc, dict) else type(doc).__name__}. kit의 adapt-input 절차로 파서를 추가하세요.")
    if head.startswith("<"):
        if "cyclonedx" in head.lower() or re.search(r"<bom[\s>]", head):
            return parse_cyclonedx_xml(text)
        if re.search(r"<project[\s>]", head):
            return parse_pom(text)
        raise UnsupportedInput("알아보지 못한 XML입니다 (CycloneDX XML과 pom.xml만 읽습니다).")
    if re.match(r"^SPDXVersion:", head):
        return parse_spdx_tag_value(text)
    if name.endswith((".csv", ".tsv")) or (head.count(",") + head.count("\t") + head.count(";") >= 2 and "\n" in text):
        return parse_table(text, columns, ecosystem)
    raise UnsupportedInput("알아보지 못한 형식입니다. 지원: CycloneDX, SPDX, 스캐너 JSON(Trivy, Grype, OSV-Scanner, Snyk, Dependency-Check), "
                           "lock 파일, CSV와 TSV, 객체 배열 JSON.")


def parser_for_name(name: str) -> Callable[[str], Parsed] | None:
    if name in BY_NAME:
        return BY_NAME[name]
    if re.fullmatch(r"requirements[\w.-]*\.txt", name):
        return parse_requirements
    return None


def parse_file(path: pathlib.Path, columns: dict[str, str] | None = None, ecosystem: str | None = None) -> Parsed:
    if path.stat().st_size > MAX_BYTES:
        raise UnsupportedInput(f"파일이 너무 큽니다 ({path.stat().st_size // 1_000_000}MB).")
    if path.suffix.lower() in (".xlsx", ".xls"):
        raise UnsupportedInput("엑셀 파일은 직접 읽지 않습니다. CSV로 저장한 뒤 입력으로 쓰세요.")
    try:
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        try:
            text = path.read_text(encoding="cp949")          # Korean spreadsheets exported as CSV
        except UnicodeDecodeError as e:
            raise UnsupportedInput("텍스트 파일이 아닙니다 (UTF-8이나 CP949로 읽히지 않음).") from e
    by_name = parser_for_name(path.name)
    try:
        return by_name(text) if by_name else _sniff(path.name.lower(), text, columns, ecosystem)
    except UnsupportedInput:
        raise
    except (ValueError, KeyError, TypeError, AttributeError, ET.ParseError, tomllib.TOMLDecodeError) as e:
        raise UnsupportedInput(f"{path.name}을(를) 읽다가 멈췄습니다: {type(e).__name__}: {str(e)[:200]}") from e


def load(path: pathlib.Path, columns: dict[str, str] | None = None, ecosystem: str | None = None) -> tuple[dict, str, list[str]]:
    """Any supported file -> (CycloneDX dict, source label, notes about what the input lacks)."""
    p = parse_file(path, columns, ecosystem)
    bom = p.bom if p.bom is not None else sbom.to_cyclonedx(p.components, p.fmt)
    return bom, f"file:{p.fmt}", p.notes


def repo_files(repo: pathlib.Path, depth: int = 3) -> list[pathlib.Path]:
    """Dependency files of a repository: the root's if it has any, otherwise those up to `depth` levels down."""
    def here(d: pathlib.Path) -> list[pathlib.Path]:
        names = [n for n in BY_NAME if (d / n).is_file()]
        names += sorted(p.name for p in d.glob("requirements*.txt") if p.name not in names)
        names = [n for n in names if SHADOWED.get(n) not in names and not (n.startswith("requirements") and "poetry.lock" in names)]
        lock = [n for n in names if n != "pom.xml" or len(names) == 1]      # a lock file beats a bare pom.xml
        return [d / n for n in lock]

    found = here(repo)
    if found or depth <= 0:
        return found
    out: list[pathlib.Path] = []
    for sub in sorted(p for p in repo.iterdir() if p.is_dir() and p.name not in SKIP_DIRS and not p.name.startswith(".")):
        out += repo_files(sub, depth - 1)
    return out


def repo_components(repo: pathlib.Path) -> tuple[list[Component], list[str]]:
    """Components from every dependency file found. -> (components, notes)."""
    files = repo_files(repo)
    parts, notes = [], []
    for f in files:
        try:
            p = BY_NAME.get(f.name, parse_requirements)(f.read_text(encoding="utf-8-sig"))
        except Exception as e:  # one unreadable file must not hide the others
            notes.append(f"{f.relative_to(repo)}: 읽지 못함 ({type(e).__name__})")
            continue
        parts += p.components
        rel = str(f.relative_to(repo))
        notes += [f"{rel}: {n}" for n in p.notes]
    if len(files) > 1:
        notes.insert(0, "의존성 파일 여러 개를 합쳤습니다: " + ", ".join(str(f.relative_to(repo)) for f in files))
    return _merge(parts), notes


# ---------- what is this? (CLI `triage inspect`) ----------

def describe(path: pathlib.Path, columns: dict[str, str] | None = None, ecosystem: str | None = None) -> dict:
    """One file: can the pipeline read it, and what does it hold. Never raises."""
    try:
        p = parse_file(path, columns, ecosystem)
    except UnsupportedInput as e:
        return {"file": str(path), "supported": False, "why": str(e)}
    except OSError as e:
        return {"file": str(path), "supported": False, "why": f"읽지 못함: {e}"}
    bom = p.bom if p.bom is not None else sbom.to_cyclonedx(p.components, p.fmt)
    comps = sbom.components_from_cyclonedx(bom)
    return {"file": str(path), "supported": True, "format": p.fmt, "components": len(comps),
            "ecosystems": dict(Counter(c.ecosystem for c in comps)), "direct": sum(c.direct for c in comps),
            "dev": sum(c.scope == "dev" for c in comps), "reported_vulnerabilities": sum(len(c.reported) for c in comps),
            "not_scannable": sbom.unsupported_purls(bom), "notes": p.notes}


MAX_UNREAD = 12
CANDIDATE_SUFFIXES = {".json", ".xml", ".csv", ".tsv", ".spdx", ".cdx", ".lock", ".yaml", ".yml", ".txt", ".mod", ".sum", ".lockfile"}


def survey(root: pathlib.Path, limit: int = 200) -> list[dict]:
    """Every file under `root` that could be an input, described. Files that are plainly something else are left out."""
    if root.is_file():
        return [describe(root)]
    out, unread, more = [], [], 0
    for p in sorted(root.rglob("*")):
        if len(out) >= limit or not p.is_file() or SKIP_DIRS & set(p.relative_to(root).parts):
            continue
        named = parser_for_name(p.name) is not None
        if not named and (p.suffix.lower() not in CANDIDATE_SUFFIXES or p.suffix.lower() in (".txt", ".yaml", ".yml", ".lock")):
            continue
        if not named and p.name in ("package.json", "tsconfig.json", "composer.json"):
            continue
        d = describe(p)
        if d["supported"]:
            out.append(d)
        elif len(unread) < MAX_UNREAD:
            unread.append(d)
        else:
            more += 1
    if more:
        unread.append({"file": f"(그 밖의 파일 {more}개)", "supported": False, "why": "같은 이유로 읽지 못했거나 입력이 아닌 파일입니다."})
    return out + unread
