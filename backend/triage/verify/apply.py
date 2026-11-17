"""Validate a remediation proposal and build its commands (F6-8, F8-11, CLAUDE.md rule 5).

LLM strings are never executed. Commands are assembled here from kind, package and to_version
after each value passes a strict pattern, so shell metacharacters cannot reach the sandbox.
"""
from __future__ import annotations

import re

from ..enrich import semver
from ..models import Finding, Remediation, RemediationProposal

NPM_NAME = re.compile(r"^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")
MAVEN_NAME = re.compile(r"^[A-Za-z0-9._-]+:[A-Za-z0-9._-]+$")
VERSION = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")
MAVEN_VERSION = re.compile(r"^\d+(\.\d+){0,3}([.-][0-9A-Za-z.-]+)?$")
NPM_FLAGS = "--package-lock-only --ignore-scripts --no-audit --no-fund"


def safe_name(f: Finding) -> bool:
    return bool((NPM_NAME if f.ecosystem == "npm" else MAVEN_NAME).match(f.package))


def safe_version(v: str | None, ecosystem: str) -> bool:
    return bool(v) and bool((VERSION if ecosystem == "npm" else MAVEN_VERSION).match(v))


def violations(p: RemediationProposal, f: Finding) -> list[str]:
    out = []
    if not safe_name(f):
        out.append("package name has unexpected characters")
    if p.kind == "mitigation_only":
        if p.to_version is not None:
            out.append("mitigation_only must not set to_version")
        return out
    if not safe_version(p.to_version, f.ecosystem):
        out.append("to_version is not a plain version")
        return out
    if not safe_version(f.version, f.ecosystem):
        out.append("current version is not a plain version")
    if f.fixed_in is None:
        out.append("no fixed version exists; use mitigation_only")
    elif semver.lt(p.to_version, f.fixed_in):
        out.append("to_version is below fixed_in")
    if p.kind == "upgrade_direct" and not f.direct:
        out.append("upgrade_direct on a transitive dependency")
    if p.kind == "override_transitive" and f.direct:
        out.append("override_transitive on a direct dependency")
    return out


def default_proposal(f: Finding) -> RemediationProposal:
    """Rule fallback: highest fixed version (D29)."""
    target = f.fixed_max or f.fixed_in
    if not target or not safe_version(target, f.ecosystem) or not safe_version(f.version, f.ecosystem):
        return RemediationProposal(kind="mitigation_only", to_version=None,
                                   mitigation="수정 버전이 없습니다. 해당 기능 사용을 줄이거나 입력 검증을 추가하고 어드바이저리를 추적합니다.",
                                   breaking_risk="low", notes=None)
    risk = {"patch": "low", "minor": "low", "major": "high"}.get(semver.bump(f.version, target), "medium")
    return RemediationProposal(kind="upgrade_direct" if f.direct else "override_transitive", to_version=target,
                               mitigation=None, breaking_risk=risk, notes=None)


def build(p: RemediationProposal, f: Finding) -> Remediation:
    """Call only after violations() returned nothing."""
    commands: list[str] = []
    patch = None
    if p.kind != "mitigation_only":
        if f.ecosystem == "npm":
            if p.kind == "upgrade_direct":
                commands = [f"npm install {f.package}@{p.to_version}"]
            else:
                patch = {"overrides": {f.package: p.to_version}}
                commands = ["npm install"]
        else:
            commands = [f"pom.xml: {f.package} 버전을 {p.to_version}(으)로 변경 후 mvn -q verify"]
    return Remediation(kind=p.kind, package=f.package, from_version=f.version, to_version=p.to_version,
                       commands=commands, package_json_patch=patch, mitigation=p.mitigation,
                       breaking_risk=p.breaking_risk, notes=p.notes)


def sandbox_command(r: Remediation) -> str | None:
    """Shell command run inside the container copy. Every interpolated value was pattern-checked."""
    if r.kind == "mitigation_only" or not r.to_version:
        return None
    if not (NPM_NAME.match(r.package) and VERSION.match(r.to_version) and VERSION.match(r.from_version)):
        raise ValueError("unsafe remediation values")
    pkg, old, new = r.package, r.from_version, r.to_version
    prune = ("const s=require('fs'),l=JSON.parse(s.readFileSync('package-lock.json'));"
             f"for(const k of Object.keys(l.packages||{{}}))if(k.endsWith('node_modules/{pkg}')&&l.packages[k].version==='{old}')delete l.packages[k];"
             "delete l.dependencies;s.writeFileSync('package-lock.json',JSON.stringify(l,null,2))")
    if r.kind == "upgrade_direct":
        return f"npm install {pkg}@{new} {NPM_FLAGS} && node -e \"{prune}\" && npm install {NPM_FLAGS}"
    js = ("const f='package.json',s=require('fs'),p=JSON.parse(s.readFileSync(f));"
          f"p.overrides={{...p.overrides,'{pkg}@{old}':'{new}'}};s.writeFileSync(f,JSON.stringify(p,null,2))")
    return f"node -e \"{js}\" && node -e \"{prune}\" && npm install {NPM_FLAGS}"
