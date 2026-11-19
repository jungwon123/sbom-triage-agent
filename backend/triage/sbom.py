"""① SBOM: Syft first, lockfile fallback, or a ready-made SBOM file (CycloneDX or SPDX JSON).

Whatever the source, the result is CycloneDX JSON and the scan reads only that (F2-5).
Lockfile metadata (scope, direct, dependency paths) is attached per purl.
"""
from __future__ import annotations

import json
import logging
import pathlib
import re
import shutil
import subprocess
import urllib.parse
import xml.etree.ElementTree as ET
from collections import deque

from .models import Component

log = logging.getLogger(__name__)
MAX_PATHS = 3


# ---------- purl ----------

def npm_purl(name: str, version: str) -> str:
    return f"pkg:npm/{urllib.parse.quote(name, safe='/').replace('@', '%40')}@{version}"


def maven_purl(group: str, artifact: str, version: str) -> str:
    return f"pkg:maven/{group}/{artifact}@{version}"


PURL_ECOSYSTEMS = {"npm": "npm", "maven": "Maven", "pypi": "PyPI", "golang": "Go", "cargo": "crates.io",
                   "nuget": "NuGet", "gem": "RubyGems", "composer": "Packagist"}   # purl type -> OSV ecosystem


def parse_purl(purl: str) -> tuple[str, str, str] | None:
    """-> (OSV ecosystem, OSV package name, version), or None for a purl type we cannot look up."""
    m = re.match(r"^pkg:([a-z0-9.+-]+)/(.+)@([^?#]+)", purl or "", re.I)
    if not m or m.group(1).lower() not in PURL_ECOSYSTEMS:
        return None
    kind, body, version = m.group(1).lower(), urllib.parse.unquote(m.group(2)), urllib.parse.unquote(m.group(3))
    eco = PURL_ECOSYSTEMS[kind]
    if kind == "maven":
        group, _, artifact = body.rpartition("/")
        return (eco, f"{group}:{artifact}", version) if group else None
    if kind == "pypi":
        body = re.sub(r"[-_.]+", "-", body).lower()      # PEP 503 name normalisation
    elif kind == "golang":
        version = version.removeprefix("v")              # OSV lists Go versions without the leading v
    return eco, body, version


def unsupported_purls(bom: dict) -> dict[str, int]:
    """Components the scan cannot look up, counted by purl type ("none" = no purl). Never silently dropped."""
    out: dict[str, int] = {}
    for c in bom.get("components", []):
        purl = c.get("purl") or ""
        if not parse_purl(purl):
            m = re.match(r"^pkg:([^/]+)/", purl)
            kind = m.group(1).lower() if m else "none"
            out[kind] = out.get(kind, 0) + 1
    return out


# ---------- npm lockfile ----------

def _resolve(packages: dict, loc: str, name: str) -> str | None:
    """npm resolution: nearest node_modules/<name> walking up from loc."""
    base = loc
    while True:
        cand = f"{base}/node_modules/{name}" if base else f"node_modules/{name}"
        if cand in packages:
            return cand
        if not base:
            return None
        base = base.rsplit("/node_modules/", 1)[0] if "/node_modules/" in base else ""


def npm_lock_components(lock: dict) -> list[Component]:
    packages = lock.get("packages")
    if not packages:  # lockfile v1: no graph, keep flat metadata
        out: dict[tuple[str, str], Component] = {}
        def walk(deps: dict | None, top: bool) -> None:
            for name, p in (deps or {}).items():
                if p.get("version"):
                    k = (name, p["version"])
                    prev = out.get(k)
                    dev = bool(p.get("dev")) and (prev.scope == "dev" if prev else True)
                    out[k] = Component(name=name, version=p["version"], ecosystem="npm", purl=npm_purl(*k),
                                       scope="dev" if dev else "prod", direct=top or bool(prev and prev.direct))
                walk(p.get("dependencies"), False)
        walk(lock.get("dependencies"), True)
        return list(out.values())

    root = packages.get("", {})
    roots = {**root.get("dependencies", {}), **root.get("devDependencies", {}),
             **root.get("optionalDependencies", {})}
    paths: dict[str, list[list[str]]] = {}
    queue: deque[tuple[str, list[str]]] = deque()
    for name in sorted(roots):
        loc = _resolve(packages, "", name)
        if loc:
            queue.append((loc, [name]))
    seen_edges = set()
    while queue:
        loc, chain = queue.popleft()
        got = paths.setdefault(loc, [])
        if len(got) >= MAX_PATHS:
            continue
        got.append(chain)
        p = packages.get(loc, {})
        deps = {**p.get("dependencies", {}), **p.get("optionalDependencies", {}), **p.get("peerDependencies", {})}
        for name in sorted(deps):
            child = _resolve(packages, loc, name)
            if child and (loc, child) not in seen_edges and len(chain) < 12:
                seen_edges.add((loc, child))
                queue.append((child, chain + [name]))

    out: dict[tuple[str, str], Component] = {}
    for loc, p in packages.items():
        if "node_modules/" not in loc or not p.get("version") or p.get("link"):
            continue
        name = p.get("name") or loc.rsplit("node_modules/", 1)[1]
        k = (name, p["version"])
        prev = out.get(k)
        dev = bool(p.get("dev")) and (prev.scope == "dev" if prev else True)
        direct = (name in roots and loc == f"node_modules/{name}") or bool(prev and prev.direct)
        merged = (prev.paths if prev else []) + paths.get(loc, [])
        out[k] = Component(name=name, version=p["version"], ecosystem="npm", purl=npm_purl(*k),
                           scope="dev" if dev else "prod", direct=direct, paths=merged[:MAX_PATHS])
    return list(out.values())


# ---------- Maven pom.xml (direct dependencies only) ----------

def maven_pom_components(pom_text: str) -> list[Component]:
    root = ET.fromstring(pom_text)
    ns = {"m": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {"m": ""}
    q = (lambda t: f"m:{t}") if ns["m"] else (lambda t: t)
    props: dict[str, str] = {}
    pe = root.find(q("properties"), ns)
    if pe is not None:
        for el in pe:
            props[el.tag.split("}")[-1]] = (el.text or "").strip()
    ver = root.findtext(q("version"), default="", namespaces=ns) or root.findtext(f"{q('parent')}/{q('version')}", default="", namespaces=ns)
    props.setdefault("project.version", ver.strip())
    managed: dict[str, str] = {}
    for d in root.findall(f"{q('dependencyManagement')}/{q('dependencies')}/{q('dependency')}", ns):
        g, a, v = (d.findtext(q(t), default="", namespaces=ns).strip() for t in ("groupId", "artifactId", "version"))
        managed[f"{g}:{a}"] = v

    def sub(v: str) -> str:
        return re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), v)

    out = []
    for d in root.findall(f"{q('dependencies')}/{q('dependency')}", ns):
        g, a, v, scope = (d.findtext(q(t), default="", namespaces=ns).strip() for t in ("groupId", "artifactId", "version", "scope"))
        v = sub(v or managed.get(f"{g}:{a}", ""))
        if not (g and a and v) or "${" in v:
            log.warning("maven dependency without resolvable version: %s:%s", g, a)
            continue
        out.append(Component(name=f"{g}:{a}", version=v, ecosystem="Maven", purl=maven_purl(g, a, v),
                             scope="dev" if scope in ("test", "provided") else "prod", direct=True, paths=[[f"{g}:{a}"]]))
    return out


# ---------- CycloneDX ----------

def to_cyclonedx(components: list[Component], source: str) -> dict:
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"tools": {"components": [{"type": "application", "name": f"sbom-triage ({source})"}]}},
        "components": [{
            "type": "library", "bom-ref": c.purl, "name": c.name, "version": c.version, "purl": c.purl,
            "scope": "optional" if c.scope == "dev" else "required",
            "properties": [{"name": "triage:direct", "value": str(c.direct).lower()},
                           {"name": "triage:paths", "value": json.dumps(c.paths)}],
        } for c in components],
    }


def lockfile_components(repo: pathlib.Path) -> list[Component]:
    if (repo / "package-lock.json").exists():
        return npm_lock_components(json.loads((repo / "package-lock.json").read_text()))
    if (repo / "pom.xml").exists():
        return maven_pom_components((repo / "pom.xml").read_text())
    return []


def run_syft(repo: pathlib.Path, timeout: int = 300) -> dict | None:
    if not shutil.which("syft"):
        return None
    try:
        r = subprocess.run(["syft", f"dir:{repo}", "-o", "cyclonedx-json", "-q"],
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        log.warning("syft timed out")
        return None
    if r.returncode != 0:
        log.warning("syft failed: %s", r.stderr[-300:])
        return None
    try:
        return json.loads(r.stdout)
    except ValueError:
        return None


def generate(repo: pathlib.Path, use_syft: bool = True) -> tuple[dict, str]:
    """-> (CycloneDX dict, source). Lockfile metadata is merged into Syft output by purl."""
    lock = lockfile_components(repo)
    bom = run_syft(repo) if use_syft else None
    if bom is None:
        if not lock:
            raise FileNotFoundError(f"no package-lock.json or pom.xml in {repo}")
        return to_cyclonedx(lock, "lockfile"), "lockfile"
    meta = {c.purl: c for c in lock}
    syft_comps = components_from_cyclonedx(bom)
    merged = [meta.get(c.purl, c) for c in syft_comps]
    known = {c.purl for c in merged}
    merged += [c for c in lock if c.purl not in known]  # lockfile entries Syft skipped
    return to_cyclonedx(merged, "syft"), "syft"


def _prop(c: dict, name: str) -> str | None:
    return next((p.get("value") for p in c.get("properties", []) if p.get("name") == name), None)


def components_from_cyclonedx(bom: dict) -> list[Component]:
    raw = bom.get("components", [])
    by_ref = {c.get("bom-ref"): c for c in raw}
    deps = {d.get("ref"): d.get("dependsOn", []) for d in bom.get("dependencies", [])}
    root_ref = (bom.get("metadata", {}).get("component") or {}).get("bom-ref")
    roots = deps.get(root_ref, []) if root_ref else []
    graph_paths: dict[str, list[list[str]]] = {}
    queue = deque((r, [by_ref.get(r, {}).get("name", r)]) for r in roots)
    while queue:
        ref, chain = queue.popleft()
        got = graph_paths.setdefault(ref, [])
        if len(got) >= MAX_PATHS:
            continue
        got.append(chain)
        for child in deps.get(ref, []):
            if len(chain) < 12:
                queue.append((child, chain + [by_ref.get(child, {}).get("name", child)]))

    out: dict[str, Component] = {}
    for c in raw:
        parsed = parse_purl(c.get("purl", ""))
        if not parsed:
            continue
        eco, name, version = parsed
        direct_prop = _prop(c, "triage:direct")
        paths_prop = _prop(c, "triage:paths")
        ref = c.get("bom-ref")
        purl = npm_purl(name, version) if eco == "npm" else c["purl"].split("?")[0]
        comp = Component(
            name=name, version=version, ecosystem=eco, purl=purl,
            scope="dev" if c.get("scope") in ("optional", "excluded") else "prod",
            direct=(direct_prop == "true") if direct_prop else ref in roots,
            paths=json.loads(paths_prop) if paths_prop else graph_paths.get(ref, []),
        )
        out.setdefault(comp.purl, comp)
    return list(out.values())


# ---------- SPDX JSON -> CycloneDX ----------

def spdx_to_cyclonedx(doc: dict) -> dict:
    pkgs = {p["SPDXID"]: p for p in doc.get("packages", [])}
    rels = doc.get("relationships", [])
    described = {r["relatedSpdxElement"] for r in rels if r.get("relationshipType") == "DESCRIBES"}
    described |= set(doc.get("documentDescribes", []))
    comps, deps = [], {}
    for sid, p in pkgs.items():
        purl = next((r.get("referenceLocator") for r in p.get("externalRefs", [])
                     if r.get("referenceType") == "purl"), None)
        if sid in described and not purl:
            continue                                  # the product itself, not a dependency
        comp = {"type": "library", "bom-ref": sid, "name": p.get("name"), "version": p.get("versionInfo"),
                "scope": "required"}
        if purl:
            comp["purl"] = purl                       # without one it is kept and counted as not scanned
        comps.append(comp)
    for r in rels:
        a, t, b = r.get("spdxElementId"), r.get("relationshipType"), r.get("relatedSpdxElement")
        if t == "DEPENDS_ON":
            deps.setdefault(a, []).append(b)
        elif t == "DEPENDENCY_OF":
            deps.setdefault(b, []).append(a)
        elif t in ("DEV_DEPENDENCY_OF", "TEST_DEPENDENCY_OF"):
            deps.setdefault(b, []).append(a)
            for c in comps:
                if c["bom-ref"] == a:
                    c["scope"] = "optional"
    root = next(iter(described), None)
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "metadata": {"component": {"bom-ref": root}} if root else {},
            "components": comps, "dependencies": [{"ref": k, "dependsOn": v} for k, v in deps.items()]}


def load_file(path: pathlib.Path) -> tuple[dict, str]:
    """Read a ready-made SBOM (finals data may arrive as SBOM files instead of repos)."""
    doc = json.loads(path.read_text())
    if doc.get("bomFormat") == "CycloneDX":
        return doc, "file:cyclonedx"
    if str(doc.get("spdxVersion", "")).startswith("SPDX"):
        return spdx_to_cyclonedx(doc), "file:spdx"
    raise ValueError(f"unsupported SBOM format: {path}")
