"""② Scan + ③ enrich: CycloneDX components -> OSV querybatch -> Finding (F3, F4).

Missing external data becomes None plus an entry in Finding.missing, never an exception.
"""
from __future__ import annotations

import concurrent.futures as cf
import logging
import math
import pathlib

from . import cache
from .enrich import epss as epss_mod, kev as kev_mod, semver, usages
from .models import Component, Finding

log = logging.getLogger(__name__)
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
LABEL = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 3.0}
_AV = {"N": .85, "A": .62, "L": .55, "P": .2}
_AC = {"L": .77, "H": .44}
_UI = {"N": .85, "R": .62}
_CIA = {"H": .56, "L": .22, "N": 0}


def cvss31(vector: str) -> float | None:
    """CVSS 3.x base score from a vector; None for other versions."""
    if not vector.startswith("CVSS:3"):
        return None
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = {"N": .85, "L": .68 if changed else .62, "H": .5 if changed else .27}[m["PR"]]
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        impact = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if changed else 6.42 * iss
        if impact <= 0:
            return 0.0
        expl = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
        raw = min((1.08 if changed else 1) * (impact + expl), 10)
    except (KeyError, ValueError):
        return None
    return math.ceil(raw * 10 - 1e-9) / 10


def severity(detail: dict) -> tuple[float | None, str]:
    for s in detail.get("severity", []):
        if s.get("type") == "CVSS_V3":
            score = cvss31(s.get("score", ""))
            if score is not None:
                return score, "vector"
    label = str(detail.get("database_specific", {}).get("severity", "")).upper()
    return (LABEL[label], "label") if label in LABEL else (None, "none")


def query_osv(components: list[Component]) -> list[tuple[Component, str]] | None:
    hits: list[tuple[Component, str]] = []
    for i in range(0, len(components), 500):
        chunk = components[i:i + 500]
        body = {"queries": [{"package": {"ecosystem": c.ecosystem, "name": c.name}, "version": c.version} for c in chunk]}
        res = cache.fetch_json(OSV_BATCH, body)
        if res is None:
            return None
        for c, r in zip(chunk, res.get("results", [])):
            hits += [(c, v["id"]) for v in r.get("vulns", [])]
    return hits


def scan(components: list[Component], repo: pathlib.Path | None) -> tuple[list[Finding], dict]:
    hits = query_osv(components)
    # what the input file itself reported: kept even when OSV does not list it or cannot be reached
    told = {(c.purl, r.id): r for c in components for r in c.reported if r.id}
    osv_ok = hits is not None
    if hits is None:
        if not told:
            raise RuntimeError("OSV unavailable and no cached response (try DEMO_MODE=live with network)")
        log.warning("OSV unavailable: continuing with the %d vulnerabilities the input reports", len(told))
        hits = []
    from_osv = len(hits)
    hits = hits + [(c, r.id) for c in components for r in c.reported if r.id]     # after OSV's, so OSV wins a tie
    ids = sorted({vid for _, vid in hits})
    with cf.ThreadPoolExecutor(8) as ex:
        details = dict(zip(ids, ex.map(lambda i: cache.fetch_json(OSV_VULN + i) or {}, ids)))
    cve_of = {i: next((a for a in [i, *d.get("aliases", [])] if a.startswith("CVE-")), None) for i, d in details.items()}
    epss = epss_mod.lookup([c for c in cve_of.values() if c])
    kev = kev_mod.catalog()
    file_cache: dict[str, list[tuple[str, str]]] = {}

    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    only_input = 0
    for n, (comp, vid) in enumerate(hits):
        d = details.get(vid, {})
        own = told.get((comp.purl, vid))
        canon = cve_of.get(vid) or vid
        if d.get("withdrawn") or (canon, comp.name, comp.version) in seen:
            continue
        seen.add((canon, comp.name, comp.version))
        only_input += n >= from_osv
        missing = []
        if not d:
            missing.append("osv_detail")
        cve = cve_of.get(vid)
        e = epss.get(cve) if cve else None
        if e is None:
            missing.append("epss")
        if kev is None:
            missing.append("kev")
        cvss, src = severity(d)
        if cvss is None and own is not None:        # no advisory text: fall back on what the input says
            label = (own.severity or "").upper()
            cvss, src = (own.cvss, "vector") if own.cvss is not None else (LABEL[label], "label") if label in LABEL else (None, "none")
        if cvss is None:
            missing.append("cvss")
        fixes = semver.fixes_for(d, comp.ecosystem, comp.name)
        lo = semver.fixed_in(fixes, comp.version)
        if lo is None and not d and own is not None and own.fixed and semver.valid(own.fixed):
            lo = own.fixed
        if comp.ecosystem not in file_cache:
            file_cache[comp.ecosystem] = usages.files_for(repo, comp.ecosystem)
        if repo is None or comp.ecosystem not in usages.SEARCHABLE:
            missing.append("source")     # no import search for this input: reachability stays unknown
        findings.append(Finding(
            id=f"{canon}@{comp.name}@{comp.version}", vuln_id=canon,
            aliases=sorted({vid, *d.get("aliases", [])} - {canon}), ecosystem=comp.ecosystem,
            package=comp.name, version=comp.version, scope=comp.scope, direct=comp.direct, paths=comp.paths,
            summary=d.get("summary"), cvss=cvss, cvss_source=src,
            epss=e[0] if e else None, epss_percentile=e[1] if e else None,
            kev=bool(kev and cve in kev), fixed_in=lo, fixed_max=lo,
            bump=semver.bump(comp.version, lo),
            import_sites=usages.find(comp.name, comp.ecosystem, file_cache[comp.ecosystem]) if comp.direct else [],
            missing=missing,
        ))
    # D29 / F8-12: the default target is the version that fixes every known finding of the package
    top: dict[tuple[str, str], str] = {}
    for f in findings:
        k = (f.package, f.version)
        if f.fixed_in and (k not in top or semver.lt(top[k], f.fixed_in)):
            top[k] = f.fixed_in
    for f in findings:
        f.fixed_max = top.get((f.package, f.version)) if f.fixed_in else None
    n = len(findings) or 1
    coverage = {
        "components": len(components), "findings": len(findings),
        "epss_pct": round(sum(f.epss_percentile is not None for f in findings) / n * 100, 1),
        "kev_feed": kev is not None, "kev_hits": sum(f.kev for f in findings),
        "cvss_pct": round(sum(f.cvss is not None for f in findings) / n * 100, 1),
        "fixed_pct": round(sum(f.fixed_in is not None for f in findings) / n * 100, 1),
    }
    if told:
        coverage["reported_by_input"] = len(told)           # vulnerabilities the input file named
        coverage["only_in_input"] = only_input              # of the findings, those OSV did not return
    if not osv_ok:
        coverage["osv"] = False
    return findings, coverage
