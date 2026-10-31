"""Rule-only PoC: lockfile -> OSV/EPSS/KEV -> draft 25/25/50 score -> buckets.

Reads target repos as data and never executes them. Responses are cached in out/poc-cache.
usage: python -I poc/rule_poc.py <name>=<repo_dir> ...
"""
import concurrent.futures as cf
import hashlib
import json
import math
import pathlib
import re
import sys
import time
import urllib.request

CACHE = pathlib.Path("out/poc-cache")
LABEL = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.5, "LOW": 3.0}
AV = {"N": .85, "A": .62, "L": .55, "P": .2}
AC = {"L": .77, "H": .44}
UI = {"N": .85, "R": .62}
CIA = {"H": .56, "L": .22, "N": 0}
TEST_PATH = re.compile(r"(^|/)(e2e|tests?|__tests__|__mocks__|cypress|spec)(/|$)|\.(spec|test)\.[cm]?[jt]sx?$")
SOURCE_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
SKIP_DIRS = {"node_modules", ".git", "dist", "build", "vendor", "assets"}


def fetch(url, data=None):
    key = hashlib.sha256((url + json.dumps(data)).encode()).hexdigest()
    path = CACHE / f"{key}.json"
    if path.exists():
        return json.loads(path.read_text())
    req = urllib.request.Request(
        url, data=json.dumps(data).encode() if data else None,
        headers={"User-Agent": "sbom-triage-poc", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as res:
        body = json.load(res)
    path.write_text(json.dumps(body))
    return body


def cvss31(vector):
    """Base score from a CVSS 3.x vector; None for other versions."""
    if not vector.startswith("CVSS:3"):
        return None
    m = dict(p.split(":") for p in vector.split("/")[1:])
    changed = m["S"] == "C"
    pr = {"N": .85, "L": .68 if changed else .62, "H": .5 if changed else .27}[m["PR"]]
    iss = 1 - (1 - CIA[m["C"]]) * (1 - CIA[m["I"]]) * (1 - CIA[m["A"]])
    impact = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    expl = 8.22 * AV[m["AV"]] * AC[m["AC"]] * pr * UI[m["UI"]]
    raw = min((1.08 if changed else 1) * (impact + expl), 10)
    return math.ceil(raw * 10 - 1e-9) / 10


def semver(v):
    nums = re.findall(r"\d+", v.split("-")[0])[:3]
    return tuple(int(n) for n in nums) + (0,) * (3 - len(nums))


def lock_components(lock):
    out = {}
    def put(name, version, dev):
        out[(name, version)] = out.get((name, version), True) and dev
    if "packages" in lock:
        for path, p in lock["packages"].items():
            if "node_modules/" in path and p.get("version"):
                put(p.get("name") or path.rsplit("node_modules/", 1)[1], p["version"], bool(p.get("dev")))
    else:
        def walk(deps):
            for name, p in (deps or {}).items():
                if p.get("version"):
                    put(name, p["version"], bool(p.get("dev")))
                walk(p.get("dependencies"))
        walk(lock.get("dependencies"))
    return out


def sources(repo):
    for f in repo.rglob("*"):
        rel = f.relative_to(repo)
        if f.suffix in SOURCE_EXT and f.is_file() and not SKIP_DIRS & set(rel.parts) and ".min." not in f.name:
            yield rel.as_posix(), f.read_text(errors="ignore")


def sites(pkg, files):
    pat = re.compile(rf"""(from\s+|require\(\s*|import\(\s*|import\s+)['"]{re.escape(pkg)}(/[^'"]*)?['"]""")
    runtime, test = [], []
    for rel, text in files:
        if pat.search(text):
            (test if TEST_PATH.search(rel) else runtime).append(rel)
    return runtime, test


def fixed_for(detail, name, version):
    fixes = [e["fixed"] for a in detail.get("affected", []) if a.get("package", {}).get("name") == name
             for r in a.get("ranges", []) for e in r.get("events", []) if "fixed" in e]
    later = [f for f in fixes if semver(f) > semver(version)]
    return min(later, key=semver) if later else None


def bump(version, fixed):
    if not fixed:
        return "none"
    a, b = semver(version), semver(fixed)
    return "major" if a[0] != b[0] else "minor" if a[1] != b[1] else "patch"


def severity_of(detail):
    for s in detail.get("severity", []):
        if s.get("type") == "CVSS_V3":
            score = cvss31(s["score"])
            if score is not None:
                return score, "vector"
    label = detail.get("database_specific", {}).get("severity")
    return (LABEL[label], "label") if label in LABEL else (None, "none")


def analyze(name, repo):
    start = time.time()
    lock = json.loads((repo / "package-lock.json").read_text())
    pkg = json.loads((repo / "package.json").read_text())
    comps = lock_components(lock)
    names = set(pkg.get("dependencies", {})) | set(pkg.get("devDependencies", {}))
    top = lock.get("packages", {})
    direct = {(n, (top.get(f"node_modules/{n}") or lock.get("dependencies", {}).get(n) or {}).get("version")) for n in names}
    keys = list(comps)
    hits = []
    for i in range(0, len(keys), 500):
        chunk = keys[i:i + 500]
        body = {"queries": [{"package": {"ecosystem": "npm", "name": n}, "version": v} for n, v in chunk]}
        for key, res in zip(chunk, fetch("https://api.osv.dev/v1/querybatch", body)["results"]):
            hits += [(key, v["id"]) for v in res.get("vulns", [])]
    ids = sorted({i for _, i in hits})
    with cf.ThreadPoolExecutor(8) as ex:
        details = dict(zip(ids, ex.map(lambda i: fetch(f"https://api.osv.dev/v1/vulns/{i}"), ids)))
    cve_of = {i: next((a for a in [i, *d.get("aliases", [])] if a.startswith("CVE-")), None) for i, d in details.items()}
    cves = sorted({c for c in cve_of.values() if c})
    epss = {}
    for i in range(0, len(cves), 80):
        for row in fetch("https://api.first.org/data/v1/epss?cve=" + ",".join(cves[i:i + 80]))["data"]:
            epss[row["cve"]] = float(row["percentile"])
    kev = {v["cveID"] for v in fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")["vulnerabilities"]}
    files = list(sources(repo))
    findings, seen = [], set()
    for (pname, ver), vid in hits:
        d = details[vid]
        canon = cve_of[vid] or vid
        if d.get("withdrawn") or (canon, pname, ver) in seen:
            continue
        seen.add((canon, pname, ver))
        runtime, test = sites(pname, files)
        is_direct = (pname, ver) in direct
        dev = comps[(pname, ver)]
        reach = (.6 if runtime else .2) if is_direct else .6
        exposure = (.2 if dev else 1) * (1 if is_direct else .7) * reach
        cvss, source = severity_of(d)
        pct = epss.get(cve_of[vid])
        is_kev = cve_of[vid] in kev
        exploit = 1.0 if is_kev else (pct if pct is not None else .5)
        risk = (cvss if cvss is not None else 5) * 2.5 + exploit * 25 + exposure * 50
        fixed = fixed_for(d, pname, ver)
        jump = bump(ver, fixed)
        effort = "high" if jump == "none" else "medium" if jump == "major" or not is_direct else "low"
        bucket = ("NOW" if effort != "high" else "NEXT") if risk >= 60 else "NEXT" if risk >= 30 else "MONITOR"
        findings.append({
            "pkg": pname, "ver": ver, "id": canon, "cvss": cvss, "cvss_src": source, "pct": pct, "kev": is_kev,
            "dev": dev, "direct": is_direct, "runtime": len(runtime), "test_only": bool(test and not runtime),
            "fixed": fixed, "bump": jump, "effort": effort, "risk": round(risk, 1), "bucket": bucket,
            "guard": bucket == "NOW" and (is_kev or ((pct or 0) >= .9 and bool(runtime))),
        })
    high = [f for f in findings if (f["cvss"] or 0) >= 7]
    cnt = {b: sum(f["bucket"] == b for f in findings) for b in ("NOW", "NEXT", "MONITOR")}
    now_pkgs = sorted({f"{f['pkg']}@{f['ver']}" for f in findings if f["bucket"] == "NOW"})
    summary = {
        "name": name, "components": len(comps), "findings": len(findings), "cvss_ge_7": len(high), **cnt,
        "now_packages": len(now_pkgs), "now_pkg_list": now_pkgs,
        "high_not_now": sum(f["bucket"] != "NOW" for f in high),
        "high_monitor": sum(f["bucket"] == "MONITOR" for f in high),
        "now_below_7": sum(f["bucket"] == "NOW" and (f["cvss"] or 0) < 7 for f in findings),
        "noise_reduction_pct": round((len(findings) - cnt["NOW"]) / len(findings) * 100, 1),
        "cvss_vector": sum(f["cvss_src"] == "vector" for f in findings),
        "epss_cov": sum(f["pct"] is not None for f in findings), "kev": sum(f["kev"] for f in findings),
        "test_only_direct_prod": sorted({f["pkg"] for f in findings if f["test_only"] and f["direct"] and not f["dev"]}),
        "guard_candidates": sum(f["guard"] for f in findings), "seconds": round(time.time() - start, 1),
    }
    pathlib.Path(f"out/poc/{name}.json").write_text(json.dumps(findings, ensure_ascii=False, indent=1))
    return summary


if __name__ == "__main__":
    CACHE.mkdir(parents=True, exist_ok=True)
    pathlib.Path("out/poc").mkdir(parents=True, exist_ok=True)
    results = [analyze(*a.split("=", 1)[0:1], pathlib.Path(a.split("=", 1)[1])) for a in sys.argv[1:]]
    pathlib.Path("out/poc/summary.json").write_text(json.dumps(results, ensure_ascii=False, indent=1))
    print(json.dumps(results, ensure_ascii=False, indent=1))
