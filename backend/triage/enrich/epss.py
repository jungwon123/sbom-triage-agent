"""FIRST EPSS score and percentile, batched, via cache.py."""
from __future__ import annotations

from .. import cache

URL = "https://api.first.org/data/v1/epss?cve="
BATCH = 80


def lookup(cves: list[str]) -> dict[str, tuple[float, float]]:
    """cve -> (epss, percentile). Missing CVEs are simply absent."""
    out: dict[str, tuple[float, float]] = {}
    cves = sorted(set(cves))
    for i in range(0, len(cves), BATCH):
        body = cache.fetch_json(URL + ",".join(cves[i:i + BATCH]), max_age=cache.DAY)
        for row in (body or {}).get("data", []):
            out[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
    if len(out) < len(cves):                 # the API did not answer for some: use the seeded file, if any
        local = cache.snapshot_get("epss") or {}
        for cve in cves:
            if cve not in out and cve in local:
                out[cve] = (float(local[cve][0]), float(local[cve][1]))
    return out


def parse_csv(text: str) -> dict[str, list[float]]:
    """FIRST's daily file (cve,epss,percentile with a comment line on top) -> {cve: [epss, percentile]}."""
    out: dict[str, list[float]] = {}
    for line in text.splitlines():
        parts = line.strip().split(",")
        if len(parts) >= 3 and parts[0].upper().startswith("CVE-"):
            try:
                out[parts[0].upper()] = [float(parts[1]), float(parts[2])]
            except ValueError:
                continue
    return out
