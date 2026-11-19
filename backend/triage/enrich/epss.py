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
    return out
