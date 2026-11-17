"""CISA Known Exploited Vulnerabilities feed, via cache.py."""
from __future__ import annotations

from .. import cache

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def catalog() -> set[str] | None:
    """None when the feed is unavailable, so callers can record the gap instead of assuming 'not KEV'."""
    body = cache.fetch_json(URL)
    if body is None:
        return None
    return {v["cveID"] for v in body.get("vulnerabilities", [])}
