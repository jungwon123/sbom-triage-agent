"""CISA Known Exploited Vulnerabilities feed, via cache.py."""
from __future__ import annotations

from .. import cache

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def catalog() -> set[str] | None:
    """None when the feed is unavailable, so callers can record the gap instead of assuming 'not KEV'."""
    body = cache.fetch_json(URL, max_age=cache.DAY)
    if body is None:
        return None
    return {v["cveID"] for v in body.get("vulnerabilities", [])}


def version() -> dict | None:
    """Which KEV list the run was judged against, for the run record and the dashboard."""
    body = cache.fetch_json(URL, max_age=cache.DAY)
    if body is None:
        return None
    return {"catalog_version": body.get("catalogVersion"), "date_released": body.get("dateReleased"),
            "count": len(body.get("vulnerabilities", []))}
