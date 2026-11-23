"""Disk cache for every external HTTP call (CLAUDE.md rule 6).

DEMO_MODE=replay never touches the network: a cache miss returns None and is logged.
The key formula matches poc/rule_poc.py so PoC responses can seed fixtures/cache.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import pathlib
import time
from typing import Any

import httpx

log = logging.getLogger(__name__)
ROOT = pathlib.Path(__file__).resolve().parents[2]
CACHE_DIR = pathlib.Path(os.environ.get("TRIAGE_CACHE_DIR", ROOT / "fixtures" / "cache"))
USER_AGENT = "sbom-triage"


def replay_mode() -> bool:
    return os.environ.get("DEMO_MODE", "live") == "replay"


def key(url: str, data: Any = None) -> str:
    return hashlib.sha256((url + json.dumps(data)).encode()).hexdigest()


DAY = 86_400.0


def snapshot_get(name: str) -> Any | None:
    """A data file handed over on site (no network): stored once with `triage seed`, read like a cached response."""
    from . import store
    hit = store.get().cache_get(key("snapshot:" + name))
    return hit[0] if hit else None


def snapshot_put(name: str, body: Any) -> None:
    from . import store
    store.get().cache_put(key("snapshot:" + name), "snapshot:" + name, body)


def seed(url: str, body: Any, data: Any = None) -> None:
    """Store `body` as if it had been fetched from `url` (an offline copy of a public feed)."""
    from . import store
    store.get().cache_put(key(url, data), url, body)


def fetch_json(url: str, data: Any = None, timeout: float = 60, max_age: float | None = None) -> Any | None:
    """max_age (seconds) is for feeds that change daily (KEV, EPSS): an older copy is fetched again in
    live mode. If that fetch fails the old copy is still returned, with a warning. Replay never refetches."""
    from . import store          # late import: the file store reads CACHE_DIR from this module
    st, k = store.get(), key(url, data)
    stale = None
    hit = st.cache_get(k)
    if hit is not None:
        body, fetched_at = hit
        if replay_mode() or max_age is None or time.time() - fetched_at <= max_age:
            return body
        stale = body
    if replay_mode():
        log.warning("replay cache miss: %s", url[:120])
        return None
    try:
        with httpx.Client(timeout=timeout, headers={"User-Agent": USER_AGENT}) as client:
            res = client.post(url, json=data) if data is not None else client.get(url)
            res.raise_for_status()
            body = res.json()
    except (httpx.HTTPError, ValueError) as e:
        log.warning("fetch failed %s: %s%s", url[:120], e, " (using the older cached copy)" if stale is not None else "")
        return stale
    st.cache_put(k, url, body)
    return body
