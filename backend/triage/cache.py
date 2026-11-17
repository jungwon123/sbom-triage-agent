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


def fetch_json(url: str, data: Any = None, timeout: float = 60) -> Any | None:
    path = CACHE_DIR / f"{key(url, data)}.json"
    if path.exists():
        return json.loads(path.read_text())
    if replay_mode():
        log.warning("replay cache miss: %s", url[:120])
        return None
    try:
        with httpx.Client(timeout=timeout, headers={"User-Agent": USER_AGENT}) as client:
            res = client.post(url, json=data) if data is not None else client.get(url)
            res.raise_for_status()
            body = res.json()
    except (httpx.HTTPError, ValueError) as e:
        log.warning("fetch failed %s: %s", url[:120], e)
        return None
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body))
    return body
