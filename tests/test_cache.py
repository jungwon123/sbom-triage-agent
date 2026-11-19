"""Daily feeds must not stay frozen in the cache (KEV, EPSS), and replay must never refetch."""
import json
import os
import time

import httpx
import pytest

from triage import cache
from triage.enrich import kev


class FakeClient:
    calls = 0
    body: dict = {}
    fail = False

    def __init__(self, *a, **k): pass
    def __enter__(self): return self
    def __exit__(self, *a): return False

    def get(self, url):
        FakeClient.calls += 1
        if FakeClient.fail:
            raise httpx.ConnectError("down")
        return httpx.Response(200, json=FakeClient.body, request=httpx.Request("GET", url))


@pytest.fixture
def net(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(cache.httpx, "Client", FakeClient)
    monkeypatch.delenv("DEMO_MODE", raising=False)
    FakeClient.calls, FakeClient.fail = 0, False
    return tmp_path


def age(tmp_path, url, days):
    path = tmp_path / f"{cache.key(url)}.json"
    old = time.time() - days * cache.DAY
    os.utime(path, (old, old))


def test_fresh_copy_is_reused_and_old_copy_is_fetched_again(net):
    FakeClient.body = {"v": 1}
    assert cache.fetch_json("https://x/feed", max_age=cache.DAY) == {"v": 1}
    assert cache.fetch_json("https://x/feed", max_age=cache.DAY) == {"v": 1} and FakeClient.calls == 1
    age(net, "https://x/feed", 2)
    FakeClient.body = {"v": 2}
    assert cache.fetch_json("https://x/feed", max_age=cache.DAY) == {"v": 2} and FakeClient.calls == 2


def test_without_max_age_the_cache_never_expires(net):
    FakeClient.body = {"v": 1}
    cache.fetch_json("https://x/advisory")
    age(net, "https://x/advisory", 400)
    FakeClient.body = {"v": 2}
    assert cache.fetch_json("https://x/advisory") == {"v": 1} and FakeClient.calls == 1


def test_failed_refresh_falls_back_to_the_old_copy(net):
    FakeClient.body = {"v": 1}
    cache.fetch_json("https://x/feed", max_age=cache.DAY)
    age(net, "https://x/feed", 3)
    FakeClient.fail = True
    assert cache.fetch_json("https://x/feed", max_age=cache.DAY) == {"v": 1}


def test_replay_never_refetches(net, monkeypatch):
    FakeClient.body = {"v": 1}
    cache.fetch_json("https://x/feed", max_age=cache.DAY)
    age(net, "https://x/feed", 30)
    monkeypatch.setenv("DEMO_MODE", "replay")
    assert cache.fetch_json("https://x/feed", max_age=cache.DAY) == {"v": 1} and FakeClient.calls == 1


def test_kev_version_is_reported(net):
    FakeClient.body = {"catalogVersion": "2026.11.19", "dateReleased": "2026-11-19T15:00:00Z",
                       "vulnerabilities": [{"cveID": "CVE-2021-44228"}]}
    assert kev.catalog() == {"CVE-2021-44228"}
    assert kev.version() == {"catalog_version": "2026.11.19", "date_released": "2026-11-19T15:00:00Z", "count": 1}
