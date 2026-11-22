"""Login and roles (auth.py, HANDOFF D47) against a fake identity provider. No network."""
import base64
import hashlib
import hmac
import json
import time
import urllib.parse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from triage import auth, decide, runner
from tests.test_decide import run  # noqa: F401  (fixture)

ISSUER, CLIENT, CLIENT_SECRET = "https://idp.test", "triage", "client-secret-for-tests"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class FakeProvider:
    """Discovery, keys, token and userinfo endpoints. The test decides what the next ID token says."""

    def __init__(self):
        self.kid, self.claims, self.token, self.userinfo, self.challenge = "k1", {}, None, None, None
        self.token_requests: list[dict] = []
        self.calls: list[str] = []

    def id_token(self, key=KEY, alg="RS256", **claims) -> str:
        now = int(time.time())
        body = {"iss": ISSUER, "aud": CLIENT, "sub": "u-1", "iat": now, "exp": now + 300, **claims}
        return jwt.encode({k: v for k, v in body.items() if v is not None}, key, algorithm=alg, headers={"kid": self.kid})

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append(path)
        if path == "/.well-known/openid-configuration":
            return httpx.Response(200, json={
                "issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/authorize", "token_endpoint": f"{ISSUER}/token",
                "jwks_uri": f"{ISSUER}/keys", "userinfo_endpoint": f"{ISSUER}/userinfo"})
        if path == "/keys":
            jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key()))
            return httpx.Response(200, json={"keys": [{**jwk, "kid": self.kid, "use": "sig", "alg": "RS256"}]})
        if path == "/token":
            form = dict(urllib.parse.parse_qsl(request.content.decode()))
            self.token_requests.append({**form, "authorization": request.headers.get("authorization", "")})
            if b64(hashlib.sha256(form.get("code_verifier", "").encode()).digest()) != self.challenge:
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(200, json={"id_token": self.token or self.id_token(**self.claims), "access_token": "at-1"})
        if path == "/userinfo":
            return httpx.Response(200, json=self.userinfo or {})
        return httpx.Response(404)


@pytest.fixture
def idp(monkeypatch):
    fake = FakeProvider()
    for k, v in {"TRIAGE_AUTH": "oidc", "OIDC_ISSUER": ISSUER, "OIDC_CLIENT_ID": CLIENT, "OIDC_CLIENT_SECRET": CLIENT_SECRET,
                 "TRIAGE_SESSION_SECRET": "s" * 40, "OIDC_VIEWER_GROUPS": "dev", "OIDC_APPROVER_GROUPS": "sec-approvers, leads",
                 "OIDC_ADMIN_GROUPS": "sec-admins"}.items():
        monkeypatch.setenv(k, v)
    for k in ("TRIAGE_PUBLIC_URL", "OIDC_DEFAULT_ROLE", "OIDC_ROLES_CLAIM", "OIDC_SCOPES"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(auth, "transport", httpx.MockTransport(fake))
    auth._provider_cache.clear()
    auth._jwks_cache.clear()
    return fake


@pytest.fixture
def site(run, monkeypatch):  # noqa: F811
    from triage import api
    r = run()
    monkeypatch.setattr(runner, "OUT", r.dir.parent)
    return TestClient(api.app, follow_redirects=False), r


def start(c: TestClient, idp: FakeProvider, next_path: str = "/") -> dict:
    res = c.get("/auth/login", params={"next": next_path})
    assert res.status_code == 303 and res.headers["location"].startswith(f"{ISSUER}/authorize?")
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(res.headers["location"]).query))
    idp.challenge = q["code_challenge"]
    return q


def sign_in(c: TestClient, idp: FakeProvider, groups=("sec-approvers",), next_path="/", token=None, **claims):
    q = start(c, idp, next_path)
    idp.claims = {"nonce": q["nonce"], "name": "김보안", "email": "kim@example.com", "groups": None if groups is None else list(groups), **claims}
    idp.token = token(q) if callable(token) else token
    return c.get("/auth/callback", params={"code": "c-1", "state": q["state"]})


def test_login_is_off_by_default_and_everything_stays_open(site, monkeypatch):
    monkeypatch.delenv("TRIAGE_AUTH", raising=False)
    c, r = site
    assert c.get("/api/me").json() == {"mode": "off", "signed_in": False, "name": None, "email": None, "role": "admin"}
    assert c.get("/api/runs").status_code == 200
    d = c.post(f"/api/runs/{r.dir.name}/decisions", json={"target": "lib@1.0.0", "status": "approved", "by": "kim"}).json()
    assert d["by"] == "kim" and d["by_id"] is None


def test_nothing_is_readable_without_a_session(site, idp):
    c, r = site
    rid = r.dir.name
    assert c.get("/api/me").json()["signed_in"] is False and c.get("/api/me").json()["mode"] == "oidc"
    for path in ("/api/runs", f"/api/runs/{rid}", f"/api/runs/{rid}/proposals", f"/api/runs/{rid}/events",
                 f"/api/runs/{rid}/patch?target=lib@1.0.0", f"/api/runs/{rid}/jobs/latest", "/api/search?package=lib"):
        assert c.get(path).status_code == 401, path
    for path in ("decisions", "export", "export/together"):
        assert c.post(f"/api/runs/{rid}/{path}", json={"target": "lib@1.0.0", "status": "approved"}).status_code == 401
    assert c.get("/api/health").status_code == 200          # the probe stays open and shows no run data
    assert idp.calls == []                                   # and nothing was sent out


def test_the_login_request_carries_state_nonce_and_pkce(site, idp):
    c, _ = site
    q = start(c, idp, "/?run=abc")
    assert q["response_type"] == "code" and q["client_id"] == CLIENT and q["code_challenge_method"] == "S256"
    assert q["redirect_uri"] == "http://testserver/auth/callback" and "openid" in q["scope"].split()
    assert len(q["state"]) >= 24 and len(q["nonce"]) >= 24 and q["state"] != q["nonce"]
    assert CLIENT_SECRET not in json.dumps(q)


def test_sign_in_then_the_session_decides_who_recorded_the_decision(site, idp):
    c, r = site
    res = sign_in(c, idp, next_path="/?run=abc")
    assert res.status_code == 303 and res.headers["location"] == "/?run=abc"
    cookie = res.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie
    assert c.get("/api/me").json() == {"mode": "oidc", "signed_in": True, "name": "김보안", "email": "kim@example.com", "role": "approver"}
    sent = idp.token_requests[-1]
    assert sent["grant_type"] == "authorization_code" and sent["code"] == "c-1" and sent["authorization"].startswith("Basic ")
    assert "client_secret" not in sent                        # sent in the header, not twice
    d = c.post(f"/api/runs/{r.dir.name}/decisions", json={"target": "lib@1.0.0", "status": "approved", "by": "someone else"})
    assert d.status_code == 200 and d.json()["by"] == "김보안" and d.json()["by_id"] == "kim@example.com"
    assert decide.proposals(r)[0].decision.by_id == "kim@example.com"
    assert "PR_DRAFT.md" in c.post(f"/api/runs/{r.dir.name}/export").json()["files"]


def test_a_viewer_reads_but_cannot_decide_or_export(site, idp):
    c, r = site
    sign_in(c, idp, groups=["dev"])
    rid = r.dir.name
    assert c.get("/api/me").json()["role"] == "viewer"
    assert c.get(f"/api/runs/{rid}/proposals").status_code == 200
    res = c.post(f"/api/runs/{rid}/decisions", json={"target": "lib@1.0.0", "status": "approved"})
    assert res.status_code == 403 and "승인 권한" in res.json()["detail"]
    assert c.post(f"/api/runs/{rid}/export").status_code == 403
    assert c.post(f"/api/runs/{rid}/export/together").status_code == 403
    assert decide.proposals(r)[0].decision is None


def test_the_highest_matching_group_wins_and_no_group_means_no_session(site, idp, monkeypatch):
    c, _ = site
    sign_in(c, idp, groups=["dev", "leads", "sec-admins"])
    assert c.get("/api/me").json()["role"] == "admin"
    c.cookies.clear()
    res = sign_in(c, idp, groups=["marketing"])
    assert res.headers["location"] == "/?login_error=no_role" and c.get("/api/runs").status_code == 401
    monkeypatch.setenv("OIDC_DEFAULT_ROLE", "viewer")
    sign_in(c, idp, groups=["marketing"])
    assert c.get("/api/me").json()["role"] == "viewer"


def test_roles_from_a_nested_claim_and_from_userinfo(site, idp, monkeypatch):
    c, _ = site
    monkeypatch.setenv("OIDC_ROLES_CLAIM", "realm_access.roles")
    sign_in(c, idp, groups=[], realm_access={"roles": ["sec-approvers"]})
    assert c.get("/api/me").json()["role"] == "approver"
    c.cookies.clear()
    monkeypatch.setenv("OIDC_ROLES_CLAIM", "groups")
    idp.userinfo = {"sub": "u-1", "groups": ["sec-admins"]}
    sign_in(c, idp, groups=None)                              # the ID token has no groups claim at all
    assert c.get("/api/me").json()["role"] == "admin"
    c.cookies.clear()
    idp.userinfo = {"sub": "somebody-else", "groups": ["sec-admins"]}
    assert sign_in(c, idp, groups=None).headers["location"] == "/?login_error=no_role"


def forged_hs256(q: dict) -> str:
    """Signed with the provider's public key as an HMAC secret: the classic algorithm confusion."""
    pem = KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    now = int(time.time())
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "k1"}).encode())
    body = b64(json.dumps({"iss": ISSUER, "aud": CLIENT, "sub": "u-1", "iat": now, "exp": now + 300,
                           "nonce": q["nonce"], "groups": ["sec-admins"]}).encode())
    return f"{head}.{body}.{b64(hmac.new(pem, f'{head}.{body}'.encode(), hashlib.sha256).digest())}"


def unsigned(q: dict) -> str:
    now = int(time.time())
    body = {"iss": ISSUER, "aud": CLIENT, "sub": "u-1", "iat": now, "exp": now + 300, "nonce": q["nonce"], "groups": ["sec-admins"]}
    return f"{b64(json.dumps({'alg': 'none'}).encode())}.{b64(json.dumps(body).encode())}."


@pytest.mark.parametrize("name,make", [
    ("signed by another key", lambda idp, q: idp.id_token(key=OTHER_KEY, nonce=q["nonce"], groups=["sec-admins"])),
    ("for another client", lambda idp, q: idp.id_token(aud="other-app", nonce=q["nonce"], groups=["sec-admins"])),
    ("from another issuer", lambda idp, q: idp.id_token(iss="https://evil.test", nonce=q["nonce"], groups=["sec-admins"])),
    ("expired", lambda idp, q: idp.id_token(exp=int(time.time()) - 3600, nonce=q["nonce"], groups=["sec-admins"])),
    ("from another login", lambda idp, q: idp.id_token(nonce="not-this-login", groups=["sec-admins"])),
    ("without a nonce", lambda idp, q: idp.id_token(groups=["sec-admins"])),
    ("two audiences, other party", lambda idp, q: idp.id_token(aud=[CLIENT, "x"], azp="x", nonce=q["nonce"], groups=["sec-admins"])),
    ("hs256 with the public key", lambda idp, q: forged_hs256(q)),
    ("unsigned", lambda idp, q: unsigned(q)),
    ("not a token", lambda idp, q: "garbage"),
])
def test_a_bad_id_token_gives_no_session(site, idp, name, make):
    c, _ = site
    res = sign_in(c, idp, token=lambda q: make(idp, q))
    assert res.status_code == 303 and res.headers["location"] == "/?login_error=failed", name
    assert "triage_session=" not in res.headers.get("set-cookie", "").replace('triage_session=""', "")
    assert c.get("/api/runs").status_code == 401


def test_state_must_match_and_the_login_cookie_is_required(site, idp):
    c, _ = site
    q = start(c, idp)
    idp.claims = {"nonce": q["nonce"], "groups": ["sec-approvers"]}
    assert c.get("/auth/callback", params={"code": "c-1", "state": "forged"}).headers["location"] == "/?login_error=failed"
    q = start(c, idp)
    c.cookies.clear()                                         # a callback somebody else started
    assert c.get("/auth/callback", params={"code": "c-1", "state": q["state"]}).headers["location"] == "/?login_error=expired"
    start(c, idp)
    assert c.get("/auth/callback", params={"error": "access_denied"}).headers["location"] == "/?login_error=denied"
    assert c.get("/api/runs").status_code == 401


def test_a_rotated_provider_key_is_fetched_once(site, idp):
    c, _ = site
    sign_in(c, idp)
    c.cookies.clear()
    idp.kid = "k2"
    before = idp.calls.count("/keys")
    assert sign_in(c, idp).headers["location"] == "/"
    assert idp.calls.count("/keys") == before + 1


def test_the_session_cookie_cannot_be_altered_reused_or_outlive_its_expiry(site, idp, monkeypatch):
    c, _ = site
    sign_in(c, idp, groups=["dev"])
    good = c.cookies.get(auth.SESSION_COOKIE)
    body, sig = good.split(".")
    data = json.loads(auth._unb64(body))
    forged = auth._b64(json.dumps({**data, "role": "admin"}).encode())
    for bad in (f"{forged}.{sig}", f"{body}.{sig[:-2]}xx", "x.y", "", auth.seal(data, b"another-secret" * 4, "session", 600),
                auth.seal({**data, "role": "admin"}, b"s" * 40, "login", 600)):   # a login cookie is not a session
        c.cookies.clear()
        c.cookies.set(auth.SESSION_COOKIE, bad)
        assert c.get("/api/runs").status_code == 401, bad
    c.cookies.clear()
    c.cookies.set(auth.SESSION_COOKIE, good)
    assert c.get("/api/runs").status_code == 200
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + auth.SESSION_TTL + 1)
    assert c.get("/api/runs").status_code == 401


def test_logout_ends_the_session(site, idp):
    c, _ = site
    sign_in(c, idp)
    assert c.post("/auth/logout").json() == {"ok": True}
    assert c.get("/api/me").json()["signed_in"] is False and c.get("/api/runs").status_code == 401


def test_a_write_from_another_site_is_refused(site, idp):
    c, r = site
    sign_in(c, idp)
    url, body = f"/api/runs/{r.dir.name}/decisions", {"target": "lib@1.0.0", "status": "approved"}
    assert c.post(url, json=body, headers={"Origin": "https://evil.test"}).status_code == 403
    assert c.post(url, json=body, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert c.post("/auth/logout", headers={"Origin": "https://evil.test"}).status_code == 403
    assert decide.proposals(r)[0].decision is None
    assert c.post(url, json=body, headers={"Origin": "http://testserver"}).status_code == 200


def test_next_only_leads_back_into_this_site(site, idp):
    c, _ = site
    for bad in ("https://evil.test/", "//evil.test", "/\\evil.test", "javascript:alert(1)", "/a\nb"):
        assert sign_in(c, idp, next_path=bad).headers["location"] == "/", bad
        c.cookies.clear()
    assert auth.safe_next("/?run=20261118-030615-realworld") == "/?run=20261118-030615-realworld"


def test_the_callback_address_follows_the_public_url(site, idp, monkeypatch):
    c, _ = site
    monkeypatch.setenv("TRIAGE_PUBLIC_URL", "https://triage.example.com/")
    res = c.get("/auth/login")
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(res.headers["location"]).query))
    assert q["redirect_uri"] == "https://triage.example.com/auth/callback" and "secure" in res.headers["set-cookie"].lower()


def test_a_provider_that_is_down_or_lies_about_itself_starts_no_login(site, idp, monkeypatch):
    c, _ = site
    monkeypatch.setattr(auth, "transport", httpx.MockTransport(lambda req: httpx.Response(503)))
    assert c.get("/auth/login").headers["location"] == "/?login_error=provider"
    other = {"issuer": "https://evil.test", "authorization_endpoint": "https://evil.test/a",
             "token_endpoint": "https://evil.test/t", "jwks_uri": "https://evil.test/k"}
    monkeypatch.setattr(auth, "transport", httpx.MockTransport(lambda req: httpx.Response(200, json=other)))
    assert c.get("/auth/login").headers["location"] == "/?login_error=provider"
    plain = {"issuer": ISSUER, "authorization_endpoint": "http://idp.test/a", "token_endpoint": f"{ISSUER}/t", "jwks_uri": f"{ISSUER}/k"}
    monkeypatch.setattr(auth, "transport", httpx.MockTransport(lambda req: httpx.Response(200, json=plain)))
    assert c.get("/auth/login").headers["location"] == "/?login_error=provider"


@pytest.mark.parametrize("env,word", [
    ({"OIDC_ISSUER": ""}, "OIDC_ISSUER"), ({"OIDC_CLIENT_ID": ""}, "OIDC_CLIENT_ID"),
    ({"TRIAGE_SESSION_SECRET": ""}, "TRIAGE_SESSION_SECRET"), ({"TRIAGE_SESSION_SECRET": "short"}, "32"),
    ({"OIDC_ISSUER": "http://idp.example.com"}, "https"), ({"OIDC_DEFAULT_ROLE": "root"}, "OIDC_DEFAULT_ROLE"),
    ({"TRIAGE_AUTH": "basic"}, "off or oidc"),
])
def test_half_configured_login_is_refused_by_name_without_values(idp, monkeypatch, env, word):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(auth.AuthConfigError) as e:
        auth.settings()
    assert word in str(e.value) and CLIENT_SECRET not in str(e.value) and "s" * 40 not in str(e.value)
    assert auth.describe()[0] == "fail"


def test_the_server_does_not_start_with_broken_login_settings(idp, monkeypatch):
    from triage import api
    monkeypatch.setenv("TRIAGE_SESSION_SECRET", "short")
    with pytest.raises(auth.AuthConfigError):
        with TestClient(api.app):
            pass
