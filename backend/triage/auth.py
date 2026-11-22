"""Login and roles (HANDOFF D47).

TRIAGE_AUTH=off (default): no login. The offline demo and the tests run this way; the name on a
decision is whatever the person typed.

TRIAGE_AUTH=oidc: OpenID Connect authorization code flow with PKCE against the provider at
OIDC_ISSUER. The ID token is checked (signature against the provider's keys, issuer, audience,
expiry, nonce) and the person's groups are mapped to one of three roles:

    viewer    read runs, findings, proposals and patches
    approver  viewer + record decisions, export approved changes, start sandbox work
    admin     approver + actions that cost money or change configuration (none on screen yet)

A person whose groups match no role gets OIDC_DEFAULT_ROLE, and no access when that is unset.

The session is a signed cookie (HMAC-SHA256 with TRIAGE_SESSION_SECRET), so API processes share
nothing but the secret. It cannot be revoked before it expires (8 hours); a role change at the
provider takes effect at the next login.

This module is the only place besides the LLM adapters and notify.py that sends anything out
(CLAUDE.md rule 6), and only to the configured provider: the authorization code, the client
credentials and the PKCE verifier. No run data leaves through it.
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import urllib.parse
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from .models import Me

log = logging.getLogger(__name__)

ROLES = ("viewer", "approver", "admin")          # each includes the ones before it
ROLE_KO = {"viewer": "열람", "approver": "승인", "admin": "관리"}
SESSION_COOKIE, FLOW_COOKIE = "triage_session", "triage_login"
SESSION_TTL, FLOW_TTL = 8 * 3600, 600
ALGS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512")   # never "none" or HS*
PROVIDER_TTL = 3600.0
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")

transport: httpx.BaseTransport | None = None      # tests put a fake identity provider here
_provider_cache: dict[str, tuple[float, dict]] = {}
_jwks_cache: dict[str, tuple[float, dict]] = {}


class AuthConfigError(RuntimeError):
    """The login settings are incomplete. The message names variables, never values."""


class LoginError(Exception):
    """A login that must not produce a session. `code` is what the sign-in screen is told."""
    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code


@dataclasses.dataclass(frozen=True)
class User:
    sub: str
    name: str
    email: str | None
    role: str
    local: bool = False          # True when login is off: nobody was identified


LOCAL = User(sub="", name="", email=None, role="admin", local=True)


@dataclasses.dataclass(frozen=True)
class Settings:
    mode: str
    issuer: str = ""
    client_id: str = ""
    client_secret: str = ""
    secret: bytes = b""
    public_url: str = ""
    scopes: str = "openid profile email"
    roles_claim: str = "groups"
    groups: tuple[tuple[str, frozenset[str]], ...] = ()
    default_role: str | None = None


def _list(name: str) -> frozenset[str]:
    return frozenset(x.strip() for x in os.environ.get(name, "").split(",") if x.strip())


def settings() -> Settings:
    """Read the login settings from the environment. Raises AuthConfigError when oidc is half set."""
    env = os.environ.get
    mode = env("TRIAGE_AUTH", "off").strip().lower() or "off"
    public_url = env("TRIAGE_PUBLIC_URL", "").strip().rstrip("/")
    if mode == "off":
        return Settings(mode="off", public_url=public_url)
    if mode != "oidc":
        raise AuthConfigError("TRIAGE_AUTH must be off or oidc")
    missing = [k for k in ("OIDC_ISSUER", "OIDC_CLIENT_ID", "TRIAGE_SESSION_SECRET") if not env(k, "").strip()]
    if missing:
        raise AuthConfigError(f"TRIAGE_AUTH=oidc needs {', '.join(missing)}")
    secret = env("TRIAGE_SESSION_SECRET", "").strip()
    if len(secret) < 32:
        raise AuthConfigError("TRIAGE_SESSION_SECRET must be at least 32 characters (python -c 'import secrets; print(secrets.token_urlsafe(48))')")
    issuer = env("OIDC_ISSUER", "").strip().rstrip("/")
    if not _trusted_url(issuer, issuer):
        raise AuthConfigError("OIDC_ISSUER must be an https URL (http is accepted for localhost only)")
    default = env("OIDC_DEFAULT_ROLE", "").strip().lower() or None
    if default == "none":
        default = None
    if default not in (None, *ROLES):
        raise AuthConfigError("OIDC_DEFAULT_ROLE must be viewer, approver, admin or none")
    return Settings(
        mode="oidc", issuer=issuer, client_id=env("OIDC_CLIENT_ID", "").strip(),
        client_secret=env("OIDC_CLIENT_SECRET", "").strip(), secret=secret.encode(), public_url=public_url,
        scopes=env("OIDC_SCOPES", "").strip() or "openid profile email",
        roles_claim=env("OIDC_ROLES_CLAIM", "").strip() or "groups",
        groups=tuple((r, _list(f"OIDC_{r.upper()}_GROUPS")) for r in ROLES), default_role=default)


def allows(have: str | None, need: str) -> bool:
    return have in ROLES and ROLES.index(have) >= ROLES.index(need)


# ---- signed cookies ----

def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _mac(secret: bytes, purpose: str, body: str) -> str:
    return _b64(hmac.new(secret, f"{purpose}.{body}".encode(), hashlib.sha256).digest())


def seal(data: dict, secret: bytes, purpose: str, ttl: int) -> str:
    body = _b64(json.dumps({**data, "exp": int(time.time()) + ttl}, separators=(",", ":")).encode())
    return f"{body}.{_mac(secret, purpose, body)}"


def unseal(token: str | None, secret: bytes, purpose: str) -> dict | None:
    """-> the data, or None when the token is missing, altered, made for another purpose or expired."""
    try:
        body, sig = (token or "").split(".")
        if not hmac.compare_digest(sig, _mac(secret, purpose, body)):
            return None
        data = json.loads(_unb64(body))
        return data if isinstance(data, dict) and data.get("exp", 0) > time.time() else None
    except (ValueError, TypeError):
        return None


# ---- the identity provider ----

def _trusted_url(url: str, issuer: str) -> bool:
    """https, or plain http only when the issuer itself is a local development provider."""
    u = urllib.parse.urlsplit(url)
    if u.scheme == "https" and u.hostname:
        return True
    return u.scheme == "http" and u.hostname in LOCAL_HOSTS and urllib.parse.urlsplit(issuer).hostname in LOCAL_HOSTS


def _http() -> httpx.Client:
    return httpx.Client(timeout=10, transport=transport, follow_redirects=False)


def _fetch_json(url: str) -> dict:
    with _http() as c:
        res = c.get(url, headers={"Accept": "application/json"})
    res.raise_for_status()
    data = res.json()
    if not isinstance(data, dict):
        raise ValueError("not a JSON object")
    return data


def provider(s: Settings) -> dict:
    """The provider's discovery document, kept for an hour."""
    hit = _provider_cache.get(s.issuer)
    if hit and hit[0] > time.time() - PROVIDER_TTL:
        return hit[1]
    doc = _fetch_json(f"{s.issuer}/.well-known/openid-configuration")
    if str(doc.get("issuer", "")).rstrip("/") != s.issuer:
        raise LoginError("failed", "discovery document names a different issuer")
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not _trusted_url(str(doc.get(key, "")), s.issuer):
            raise LoginError("failed", f"discovery document has no usable {key}")
    _provider_cache[s.issuer] = (time.time(), doc)
    return doc


def _keys(s: Settings, refresh: bool = False) -> list[dict]:
    hit = _jwks_cache.get(s.issuer)
    if not hit or refresh or hit[0] <= time.time() - PROVIDER_TTL:
        hit = (time.time(), _fetch_json(provider(s)["jwks_uri"]))
        _jwks_cache[s.issuer] = hit
    return [k for k in hit[1].get("keys", []) if isinstance(k, dict) and k.get("use", "sig") == "sig"]


def verify_id_token(s: Settings, token: str, nonce: str) -> dict:
    """-> the claims of a token this provider signed for this client in this login. Raises LoginError."""
    import jwt                                        # PyJWT, from the "auth" extra
    try:
        head = jwt.get_unverified_header(token)
        if head.get("alg") not in ALGS:
            raise LoginError("failed", f"ID token algorithm {head.get('alg')!r} is not accepted")
        kid = head.get("kid")
        match = [k for k in _keys(s) if kid is None or k.get("kid") == kid]
        if not match and kid is not None:              # the provider may have rotated its keys
            match = [k for k in _keys(s, refresh=True) if k.get("kid") == kid]
        if len(match) != 1:
            raise LoginError("failed", "no single provider key matches the ID token")
        claims = jwt.decode(token, key=jwt.PyJWK.from_dict(match[0]).key, algorithms=[head["alg"]],
                            audience=s.client_id, issuer=provider(s)["issuer"], leeway=60,
                            options={"require": ["exp", "iat", "sub", "aud", "iss"]})
    except jwt.PyJWTError as e:
        raise LoginError("failed", f"ID token rejected: {e}") from e
    aud = claims.get("aud")
    if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != s.client_id:
        raise LoginError("failed", "ID token was issued to another client")
    if not nonce or not hmac.compare_digest(str(claims.get("nonce", "")), nonce):
        raise LoginError("failed", "ID token does not belong to this login (nonce)")
    return claims


def _claim(claims: dict, path: str) -> Any:
    """A claim by name ("groups", "https://example.com/roles") or by dotted path ("realm_access.roles")."""
    if path in claims:
        return claims[path]
    cur: Any = claims
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def role_for(s: Settings, claims: dict) -> str | None:
    raw = _claim(claims, s.roles_claim)
    have = {str(x) for x in raw} if isinstance(raw, (list, tuple)) else ({raw} if isinstance(raw, str) else set())
    for role, names in reversed(s.groups):             # the highest matching role wins
        if have & names:
            return role
    return s.default_role


def begin(s: Settings, next_path: str, redirect_uri: str) -> tuple[str, str]:
    """-> (where to send the browser, the value of the short-lived login cookie)."""
    state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    query = urllib.parse.urlencode({
        "response_type": "code", "client_id": s.client_id, "redirect_uri": redirect_uri, "scope": s.scopes,
        "state": state, "nonce": nonce, "code_challenge_method": "S256",
        "code_challenge": _b64(hashlib.sha256(verifier.encode()).digest())})
    endpoint = provider(s)["authorization_endpoint"]
    flow = {"state": state, "nonce": nonce, "verifier": verifier, "next": safe_next(next_path), "redirect_uri": redirect_uri}
    return f"{endpoint}{'&' if '?' in endpoint else '?'}{query}", seal(flow, s.secret, "login", FLOW_TTL)


def finish(s: Settings, flow_cookie: str | None, code: str, state: str) -> tuple[User, str]:
    """Exchange the code, check the ID token, map the role. -> (user, where to go next)."""
    flow = unseal(flow_cookie, s.secret, "login")
    if flow is None:
        raise LoginError("expired", "no valid login cookie")
    if not code or not state or not hmac.compare_digest(str(flow.get("state", "")), state):
        raise LoginError("failed", "state does not match the login that was started")
    doc = provider(s)
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": flow["redirect_uri"],
            "client_id": s.client_id, "code_verifier": flow["verifier"]}
    basic = None
    if s.client_secret:
        if "client_secret_basic" in doc.get("token_endpoint_auth_methods_supported", ["client_secret_basic"]):
            basic = (urllib.parse.quote(s.client_id, safe=""), urllib.parse.quote(s.client_secret, safe=""))
        else:
            form["client_secret"] = s.client_secret
    try:
        with _http() as c:
            res = c.post(doc["token_endpoint"], data=form, auth=basic, headers={"Accept": "application/json"})
        tokens = res.json() if res.status_code == 200 else None
    except (httpx.HTTPError, ValueError) as e:
        raise LoginError("failed", f"token request failed: {type(e).__name__}") from e
    if not isinstance(tokens, dict) or not tokens.get("id_token"):
        raise LoginError("failed", f"token endpoint answered {res.status_code} without an ID token")
    claims = verify_id_token(s, tokens["id_token"], flow["nonce"])
    if _claim(claims, s.roles_claim) is None and tokens.get("access_token") and _trusted_url(str(doc.get("userinfo_endpoint", "")), s.issuer):
        claims = {**_userinfo(doc["userinfo_endpoint"], tokens["access_token"], claims["sub"]), **claims}
    role = role_for(s, claims)
    if role is None:
        raise LoginError("no_role", f"subject {claims['sub']!r} has no group that maps to a role")
    email = claims.get("email") if isinstance(claims.get("email"), str) else None
    name = next((str(claims[k]) for k in ("name", "preferred_username", "email") if claims.get(k)), str(claims["sub"]))
    return User(sub=str(claims["sub"]), name=name.strip()[:60], email=email, role=role), flow["next"]


def _userinfo(url: str, access_token: str, sub: str) -> dict:
    """Group claims some providers leave out of the ID token. Ignored unless it is about the same subject."""
    try:
        with _http() as c:
            res = c.get(url, headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"})
        info = res.json() if res.status_code == 200 else {}
    except (httpx.HTTPError, ValueError):
        return {}
    return info if isinstance(info, dict) and info.get("sub") == sub else {}


def safe_next(path: str | None) -> str:
    """Only a path on this site: no scheme, no host, no backslash tricks."""
    p = path or "/"
    ok = p.startswith("/") and not p.startswith("//") and "\\" not in p and all(ord(ch) >= 32 for ch in p)
    return p if ok else "/"


# ---- FastAPI side ----

def _origin(s: Settings, request: Request) -> str:
    return s.public_url or f"{request.url.scheme}://{request.headers.get('host', request.url.netloc)}"


def same_site(request: Request, s: Settings | None = None) -> None:
    """Refuse a write that a page on another site made the browser send (the cookie rides along)."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    origin = request.headers.get("origin")
    if origin is not None:
        if origin.rstrip("/") != _origin(s or settings(), request):
            raise HTTPException(403, "다른 사이트에서 보낸 요청은 받지 않습니다.")
    elif request.headers.get("sec-fetch-site", "same-origin") not in ("same-origin", "none"):
        raise HTTPException(403, "다른 사이트에서 보낸 요청은 받지 않습니다.")


def current(request: Request, s: Settings | None = None) -> User | None:
    """The signed-in person, LOCAL when login is off, None when there is no valid session."""
    s = s or settings()
    if s.mode == "off":
        return LOCAL
    data = unseal(request.cookies.get(SESSION_COOKIE), s.secret, "session")
    if not data or data.get("role") not in ROLES or not data.get("sub"):
        return None
    return User(sub=data["sub"], name=str(data.get("name") or data["sub"]), email=data.get("email"), role=data["role"])


def require(role: str):
    """A FastAPI dependency: the caller must be signed in with at least this role."""
    def dependency(request: Request) -> User:
        s = settings()
        same_site(request, s)
        user = current(request, s)
        if user is None:
            raise HTTPException(401, "로그인이 필요합니다.")
        if not allows(user.role, role):
            raise HTTPException(403, f"이 작업에는 {ROLE_KO[role]} 권한이 필요합니다. 지금 계정은 {ROLE_KO[user.role]} 권한입니다.")
        return user
    return dependency


viewer, approver, admin = require("viewer"), require("approver"), require("admin")
router = APIRouter()


def _cookie(res, name: str, value: str, ttl: int, secure: bool) -> None:
    res.set_cookie(name, value, max_age=ttl, httponly=True, samesite="lax", secure=secure, path="/")


@router.get("/api/me")
def me(request: Request) -> Me:
    s = settings()
    user = current(request, s)
    if s.mode == "off":
        return Me(mode="off", signed_in=False, role="admin")
    if user is None:
        return Me(mode="oidc", signed_in=False)
    return Me(mode="oidc", signed_in=True, name=user.name, email=user.email, role=user.role)


@router.get("/auth/login")
def login(request: Request, next: str = "/"):
    s = settings()
    if s.mode == "off":
        return RedirectResponse(safe_next(next), 303)
    base = _origin(s, request)
    try:
        url, flow = begin(s, next, f"{base}/auth/callback")
    except (LoginError, httpx.HTTPError, ValueError) as e:
        log.warning("login could not start: %s", e)
        return RedirectResponse("/?login_error=provider", 303)
    res = RedirectResponse(url, 303)
    _cookie(res, FLOW_COOKIE, flow, FLOW_TTL, base.startswith("https://"))
    return res


@router.get("/auth/callback")
def callback(request: Request, code: str = "", state: str = "", error: str = ""):
    s = settings()
    if s.mode == "off":
        return RedirectResponse("/", 303)
    secure = _origin(s, request).startswith("https://")
    try:
        if error:
            raise LoginError("denied", f"provider returned {error[:60]!r}")
        user, target = finish(s, request.cookies.get(FLOW_COOKIE), code, state)
        res = RedirectResponse(target, 303)
        session = {"sub": user.sub, "name": user.name, "email": user.email, "role": user.role}
        _cookie(res, SESSION_COOKIE, seal(session, s.secret, "session", SESSION_TTL), SESSION_TTL, secure)
        log.info("signed in: %s as %s", user.sub, user.role)
    except LoginError as e:
        log.warning("login refused (%s): %s", e.code, e)
        res = RedirectResponse(f"/?login_error={e.code}", 303)
    except (httpx.HTTPError, ValueError) as e:
        log.warning("login failed: %s", type(e).__name__)
        res = RedirectResponse("/?login_error=provider", 303)
    res.delete_cookie(FLOW_COOKIE, path="/")
    return res


@router.post("/auth/logout")
def logout(request: Request) -> JSONResponse:
    same_site(request)
    res = JSONResponse({"ok": True})
    res.delete_cookie(SESSION_COOKIE, path="/")
    return res


def describe() -> tuple[str, str]:
    """For `triage doctor`: (ok|warn|fail, one line). Names variables, never values."""
    try:
        s = settings()
    except AuthConfigError as e:
        return "fail", str(e)
    if s.mode == "off":
        return "ok", "off (로그인 없음. 시연과 로컬 전용이며 운영에서는 oidc로 설정)"
    try:
        import jwt  # noqa: F401
    except ImportError:
        return "fail", "oidc인데 PyJWT가 없음 (uv sync --extra auth)"
    mapped = [r for r, names in s.groups if names]
    note = f"역할 그룹 {', '.join(mapped) or '미설정'}, 기본 역할 {s.default_role or '없음(그룹 없으면 접근 거부)'}"
    if not mapped and s.default_role is None:
        return "warn", f"oidc ({note}): 아무도 로그인할 수 없음. OIDC_APPROVER_GROUPS 등을 설정"
    if not s.public_url:
        return "warn", f"oidc ({note}). TRIAGE_PUBLIC_URL 미설정: 요청의 Host로 콜백 주소를 만듦"
    return "ok", f"oidc ({note})"
