"""SHARED AUTH SESSION MANAGER.

Differentiator #3. nuclei has primitive static auth, ZAP/Burp make
sessions manual and brittle, and nothing gives every module one session
store with automatic token refresh. This module does:

* one session store every module reads via ctx (cookies, bearer JWTs,
  OAuth2 refresh flow),
* auto-refresh on 401 with a configurable refresh hook,
* importable login helpers (form login, bearer, OAuth2 password grant).

Provider API::

    from arsenal import auth
    auth.login_form("target-profile", login_url, "user", "pass")
    sess = auth.get_session(ctx, profile="target-profile")
    status, body, headers = auth.auth_fetch(sess, url)

The ctx carries the active profile name in ctx.config["auth_profile"];
modules call auth.auth_fetch(session, url, ...) instead of raw fetch.
Secrets live in ~/.arsenal/auth.json (mode 0o600), never in the repo.
"""

from __future__ import annotations

import base64
import http.cookiejar
import json
import os
import threading
import time
import urllib.parse
import urllib.request

AUTH_FILE = os.path.join(os.path.expanduser("~"), ".arsenal", "auth.json")

_lock = threading.RLock()
_refresh_hooks: dict[str, callable] = {}


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

def _read_store() -> dict:
    if not os.path.exists(AUTH_FILE):
        return {"profiles": {}}
    try:
        with open(AUTH_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {"profiles": {}}
    except (OSError, ValueError):
        return {"profiles": {}}


def _write_store(store: dict) -> None:
    d = os.path.dirname(AUTH_FILE)
    os.makedirs(d, exist_ok=True)
    tmp = AUTH_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(store, fh, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, AUTH_FILE)


def _profiles() -> dict:
    return _read_store().setdefault("profiles", {})


def _save_profile(name: str, profile: dict) -> None:
    with _lock:
        store = _read_store()
        store.setdefault("profiles", {})[name] = profile
        _write_store(store)


def get_profile(name: str) -> dict | None:
    return _read_store().get("profiles", {}).get(name)


def list_profiles() -> list[str]:
    return sorted(_read_store().get("profiles", {}).keys())


def delete_profile(name: str) -> bool:
    with _lock:
        store = _read_store()
        if name in store.get("profiles", {}):
            del store["profiles"][name]
            _write_store(store)
            return True
    return False


# ---------------------------------------------------------------------------
# Session object: cookie jar + bearer injection + auto-refresh on 401
# ---------------------------------------------------------------------------

class AuthSession:
    """A session bound to one auth profile.

    fetch(method, url, ...) injects cookies + Authorization header, and on
    a 401 runs the refresh hook (if configured) exactly once, then
    retries. Pure stdlib (urllib); no requests dependency.
    """

    def __init__(self, profile_name: str, profile: dict):
        self.profile_name = profile_name
        self.profile = dict(profile or {})
        self.jar = http.cookiejar.CookieJar()
        self._load_cookies()
        self.last_refresh = 0.0

    # -- cookies ---------------------------------------------------------
    def _load_cookies(self):
        for c in self.profile.get("cookies", []) or []:
            try:
                cookie = http.cookiejar.Cookie(
                    version=0, name=c["name"], value=c["value"],
                    port=None, port_specified=False,
                    domain=c.get("domain", ""), domain_specified=bool(c.get("domain")),
                    domain_initial_dot=c.get("domain", "").startswith("."),
                    path=c.get("path", "/"), path_specified=True,
                    secure=bool(c.get("secure")), expires=c.get("expires"),
                    discard=True, comment=None, comment_url=None,
                    rest={}, rfc2109=False)
                self.jar.set_cookie(cookie)
            except Exception:
                continue

    def _dump_cookies(self):
        out = []
        for c in self.jar:
            out.append({"name": c.name, "value": c.value, "domain": c.domain,
                        "path": c.path, "secure": c.secure,
                        "expires": c.expires})
        self.profile["cookies"] = out
        _save_profile(self.profile_name, self.profile)

    # -- bearer ----------------------------------------------------------
    def _auth_header(self):
        token = self.profile.get("bearer") or self.profile.get("access_token")
        if token:
            return {"Authorization": "Bearer " + token}
        basic = self.profile.get("basic")
        if basic:
            raw = ("%s:%s" % (basic.get("username", ""),
                              basic.get("password", ""))).encode()
            return {"Authorization": "Basic " + base64.b64encode(raw).decode()}
        return {}

    # -- refresh ----------------------------------------------------------
    def set_refresh_hook(self, fn: callable) -> None:
        """Configurable refresh hook: fn(profile) -> True if refreshed."""
        _refresh_hooks[self.profile_name] = fn

    def refresh(self) -> bool:
        """Run the OAuth2 refresh flow or the configured hook."""
        hook = _refresh_hooks.get(self.profile_name)
        if hook is not None:
            try:
                ok = bool(hook(self.profile))
            except Exception:
                ok = False
            if ok:
                self.last_refresh = time.time()
                _save_profile(self.profile_name, self.profile)
            return ok
        if self.profile.get("refresh_token") and self.profile.get("token_url"):
            ok = oauth2_refresh(self.profile_name)
            if ok:
                self.profile = get_profile(self.profile_name) or self.profile
                self.last_refresh = time.time()
            return ok
        return False

    def _opener(self):
        return urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def fetch(self, method: str, url: str, data=None, headers=None,
              timeout: int = 15, _retried: bool = False):
        """(status, body_bytes, headers_dict). Auto-refreshes once on 401."""
        req_headers = dict(headers or {})
        req_headers.update(self._auth_header())
        body = None
        if data is not None:
            body = data.encode() if isinstance(data, str) else data
        req = urllib.request.Request(url, data=body, headers=req_headers,
                                     method=method.upper())
        opener = self._opener()
        try:
            with opener.open(req, timeout=timeout) as resp:
                out = (resp.status, resp.read(), dict(resp.headers))
        except urllib.error.HTTPError as exc:
            out = (exc.code, exc.read(), dict(exc.headers))
        status = out[0]
        self._dump_cookies()
        if status == 401 and not _retried:
            if self.refresh():
                return self.fetch(method, url, data=data, headers=headers,
                                  timeout=timeout, _retried=True)
        return out


def get_session(ctx=None, profile: str | None = None) -> AuthSession | None:
    """Every module reads its session through here.

    Profile name comes from the explicit argument, then
    ctx.config["auth_profile"]. Returns None when no profile is set, so
    modules can fall back to unauthenticated requests.
    """
    name = profile
    if not name and ctx is not None:
        cfg = getattr(ctx, "config", {}) or {}
        name = cfg.get("auth_profile")
    if not name:
        return None
    prof = get_profile(name)
    if not prof:
        return None
    sess = AuthSession(name, prof)
    return sess


def auth_fetch(session: AuthSession | None, url: str, method: str = "GET",
               data=None, headers=None, timeout: int = 15):
    """Fetch with auth when a session exists; plain fetch otherwise."""
    if session is None:
        req = urllib.request.Request(url, data=data, headers=headers or {},
                                     method=method.upper())
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), dict(exc.headers)
    return session.fetch(method, url, data=data, headers=headers,
                         timeout=timeout)


# ---------------------------------------------------------------------------
# Login helpers (importable; CLI wiring comes later)
# ---------------------------------------------------------------------------

def login_form(profile_name: str, login_url: str, username: str, password: str,
               user_field: str = "username", pass_field: str = "password",
               extra: dict | None = None, timeout: int = 15) -> bool:
    """POST a login form, keep the resulting cookies in the profile."""
    fields = {user_field: username, pass_field: password}
    fields.update(extra or {})
    data = urllib.parse.urlencode(fields).encode()
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    req = urllib.request.Request(login_url, data=data, method="POST",
                                 headers={"Content-Type":
                                          "application/x-www-form-urlencoded"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            resp.read()
            ok = resp.status < 400
    except urllib.error.HTTPError as exc:
        ok = False
    except OSError:
        return False
    profile = get_profile(profile_name) or {}
    cookies = [{"name": c.name, "value": c.value, "domain": c.domain,
                "path": c.path, "secure": c.secure, "expires": c.expires}
               for c in jar]
    profile["cookies"] = cookies
    profile["login_url"] = login_url
    _save_profile(profile_name, profile)
    return ok and bool(cookies)


def login_bearer(profile_name: str, token: str) -> None:
    profile = get_profile(profile_name) or {}
    profile["bearer"] = token
    _save_profile(profile_name, profile)


def login_basic(profile_name: str, username: str, password: str) -> None:
    profile = get_profile(profile_name) or {}
    profile["basic"] = {"username": username, "password": password}
    _save_profile(profile_name, profile)


def oauth2_password_grant(profile_name: str, token_url: str, client_id: str,
                          username: str, password: str, scope: str = "",
                          timeout: int = 15) -> bool:
    """OAuth2 resource-owner password grant; stores tokens + refresh data."""
    fields = {"grant_type": "password", "client_id": client_id,
              "username": username, "password": password}
    if scope:
        fields["scope"] = scope
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(token_url, data=data, method="POST",
                                 headers={"Content-Type":
                                          "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return False
    if "access_token" not in payload:
        return False
    profile = get_profile(profile_name) or {}
    profile.update({
        "access_token": payload["access_token"],
        "refresh_token": payload.get("refresh_token"),
        "token_url": token_url,
        "client_id": client_id,
        "token_type": payload.get("token_type", "Bearer"),
        "expires_in": payload.get("expires_in"),
        "obtained_at": time.time(),
    })
    _save_profile(profile_name, profile)
    return True


def oauth2_refresh(profile_name: str, timeout: int = 15) -> bool:
    """OAuth2 refresh_token grant against the stored token_url."""
    profile = get_profile(profile_name)
    if not profile or not profile.get("refresh_token") \
            or not profile.get("token_url"):
        return False
    fields = {"grant_type": "refresh_token",
              "refresh_token": profile["refresh_token"],
              "client_id": profile.get("client_id", "")}
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(profile["token_url"], data=data, method="POST",
                                 headers={"Content-Type":
                                          "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return False
    if "access_token" not in payload:
        return False
    profile["access_token"] = payload["access_token"]
    if payload.get("refresh_token"):
        profile["refresh_token"] = payload["refresh_token"]
    profile["obtained_at"] = time.time()
    # the OAuth2 flow is now authoritative: drop any stale manual bearer
    # so _auth_header() sends the fresh access_token, not the old one
    profile.pop("bearer", None)
    _save_profile(profile_name, profile)
    return True


ARGPARSE_SNIPPET = '''
# --- integrator: add to arsenal/cli.py subparsers ---
p = sub.add_parser("auth", help="Shared auth session manager")
asub = p.add_subparsers(dest="auth_cmd", required=True)
l = asub.add_parser("login", help="Store a login session in a profile")
l.add_argument("--profile", required=True)
l.add_argument("--url", help="Login form URL (form login)")
l.add_argument("--username"); l.add_argument("--password")
l.add_argument("--bearer", help="Store a bearer token directly")
l.add_argument("--basic", action="store_true",
               help="Store HTTP basic credentials")
l.set_defaults(func=arsenal.auth.cmd_login)
s = asub.add_parser("status", help="List profiles / show session state")
s.set_defaults(func=arsenal.auth.cmd_status)
'''


def cmd_login(args, ctx) -> int:
    if args.bearer:
        login_bearer(args.profile, args.bearer)
        print("bearer token stored in profile '%s'" % args.profile)
        return 0
    if args.basic:
        login_basic(args.profile, args.username or "", args.password or "")
        print("basic credentials stored in profile '%s'" % args.profile)
        return 0
    if args.url:
        ok = login_form(args.profile, args.url, args.username or "",
                        args.password or "")
        print("form login %s for profile '%s'" % (
            "succeeded" if ok else "FAILED (no session cookies captured)",
            args.profile))
        return 0 if ok else 1
    print("nothing to do: pass --bearer, --basic, or --url")
    return 2


def cmd_status(args, ctx) -> int:
    for name in list_profiles():
        prof = get_profile(name) or {}
        kinds = []
        if prof.get("cookies"):
            kinds.append("%d cookies" % len(prof["cookies"]))
        if prof.get("bearer") or prof.get("access_token"):
            kinds.append("bearer")
        if prof.get("refresh_token"):
            kinds.append("oauth2-refresh")
        if prof.get("basic"):
            kinds.append("basic")
        print("%-20s %s" % (name, ", ".join(kinds) or "empty"))
    return 0
