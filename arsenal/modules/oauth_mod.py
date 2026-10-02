"""PENTRIX ARSENAL module: OAuth authorization endpoint checks.

Probes common OAuth/OIDC authorization paths (/oauth/authorize,
/authorize, /connect/authorize, ...) with redirect_uri set to
https://evil.example.com/. If the server redirects to the evil host, the
redirect_uri is not validated (high). It also tests response_type=token:
if the endpoint accepts the implicit flow, a medium finding is reported.

Non-intrusive: only issues GET requests with redirects disabled.
"""

import urllib.parse

from arsenal.findings import make_finding
from arsenal.http import fetch

NAME = "oauth"
DESCRIPTION = (
    "Tests OAuth/OIDC authorization endpoints for unvalidated redirect_uri "
    "values and for acceptance of the implicit flow (response_type=token)."
)
TARGET_KIND = "url"
INTRUSIVE = False

TIMEOUT = 10
EVIL_URL = "https://evil.example.com/"
EVIL_HOST = "evil.example.com"

PATH_VARIANTS = [
    "/oauth/authorize",
    "/oauth2/authorize",
    "/authorize",
    "/connect/authorize",
    "/oauth/v2/authorize",
    "/auth/authorize",
]


def _timeout(ctx):
    cfg = getattr(ctx, "config", None)
    if isinstance(cfg, dict):
        return cfg.get("timeout", TIMEOUT)
    if cfg is not None:
        return getattr(cfg, "timeout", TIMEOUT)
    return TIMEOUT


def _log(ctx, level, msg):
    log = getattr(ctx, "log", None)
    if log is None:
        return
    try:
        getattr(log, level, log.warning)(msg)
    except Exception:
        pass


def _is_http_url(target):
    try:
        parts = urllib.parse.urlsplit(target)
    except Exception:
        return False
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def _host_of(url):
    try:
        return urllib.parse.urlsplit(url).hostname or ""
    except Exception:
        return ""


def _in_scope(target, ctx):
    scope = getattr(ctx, "scope", None)
    if scope is None:
        return True
    try:
        return bool(scope.contains(_host_of(target)))
    except Exception:
        return True


def _get_no_redirect(url, ctx):
    try:
        return fetch(url, timeout=_timeout(ctx), allow_redirects=False)
    except Exception as exc:
        _log(ctx, "debug", "%s: request failed for %s: %s" % (NAME, url, exc))
        return None


def _finding(**kwargs):
    kwargs.setdefault("module", NAME)
    return make_finding(**kwargs)


def run(target, ctx):
    """Test OAuth endpoints for redirect_uri validation and implicit flow."""
    try:
        return _run(target, ctx)
    except Exception as exc:
        _log(ctx, "warning", "%s failed on %s: %s" % (NAME, target, exc))
        return []


def _run(target, ctx):
    if not _is_http_url(target):
        return []
    if not _in_scope(target, ctx):
        _log(ctx, "warning", "%s: target out of scope: %s" % (NAME, target))
        return []
    base = target.rstrip("/")
    out = []
    for variant in PATH_VARIANTS:
        endpoint = base + variant
        params = urllib.parse.urlencode({
            "client_id": "pentrix-test",
            "redirect_uri": EVIL_URL,
            "response_type": "code",
            "scope": "openid",
        })
        resp = _get_no_redirect("%s?%s" % (endpoint, params), ctx)
        if resp is None:
            continue
        status, headers, _body, _final = resp
        if status == 404:
            continue
        location = headers.get("location", "")
        if location:
            loc_host = _host_of(urllib.parse.urljoin(endpoint, location))
            if loc_host.lower() == EVIL_HOST:
                out.append(_finding(
                    target=target,
                    severity="high",
                    confidence="review",
                    title="OAuth redirect_uri not validated",
                    description=(
                        "The OAuth authorization endpoint at %s redirects "
                        "to the untrusted redirect_uri "
                        "https://evil.example.com/ without validation, "
                        "allowing authorization codes/tokens to be sent to "
                        "an attacker." % endpoint
                    ),
                    evidence="GET %s?%s\nHTTP %s\nLocation: %s"
                             % (endpoint, params, status, location),
                    cwe="CWE-601",
                    remediation=(
                        "Validate redirect_uri against a pre-registered "
                        "allow-list per client; reject anything else."
                    ),
                ))
        # Implicit flow check: response_type=token.
        implicit_params = urllib.parse.urlencode({
            "client_id": "pentrix-test",
            "redirect_uri": EVIL_URL,
            "response_type": "token",
            "scope": "openid",
        })
        resp2 = _get_no_redirect("%s?%s" % (endpoint, implicit_params), ctx)
        if resp2 is not None:
            status2, headers2, _body2, _final2 = resp2
            location2 = headers2.get("location", "")
            accepted = (
                status2 in (301, 302, 303, 307, 308)
                and location2
                and "error" not in location2.lower()
            )
            if accepted:
                out.append(_finding(
                    target=target,
                    severity="medium",
                    confidence="review",
                    title="OAuth implicit flow accepted (response_type=token)",
                    description=(
                        "The authorization endpoint at %s accepts "
                        "response_type=token (implicit flow), which returns "
                        "access tokens in the URL fragment where they can "
                        "leak via history, logs, or referrers." % endpoint
                    ),
                    evidence="GET %s?%s\nHTTP %s\nLocation: %s"
                             % (endpoint, implicit_params, status2, location2),
                    cwe="CWE-200",
                    remediation=(
                        "Disable the implicit flow; use the authorization "
                        "code flow with PKCE instead."
                    ),
                ))
        break  # only test the first endpoint that exists
    return out
