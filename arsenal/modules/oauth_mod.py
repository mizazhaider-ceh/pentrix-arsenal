"""PENTRIX ARSENAL module: OAuth authorization endpoint checks.

Probes common OAuth/OIDC authorization paths (/oauth/authorize,
/authorize, /connect/authorize, ...) with redirect_uri set to
https://evil.example.com/. If the server redirects to the evil host, the
redirect_uri is not validated (high). It also tests response_type=token:
if the endpoint accepts the implicit flow, a medium finding is reported.

Non-intrusive: only issues GET requests with redirects disabled.
"""

import urllib.parse
from arsenal.modules.base import BaseModule


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


# ---------------------------------------------------------------------------
# Shared module helpers, bound from arsenal.modules.base (replaces the old
# per-module copies). All HTTP goes through arsenal.http with ctx, so
# stealth sleeps, UA rotation and proxy settings apply to module traffic.
# ---------------------------------------------------------------------------
_mod = BaseModule(NAME, TIMEOUT)
_timeout = _mod.timeout
_log = _mod.log
_is_http_url = _mod.is_http_url
_host_of = _mod.host_of
_in_scope = _mod.in_scope
_get_no_redirect = _mod.get_no_redirect
_finding = _mod.finding

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
            loc2_host = _host_of(
                urllib.parse.urljoin(endpoint, location2)).lower()
            # Tight rule: the endpoint only "accepts" the implicit flow
            # when it redirects back to the untrusted redirect_uri we
            # supplied (carrying token material), not when it merely
            # bounces to a same-host login page.
            accepted = (
                status2 in (301, 302, 303, 307, 308)
                and location2
                and "error" not in location2.lower()
                and (loc2_host == EVIL_HOST
                     or "access_token" in location2.lower()
                     or "id_token" in location2.lower())
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
        # No break: every authorize path that exists gets fully tested.
    return out
