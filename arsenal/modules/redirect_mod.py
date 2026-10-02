"""PENTRIX ARSENAL module: open redirect detection.

Finds redirect-style query parameters (url, redirect, next, return, dest,
continue, ...) in the target URL. When the URL has none, it tries appending
?next= and ?url=. Each candidate is set to https://evil.example.com/ and
fetched with redirects disabled; if the Location header points at the evil
host, an open redirect is reported. Confidence starts at "review"; the
verify step follows the redirect chain and can promote to "proven".

Non-intrusive: only issues GET requests, never follows the redirect.
"""

import urllib.parse
from arsenal.modules.base import BaseModule


NAME = "redirect"
DESCRIPTION = (
    "Detects open redirects by pointing redirect-style query parameters at "
    "an external host and checking whether the Location header follows it."
)
TARGET_KIND = "url"
INTRUSIVE = False

TIMEOUT = 10
EVIL_URL = "https://evil.example.com/"
EVIL_HOST = "evil.example.com"

REDIRECT_PARAMS = (
    "url", "redirect", "redirect_url", "redirecturl", "next", "return",
    "return_url", "returnurl", "dest", "destination", "continue", "target",
    "to", "goto", "redir", "r", "u", "forward", "link",
)


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

def build_test_url(url, params, target_idx, value):
    parts = urllib.parse.urlparse(url)
    new_params = [
        (name, value if i == target_idx else val)
        for i, (name, val) in enumerate(params)
    ]
    query = urllib.parse.urlencode(new_params)
    return urllib.parse.urlunparse(parts._replace(query=query))


def append_param(url, name, value):
    parts = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    params.append((name, value))
    query = urllib.parse.urlencode(params)
    return urllib.parse.urlunparse(parts._replace(query=query))


def run(target, ctx):
    """Test redirect-style parameters for open redirect."""
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
    params = urllib.parse.parse_qsl(
        urllib.parse.urlsplit(target).query, keep_blank_values=True)

    test_urls = []  # (param_name, test_url)
    for idx, (name, _value) in enumerate(params):
        if name.lower() in REDIRECT_PARAMS:
            test_urls.append((name, build_test_url(target, params, idx, EVIL_URL)))
    if not test_urls:
        # No redirect-style parameter present: try the common ones.
        test_urls.append(("next", append_param(target, "next", EVIL_URL)))
        test_urls.append(("url", append_param(target, "url", EVIL_URL)))

    out = []
    for param_name, test_url in test_urls:
        resp = _get_no_redirect(test_url, ctx)
        if resp is None:
            continue
        status, headers, _body, _final = resp
        location = headers.get("location", "")
        if not location:
            continue
        loc_host = _host_of(urllib.parse.urljoin(test_url, location))
        if loc_host.lower() == EVIL_HOST:
            out.append(_finding(
                target=target,
                severity="high",
                confidence="review",
                title="Open redirect in parameter '%s'" % param_name,
                description=(
                    "Parameter '%s' controls the redirect destination: "
                    "setting it to an external URL makes the server respond "
                    "with a redirect to that host. Attackers can abuse this "
                    "for phishing." % param_name
                ),
                evidence=(
                    "Request: %s\nHTTP %s\nLocation: %s"
                    % (test_url, status, location)
                ),
                cwe="CWE-601",
                remediation=(
                    "Validate redirect targets against an allow-list of "
                    "trusted hosts/paths instead of accepting arbitrary URLs."
                ),
            ))
    return out
