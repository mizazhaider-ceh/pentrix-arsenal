"""PENTRIX ARSENAL module: hidden parameter discovery.

Takes a baseline GET of the target, then appends roughly 40 common hidden
parameter names (admin, debug, test, is_admin, api_key, ...) with a canary
value. A parameter is flagged as discovered when it changes the status
code, changes the response length significantly, or reflects the canary.
One finding per discovered parameter, at low/info severity.

Intrusive: sends about 40 extra requests to the target.
"""

import re
import urllib.parse
from arsenal.modules.base import BaseModule


NAME = "paramminer"
DESCRIPTION = (
    "Discovers hidden query parameters by appending common parameter names "
    "with a canary value and flagging ones that change the response."
)
TARGET_KIND = "url"
INTRUSIVE = True

TIMEOUT = 10
MAX_BODY_BYTES = 2 * 1024 * 1024
CANARY = "ppminer1"

CANDIDATES = [
    "admin", "administrator", "debug", "test", "testing", "dev",
    "id", "user", "username", "role", "is_admin", "isadmin", "isAdmin",
    "admin_user", "superuser", "api_key", "apikey", "apiKey", "token",
    "access_token", "auth", "auth_token", "secret", "key", "password",
    "passwd", "email", "q", "query", "search", "s", "page", "p",
    "lang", "locale", "redirect", "url", "next", "return", "dest",
    "callback", "cb", "format", "output", "view", "action", "cmd",
    "exec", "file", "path", "dir", "include", "template", "theme",
    "preview", "show", "edit", "delete", "mode", "type", "sort",
    "order", "limit", "offset", "filter", "all", "true", "force",
]

CHARSET_RE = re.compile(r"charset=([\w-]+)", re.IGNORECASE)


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
_get = _mod.get
_finding = _mod.finding

def decode_body(headers, body):
    content_type = headers.get("content-type", "")
    match = CHARSET_RE.search(content_type or "")
    charset = match.group(1) if match else "utf-8"
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def append_param(url, name, value):
    parts = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    params.append((name, value))
    query = urllib.parse.urlencode(params)
    return urllib.parse.urlunparse(parts._replace(query=query))


def run(target, ctx):
    """Discover hidden parameters; one finding per discovered parameter."""
    try:
        return _run(target, ctx)
    except Exception as exc:
        _log(ctx, "warning", "%s failed on %s: %s" % (NAME, target, exc))
        return []


def _run(target, ctx):
    if INTRUSIVE and getattr(ctx, "safe_mode", False) \
            and not getattr(ctx, "allow_intrusive", False):
        _log(ctx, "warning", "%s skipped: safe mode blocks intrusive modules"
             % NAME)
        return []
    if not _is_http_url(target):
        return []
    if not _in_scope(target, ctx):
        _log(ctx, "warning", "%s: target out of scope: %s" % (NAME, target))
        return []

    base_resp = _get(target, ctx)
    if base_resp is None:
        return []
    base_status, base_headers, base_body, _final = base_resp
    base_len = len(base_body)
    base_text = decode_body(base_headers, base_body)
    existing = {name for name, _ in urllib.parse.parse_qsl(
        urllib.parse.urlsplit(target).query, keep_blank_values=True)}

    out = []
    for candidate in CANDIDATES:
        if candidate in existing:
            continue
        test_url = append_param(target, candidate, CANARY)
        resp = _get(test_url, ctx)
        if resp is None:
            continue
        status, headers, body, _final = resp
        if len(body) > MAX_BODY_BYTES:
            continue
        text = decode_body(headers, body)
        reasons = []
        if status != base_status:
            reasons.append("status %s -> %s" % (base_status, status))
        if abs(len(body) - base_len) > max(300, int(base_len * 0.15)):
            reasons.append("length %d -> %d bytes" % (base_len, len(body)))
        if CANARY in text and CANARY not in base_text:
            reasons.append("canary value reflected in response")
        if reasons:
            out.append(_finding(
                target=target,
                severity="low",
                confidence="review",
                title="Hidden parameter discovered: '%s'" % candidate,
                description=(
                    "Appending parameter '%s' changed the server response "
                    "(%s), which suggests the application reads it. Hidden "
                    "parameters can expose debug or privileged functionality."
                    % (candidate, "; ".join(reasons))
                ),
                evidence=(
                    "baseline: HTTP %s, %d bytes\n"
                    "?%s=%s -> HTTP %s, %d bytes (%s)"
                    % (base_status, base_len, candidate, CANARY,
                       status, len(body), "; ".join(reasons))
                ),
                cwe="CWE-200",
                remediation=(
                    "Remove or gate undocumented parameters such as '%s'; "
                    "require authentication for privileged functionality."
                    % candidate
                ),
            ))
    return out
