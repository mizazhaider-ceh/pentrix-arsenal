"""PENTRIX ARSENAL module: prototype pollution sink detection.

Appends ?__proto__[polluted]=pp1 and ?constructor[prototype][polluted2]=pp2
to the target and fetches the page. A finding is reported only on a
positive signal: the response (typically JSON) echoes the injected keys
together with the canary values, which suggests the input reaches object
construction code. Deliberately conservative: anything less than a clear
echo produces no finding.

Intrusive: sends crafted query parameters. Detection only.
"""

import re
import urllib.parse
from arsenal.modules.base import BaseModule


NAME = "ppollution"
DESCRIPTION = (
    "Tests for client/server-side prototype pollution sinks by injecting "
    "__proto__ and constructor[prototype] keys and checking for echo."
)
TARGET_KIND = "url"
INTRUSIVE = True

TIMEOUT = 10
MAX_BODY_BYTES = 2 * 1024 * 1024

PROBES = [
    ("__proto__[polluted]", "pp1"),
    ("constructor[prototype][polluted2]", "pp2"),
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
    """Probe for prototype pollution sinks; conservative positive-only."""
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
    for key, canary in PROBES:
        test_url = append_param(target, key, canary)
        resp = _get(test_url, ctx)
        if resp is None:
            continue
        _status, headers, body, _final = resp
        if len(body) > MAX_BODY_BYTES:
            continue
        text = decode_body(headers, body)
        # Positive signal only: the injected key and its canary value are
        # both echoed, suggesting the input reaches object construction.
        key_echoed = ("polluted" in text and "__proto__" in text) \
            or "polluted2" in text
        value_echoed = canary in text
        if key_echoed and value_echoed:
            idx = text.find(canary)
            excerpt = " ".join(text[max(0, idx - 80):idx + 80].split())
            return [_finding(
                target=target,
                severity="low",
                confidence="review",
                title="Possible prototype pollution sink",
                description=(
                    "The prototype pollution probe key %r was echoed in the "
                    "response together with its canary value, which suggests "
                    "the input reaches object construction code. Manual "
                    "verification is needed to confirm exploitability."
                    % key
                ),
                evidence="Request: %s\nResponse excerpt: ...%s..."
                         % (test_url, excerpt),
                cwe="CWE-1321",
                remediation=(
                    "Avoid recursive merge of untrusted input into objects; "
                    "use Map or objects created with null prototype, and "
                    "validate/sanitize keys such as __proto__."
                ),
            )]
    return []
