"""PENTRIX ARSENAL module: Host header injection detection.

Sends two probes: one overriding the Host header with evil.example.com
and one sending X-Forwarded-Host: evil.example.com. If the evil host is
reflected in the response body or in a Location header, the application
trusts attacker-controlled host input, which enables password-reset
poisoning, cache poisoning, and SSRF-adjacent issues. Reported at medium
severity.

Non-intrusive: only issues GET requests. Note: the Host override probe
depends on the shared fetch() honoring a caller-supplied Host header;
the X-Forwarded-Host probe works regardless.
"""

import re

from arsenal.modules.base import BaseModule

NAME = "hostheader"
DESCRIPTION = (
    "Tests for Host header injection by overriding Host and sending "
    "X-Forwarded-Host, then checking for reflection of the evil host."
)
TARGET_KIND = "url"
INTRUSIVE = False

TIMEOUT = 10
MAX_BODY_BYTES = 2 * 1024 * 1024
EVIL_HOST = "evil.example.com"

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


def run(target, ctx):
    """Test Host and X-Forwarded-Host handling for reflection."""
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
    probes = [
        ("Host header override", {"Host": EVIL_HOST}),
        ("X-Forwarded-Host", {"X-Forwarded-Host": EVIL_HOST}),
    ]
    out = []
    for probe_name, headers in probes:
        resp = _get(target, ctx, headers)
        if resp is None:
            continue
        _status, resp_headers, body, _final = resp
        if len(body) > MAX_BODY_BYTES:
            continue
        text = decode_body(resp_headers, body)
        location = resp_headers.get("location", "")
        reflected_where = None
        excerpt = ""
        if EVIL_HOST in text.lower():
            idx = text.lower().find(EVIL_HOST)
            reflected_where = "response body"
            excerpt = " ".join(text[max(0, idx - 80):idx + 80].split())
        elif EVIL_HOST in location.lower():
            reflected_where = "Location header"
            excerpt = location
        if reflected_where:
            out.append(_finding(
                target=target,
                severity="medium",
                confidence="review",
                title="Host header injection (%s)" % probe_name,
                description=(
                    "The %s value %s is reflected in the %s: the application "
                    "trusts attacker-controlled host input. This enables "
                    "password-reset poisoning, cache poisoning, and routing "
                    "attacks." % (probe_name, EVIL_HOST, reflected_where)
                ),
                evidence="Probe: %s: %s\nReflected in: %s\nExcerpt: ...%s..."
                         % (probe_name, EVIL_HOST, reflected_where, excerpt),
                cwe="CWE-20",
                remediation=(
                    "Validate the Host header against a whitelist; never "
                    "build absolute URLs from untrusted host input, and "
                    "ignore X-Forwarded-Host unless the proxy is trusted."
                ),
            ))
    return out
