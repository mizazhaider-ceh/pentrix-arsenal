"""PENTRIX ARSENAL module: web cache poisoning probe.

Sends X-Forwarded-Host: evil.example.com together with a cache-buster
query parameter. If the evil host is reflected in the response body AND
the response carries cache indicators (Age header, X-Cache/Cf-Cache-Status
HIT, etc.), the reflection may be served to other visitors from cache.
Reported at medium severity. Deliberately conservative: both conditions
must hold, otherwise no finding.

Intrusive: sends a header-poisoning probe. Detection only.
"""

import re
import urllib.parse

from arsenal.findings import make_finding
from arsenal.http import fetch

NAME = "cachepoison"
DESCRIPTION = (
    "Probes for web cache poisoning by reflecting X-Forwarded-Host and "
    "checking for cache indicators in the response."
)
TARGET_KIND = "url"
INTRUSIVE = True

TIMEOUT = 10
MAX_BODY_BYTES = 2 * 1024 * 1024
EVIL_HOST = "evil.example.com"
CACHE_BUSTER = "ppcache1"

CHARSET_RE = re.compile(r"charset=([\w-]+)", re.IGNORECASE)


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


def _get(url, ctx, headers):
    try:
        return fetch(url, headers=headers, timeout=_timeout(ctx),
                     allow_redirects=True)
    except Exception as exc:
        _log(ctx, "debug", "%s: request failed for %s: %s" % (NAME, url, exc))
        return None


def _finding(**kwargs):
    kwargs.setdefault("module", NAME)
    return make_finding(**kwargs)


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


def has_cache_indicators(headers):
    """True when the response looks like it came from (or into) a cache."""
    if headers.get("age") is not None:
        return True, "Age: %s" % headers.get("age")
    for name in ("x-cache", "cf-cache-status", "x-varnish-cache",
                 "x-cache-status"):
        value = headers.get(name, "")
        if value and "hit" in value.lower():
            return True, "%s: %s" % (name, value)
    if headers.get("x-varnish") or headers.get("via"):
        return True, "cache proxy header present"
    return False, ""


def run(target, ctx):
    """Probe for cache poisoning; conservative, both signals required."""
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
    test_url = append_param(target, "_cb", CACHE_BUSTER)
    resp = _get(test_url, ctx, {"X-Forwarded-Host": EVIL_HOST})
    if resp is None:
        return []
    _status, headers, body, _final = resp
    if len(body) > MAX_BODY_BYTES:
        return []
    text = decode_body(headers, body)
    if EVIL_HOST not in text.lower():
        return []
    cached, cache_evidence = has_cache_indicators(headers)
    if not cached:
        return []
    idx = text.lower().find(EVIL_HOST)
    excerpt = " ".join(text[max(0, idx - 80):idx + 80].split())
    return [_finding(
        target=target,
        severity="medium",
        confidence="review",
        title="Cache poisoning possible",
        description=(
            "The X-Forwarded-Host value (%s) is reflected in the response "
            "body and the response carries cache indicators (%s). A poisoned "
            "response containing the attacker host may be cached and served "
            "to other visitors." % (EVIL_HOST, cache_evidence)
        ),
        evidence="Request: %s (X-Forwarded-Host: %s)\nCache signal: %s\n"
                 "Response excerpt: ...%s..."
                 % (test_url, EVIL_HOST, cache_evidence, excerpt),
        cwe="CWE-345",
        remediation=(
            "Do not use untrusted Host/X-Forwarded-Host values when "
            "building responses; key the cache on the full Host header and "
            "mark uncacheable responses appropriately."
        ),
    )]
