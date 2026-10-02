"""jsintel: JavaScript intelligence engine.

TARGET_KIND "url". Crawls the JavaScript served by the target page, extracts
hidden API endpoints (quoted /api/ and /v1/ paths, full same-host URLs,
fetch() call targets) and parameter names, then probes each discovered
endpoint without authentication. Flags unauthenticated JSON APIs, verbose
error output, and exposed debug or admin interfaces.

Probing is active network testing, so INTRUSIVE is True and run() refuses to
probe when ctx.safe_mode is set or ctx.allow_intrusive is False.

Module contract: NAME, DESCRIPTION, TARGET_KIND, INTRUSIVE,
run(target, ctx) -> list[dict]. ctx provides .config, .log, .workspace,
.scope, .safe_mode and .allow_intrusive. Findings carry the keys module,
target, severity, confidence, title, description, evidence, cwe and
remediation.
"""

import json
import re
from urllib.parse import parse_qsl, urljoin, urlparse

from arsenal.modules import jscrawl
from arsenal.modules.base import BaseModule

NAME = "jsintel"
DESCRIPTION = (
    "JavaScript intelligence engine: extracts hidden API endpoints and "
    "parameter names from client-side JavaScript, then probes the discovered "
    "endpoints for unauthenticated access, verbose errors, and exposed "
    "debug or admin interfaces."
)
TARGET_KIND = "url"
INTRUSIVE = True

MAX_JS_FILES = 15
MAX_JS_BYTES = 500 * 1024
MAX_ENDPOINTS = 25
MAX_PROBE_BYTES = 256 * 1024
TIMEOUT = 10

# Shared helpers bound from arsenal.modules.base; JS discovery comes from
# the shared arsenal.modules.jscrawl crawler (no local copies).
_mod = BaseModule(NAME, TIMEOUT)
_log = _mod.log_msg
_finding = _mod.finding

COMMON_JS_PATHS = jscrawl.COMMON_JS_PATHS

# Quoted strings that look like API routes.
_API_PATH_RE = re.compile(
    r"""["'`](/(?:api|v1|v2|v3|graphql)(?:/[^"'`\s]*)?)["'`]"""
)
# fetch("/path") style calls with any path argument.
_FETCH_CALL_RE = re.compile(r"""fetch\(\s*["'`]([^"'`)]+)["'`]""")
# Full http(s) URLs in quotes; filtered to the target host later.
_FULL_URL_RE = re.compile(r"""["'`](https?://[^"'`\s]+)["'`]""")
# Parameter names: query (?name=), path (:id), JSON keys ("name":).
_QUERY_PARAM_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_]*)(?==)")
_PATH_PARAM_RE = re.compile(r"/:([A-Za-z_][A-Za-z0-9_]*)")
_JSON_KEY_RE = re.compile(r'"([A-Za-z_][A-Za-z0-9_]*)"\s*:')

# Stack-trace / verbose error markers.
_ERROR_RES = [
    re.compile(r"Traceback \(most recent call last\)"),
    re.compile(r"at\s+.*\.js:\d+"),
    re.compile(r"NullPointerException"),
    re.compile(r"SQL syntax"),
    re.compile(r"Exception in thread"),
]

# Path hints for debug or admin interfaces.
_DEBUG_HINTS = ("/debug", "/console", "/admin", "/actuator", "/.env")


# ---------------------------------------------------------------------------
# Endpoint and parameter extraction
# ---------------------------------------------------------------------------
def _normalize_endpoint(raw, page_url, host):
    """Resolve a raw endpoint string to an absolute same-host URL."""
    raw = raw.strip()
    if not raw or raw.startswith(("data:", "javascript:", "#")):
        return None
    if raw.startswith(("http://", "https://")):
        parts = urlparse(raw)
        if parts.netloc.lower() != host:
            return None
        abs_url = raw
    else:
        if not raw.startswith("/"):
            return None
        abs_url = urljoin(page_url, raw)
    parts = urlparse(abs_url)
    if parts.scheme not in ("http", "https"):
        return None
    if parts.netloc.lower() != host:
        return None
    return parts._replace(fragment="").geturl()


def _extract_endpoints(js_text, page_url, host):
    """Pull candidate API endpoints out of JavaScript text."""
    raw_hits = []
    raw_hits.extend(_API_PATH_RE.findall(js_text))
    raw_hits.extend(_FETCH_CALL_RE.findall(js_text))
    raw_hits.extend(_FULL_URL_RE.findall(js_text))
    endpoints = []
    seen = set()
    for raw in raw_hits:
        url = _normalize_endpoint(raw, page_url, host)
        if url and url not in seen:
            seen.add(url)
            endpoints.append(url)
    return endpoints


def _params_for_endpoint(url):
    """Parameter names visible inside one endpoint string."""
    params = []
    parts = urlparse(url)
    for key, _ in parse_qsl(parts.query):
        if key not in params:
            params.append(key)
    for name in _PATH_PARAM_RE.findall(parts.path):
        if name not in params:
            params.append(name)
    return params


def _json_keys(js_text, limit=10):
    keys = []
    for key in _JSON_KEY_RE.findall(js_text):
        if key not in keys:
            keys.append(key)
        if len(keys) >= limit:
            break
    return keys


# ---------------------------------------------------------------------------
# Probing and classification
# ---------------------------------------------------------------------------
def _looks_like_json(body):
    text = body.strip()
    if not text or text[0] not in "{[":
        return False
    try:
        parsed = json.loads(text)
    except Exception:
        return False
    return isinstance(parsed, (dict, list))


def _first_error_match(body):
    for pattern in _ERROR_RES:
        match = pattern.search(body)
        if match:
            return match
    return None


def _excerpt(body, match=None, radius=160):
    if match is not None:
        start = max(0, match.start() - 60)
        end = min(len(body), match.end() + 120)
        snippet = body[start:end]
    else:
        snippet = body[:radius]
    return " ".join(snippet.split())


def _build_unauth_finding(target, url, status, body, params, js_keys,
                          signal):
    param_note = ""
    observed = list(params) + [k for k in js_keys if k not in params]
    if observed:
        param_note = " Parameter names observed in client code: %s." % ", ".join(
            observed[:10]
        )
    return _finding(
        module=NAME,
        target=target,
        severity="medium",
        confidence="strong",
        title="Unauthenticated API endpoint",
        description=(
            "GET %s returned HTTP %d with a JSON body and no authentication "
            "was required. Sensitivity signal: %s. The endpoint is "
            "reachable anonymously, so any data it returns should be "
            "assumed public.%s"
            % (url, status, signal, param_note)
        ),
        evidence="GET %s -> HTTP %d\nExcerpt: %s" % (url, status, _excerpt(body)),
        cwe="CWE-862",
        remediation=(
            "Require authentication and enforce authorization checks on the "
            "endpoint. Return 401/403 for anonymous callers and make sure "
            "error responses do not leak data."
        ),
    )


def _build_verbose_error_finding(target, url, status, body, match):
    return _finding(
        module=NAME,
        target=target,
        severity="medium",
        confidence="strong",
        title="Verbose API error",
        description=(
            "GET %s returned HTTP %s with a verbose error message containing "
            "a stack trace or internal error detail (%s). Verbose errors "
            "disclose file paths, framework versions and code structure that "
            "help an attacker." % (url, status, match.group(0)[:60])
        ),
        evidence="GET %s -> HTTP %s\nExcerpt: %s"
        % (url, status, _excerpt(body, match)),
        cwe="CWE-200",
        remediation=(
            "Replace verbose errors with generic messages for clients and "
            "send full stack traces to server-side logs only."
        ),
    )


def _build_debug_finding(target, url, status, body):
    return _finding(
        module=NAME,
        target=target,
        severity="high",
        confidence="strong",
        title="Exposed debug/admin endpoint",
        description=(
            "GET %s returned HTTP %d and its path looks like a debug, "
            "console, admin, actuator or environment endpoint. Such "
            "interfaces often expose configuration, metrics or management "
            "functions." % (url, status)
        ),
        evidence="GET %s -> HTTP %d\nExcerpt: %s" % (url, status, _excerpt(body)),
        cwe="CWE-200",
        remediation=(
            "Remove the endpoint from public builds or restrict it to an "
            "internal management network with strong authentication. Never "
            "ship debug consoles or actuator endpoints on a public host."
        ),
    )


# A 200 + JSON response is only worth flagging as an unauthenticated API
# when there is a sensitivity signal: data that looks personal/secret, or
# a path that smells like an admin, account or state-changing surface.
# Without a signal the endpoint is just a public API, which is normal.
_PII_RE = re.compile(
    r"(?i)(password|passwd|secret|api[_-]?key|access[_-]?token|ssn|"
    r"social.?security|credit.?card|card.?number|cvv|bank.?account|iban|"
    r"phone|date.?of.?birth|\bdob\b|salary|passport|email)"
)
_SENSITIVE_PATH_HINTS = (
    "/admin", "/users", "/user", "/account", "/profile", "/internal",
    "/private", "/manage", "/payment", "/order", "/invoice", "/customer",
    "/settings", "/config",
)
_STATE_CHANGING_HINTS = (
    "/delete", "/update", "/create", "/edit", "/remove", "/reset",
)


def _sensitivity_signal(url, body):
    """Return a human-readable reason the endpoint looks sensitive, or None."""
    path = urlparse(url).path.lower()
    for hint in _SENSITIVE_PATH_HINTS:
        if hint in path:
            return "sensitive path (%s)" % hint
    for hint in _STATE_CHANGING_HINTS:
        if hint in path:
            return "state-changing path (%s)" % hint
    match = _PII_RE.search(body[:65536] if isinstance(body, str) else "")
    if match:
        return "response mentions %r" % match.group(1).lower()
    return None


def _probe_endpoint(target, url, js_keys, ctx):
    """GET one endpoint without auth and classify the response."""
    findings = []
    status, body = jscrawl.fetch_js(url, ctx, timeout=TIMEOUT,
                                    max_bytes=MAX_PROBE_BYTES)
    if status is None:
        return findings
    body = body[:MAX_PROBE_BYTES]
    path = urlparse(url).path.lower()
    is_debug = any(hint in path for hint in _DEBUG_HINTS)

    if status == 200 and is_debug:
        findings.append(_build_debug_finding(target, url, status, body))

    error_match = _first_error_match(body)
    if error_match is not None:
        findings.append(
            _build_verbose_error_finding(target, url, status, body, error_match)
        )

    if status == 200 and _looks_like_json(body):
        signal = _sensitivity_signal(url, body)
        if signal is None:
            # Public JSON with no sensitivity signal: not a finding.
            return findings
        findings.append(
            _build_unauth_finding(
                target, url, status, body, _params_for_endpoint(url), js_keys,
                signal,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def _run(target, ctx):
    findings = []
    if getattr(ctx, "safe_mode", False) or not getattr(ctx, "allow_intrusive", True):
        _log(
            ctx,
            "jsintel: probing disabled by safe_mode/allow_intrusive; "
            "no active requests will be made",
        )
        return findings

    html = jscrawl.fetch_page_text(target, ctx, timeout=TIMEOUT)
    if not html:
        _log(ctx, "jsintel: could not fetch page %s" % target)
        return findings

    host = urlparse(target).netloc.lower()
    js_urls = jscrawl.discover_js_urls(target, html)[:MAX_JS_FILES]
    _log(ctx, "jsintel: discovered %d JS file(s) for %s" % (len(js_urls), target))

    endpoints = []
    seen = set()
    js_keys = []
    for js_url in js_urls:
        status, body = jscrawl.fetch_js(js_url, ctx, timeout=TIMEOUT,
                                     max_bytes=MAX_JS_BYTES)
        if status != 200 or not body:
            continue
        body = body[:MAX_JS_BYTES]
        for endpoint in _extract_endpoints(body, target, host):
            if endpoint not in seen:
                seen.add(endpoint)
                endpoints.append(endpoint)
        for key in _json_keys(body):
            if key not in js_keys:
                js_keys.append(key)
        if len(endpoints) >= MAX_ENDPOINTS:
            break

    endpoints = endpoints[:MAX_ENDPOINTS]
    _log(
        ctx,
        "jsintel: probing %d discovered endpoint(s) for %s"
        % (len(endpoints), target),
    )
    for endpoint in endpoints:
        try:
            findings.extend(_probe_endpoint(target, endpoint, js_keys, ctx))
        except Exception as exc:
            _log(ctx, "jsintel: probe failed for %s: %s" % (endpoint, exc))
    return findings


def run(target, ctx):
    """Extract and probe API endpoints hidden in the target's JavaScript."""
    try:
        return _run(target, ctx)
    except Exception as exc:
        _log(ctx, "jsintel: unexpected error: %s" % exc)
        return []
