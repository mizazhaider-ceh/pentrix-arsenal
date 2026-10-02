"""PENTRIX ARSENAL module: server-side template injection (SSTI) probing.

Injects three template-expression payloads ({{7*7}}, ${7*7}, <%=7*7%>)
into each query parameter and once into the URL path. If the arithmetic
result "49" appears in the response where it was absent from the
baseline, server-side template evaluation is likely. Reported at high
severity with "strong" confidence and an evidence snippet.

Intrusive: sends crafted payloads. Detection only.
"""

import re
import urllib.parse
from arsenal.modules.base import BaseModule


NAME = "ssti"
DESCRIPTION = (
    "Probes for server-side template injection by injecting template "
    "expressions into parameters and the path and watching for evaluated "
    "output."
)
TARGET_KIND = "url"
INTRUSIVE = True

TIMEOUT = 10
MAX_BODY_BYTES = 2 * 1024 * 1024

PAYLOADS = ["{{7*7}}", "${7*7}", "<%=7*7%>"]
EXPECTED = "49"

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


def build_test_url(url, params, target_idx, value):
    parts = urllib.parse.urlparse(url)
    new_params = [
        (name, value if i == target_idx else val)
        for i, (name, val) in enumerate(params)
    ]
    query = urllib.parse.urlencode(new_params)
    return urllib.parse.urlunparse(parts._replace(query=query))


def snippet_around(text, marker, radius=100):
    idx = text.find(marker)
    if idx == -1:
        return ""
    start = max(0, idx - radius)
    end = min(len(text), idx + len(marker) + radius)
    return " ".join(text[start:end].split())


def run(target, ctx):
    """Probe parameters and path for SSTI; findings at high severity."""
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
    _status, base_headers, base_body, _final = base_resp
    base_text = decode_body(base_headers, base_body)

    params = urllib.parse.parse_qsl(
        urllib.parse.urlsplit(target).query, keep_blank_values=True)
    out = []
    seen = set()

    def check(url, where, payload):
        if where in seen:
            return
        resp = _get(url, ctx)
        if resp is None:
            return
        _status, headers, body, _final = resp
        if len(body) > MAX_BODY_BYTES:
            return
        text = decode_body(headers, body)
        if EXPECTED in text and EXPECTED not in base_text:
            seen.add(where)
            out.append(_finding(
                target=target,
                severity="high",
                confidence="strong",
                title="Server-side template injection likely (%s)" % where,
                description=(
                    "The template expression %r was evaluated server-side: "
                    "the response contains %r where the baseline did not. "
                    "This indicates the input reaches a template engine."
                    % (payload, EXPECTED)
                ),
                evidence="Request: %s\nResponse excerpt: ...%s..."
                         % (url, snippet_around(text, EXPECTED)),
                cwe="CWE-94",
                remediation=(
                    "Never render user input as a template; use logic-less "
                    "templates with auto-escaping and sandbox the engine."
                ),
            ))

    for pidx, (name, _value) in enumerate(params):
        for payload in PAYLOADS:
            check(build_test_url(target, params, pidx, payload),
                  "parameter '%s'" % name, payload)

    # One path injection probe with the first payload.
    parts = urllib.parse.urlparse(target)
    path_probe = urllib.parse.urlunparse(parts._replace(
        path=parts.path.rstrip("/") + "/" + urllib.parse.quote(PAYLOADS[0], safe="")
    ))
    check(path_probe, "URL path", PAYLOADS[0])
    return out
