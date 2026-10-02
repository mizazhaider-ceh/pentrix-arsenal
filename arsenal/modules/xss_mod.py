"""PENTRIX ARSENAL module: reflected XSS detection.

Adapted from pentrix-xss: injects a small set of inert canary payloads into
each query parameter of a URL, fetches the page, and reports where each
value is reflected, classified by HTML context. Severity follows the
reflection context: script/event-handler context is high, HTML attribute is
medium, plain text is low. Confidence is "strong" when the context is
directly executable, otherwise "review".

Intrusive: sends crafted payloads to the target. Detection only; nothing
is exploited.
"""

import html
import re
import urllib.parse
from arsenal.modules.base import BaseModule


NAME = "xss"
DESCRIPTION = (
    "Detects reflected cross-site scripting by injecting inert canary "
    "payloads into each query parameter and classifying the reflection "
    "context (script, attribute, tag, text)."
)
TARGET_KIND = "url"
INTRUSIVE = True

TIMEOUT = 10
MAX_BODY_BYTES = 2 * 1024 * 1024

# Small payload set for speed (at most 6 per the module contract).
PAYLOADS = [
    "{CANARY}<>'\"",
    "{CANARY}\">",
    "\"'><svg/onload={CANARY}>",
    "'-{CANARY}-",
]

# Context labels, ordered from most to least dangerous.
CTX_SCRIPT = "inside <script> block"
CTX_DQ_ATTR = "inside double-quoted attribute"
CTX_SQ_ATTR = "inside single-quoted attribute"
CTX_TAG = "inside HTML tag"
CTX_TEXT = "plain HTML text"
CTX_ENCODED = "HTML-encoded"

CTX_SEVERITY = {
    CTX_SCRIPT: "high",
    CTX_TAG: "high",        # event-handler injection context
    CTX_DQ_ATTR: "medium",
    CTX_SQ_ATTR: "medium",
    CTX_TEXT: "low",
}
# Contexts where injected markup can execute directly.
EXECUTABLE_CONTEXTS = {CTX_SCRIPT, CTX_TAG, CTX_DQ_ATTR, CTX_SQ_ATTR}
SEVERITY_ORDER = [CTX_SCRIPT, CTX_TAG, CTX_DQ_ATTR, CTX_SQ_ATTR, CTX_TEXT]

SCRIPT_OPEN_RE = re.compile(r"<script\b[^>]*>", re.IGNORECASE)
SCRIPT_CLOSE_RE = re.compile(r"</script\s*>", re.IGNORECASE)
CHARSET_RE = re.compile(r"charset=([\w-]+)", re.IGNORECASE)
HTML_SNIFF_RE = re.compile(
    r"<(html|head|body|div|p|span|input|script|a|title|!doctype)\b", re.IGNORECASE
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
_get = _mod.get
_finding = _mod.finding

# ---------------------------------------------------------------------------
# Reflection logic (adapted from pentrix-xss)
# ---------------------------------------------------------------------------

def make_canary(param_idx, payload_idx):
    return "pxss%dx%d" % (param_idx, payload_idx)


def build_test_url(url, params, target_idx, payload_value):
    parts = urllib.parse.urlparse(url)
    new_params = [
        (name, payload_value if i == target_idx else value)
        for i, (name, value) in enumerate(params)
    ]
    query = urllib.parse.urlencode(new_params)
    return urllib.parse.urlunparse(parts._replace(query=query))


def decode_body(headers, body):
    content_type = headers.get("content-type", "")
    match = CHARSET_RE.search(content_type or "")
    charset = match.group(1) if match else "utf-8"
    try:
        return body.decode(charset, errors="replace"), content_type
    except LookupError:
        return body.decode("utf-8", errors="replace"), content_type


def looks_like_html(content_type, text):
    ctype = (content_type or "").lower()
    if "html" in ctype:
        return True
    if ctype and not any(t in ctype for t in ("text", "xml", "xhtml")):
        return False
    return bool(HTML_SNIFF_RE.search(text.lstrip()[:4096]))


def find_script_spans(text):
    spans = []
    for match in SCRIPT_OPEN_RE.finditer(text):
        close = SCRIPT_CLOSE_RE.search(text, match.end())
        end = close.end() if close else len(text)
        spans.append((match.start(), end))
    return spans


def classify_raw(text, idx, script_spans):
    if any(start <= idx < end for start, end in script_spans):
        return CTX_SCRIPT
    lt = text.rfind("<", 0, idx)
    gt = text.rfind(">", 0, idx)
    if lt > gt:
        in_single = in_double = False
        for ch in text[lt:idx]:
            if ch == '"' and not in_single:
                in_double = not in_double
            elif ch == "'" and not in_double:
                in_single = not in_single
        if in_double:
            return CTX_DQ_ATTR
        if in_single:
            return CTX_SQ_ATTR
        return CTX_TAG
    return CTX_TEXT


def encoded_variants(payload):
    base = html.escape(payload, quote=True)
    return {
        base,
        base.replace("&#x27;", "&#39;"),
        base.replace("&quot;", "&#34;"),
        html.escape(payload, quote=False),
    }


def find_reflections(text, payload):
    """Return ordered unique context labels for reflections of payload."""
    script_spans = find_script_spans(text)
    contexts = []
    snippet = None
    start = 0
    while True:
        idx = text.find(payload, start)
        if idx == -1:
            break
        ctx = classify_raw(text, idx, script_spans)
        if ctx not in contexts:
            contexts.append(ctx)
            if snippet is None:
                snippet = text[max(0, idx - 80):idx + 120].replace("\n", " ")
        start = idx + len(payload)
    if not contexts:
        for variant in encoded_variants(payload):
            if variant != payload and variant in text:
                return [CTX_ENCODED], None
    return contexts, snippet


def worst_context(contexts):
    for ctx in SEVERITY_ORDER:
        if ctx in contexts:
            return ctx
    return None


def scan_url(url, ctx):
    """Scan every query parameter of url. Returns per-parameter results."""
    parts = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if not params:
        return []
    results = []
    for pidx, (name, _value) in enumerate(params):
        entry = {"parameter": name, "contexts": [], "snippet": None}
        for sidx, template in enumerate(PAYLOADS):
            canary = make_canary(pidx, sidx)
            payload_value = template.replace("{CANARY}", canary)
            test_url = build_test_url(url, params, pidx, payload_value)
            resp = _get(test_url, ctx)
            if resp is None:
                continue  # one failed request must not skip other payloads
            _status, headers, body, _final = resp
            if len(body) > MAX_BODY_BYTES:
                continue
            text, content_type = decode_body(headers, body)
            if not looks_like_html(content_type, text):
                continue
            contexts, snippet = find_reflections(text, payload_value)
            for ctx_label in contexts:
                if ctx_label not in entry["contexts"]:
                    entry["contexts"].append(ctx_label)
                    if entry["snippet"] is None and snippet:
                        entry["snippet"] = snippet
        results.append(entry)
    return results


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(target, ctx):
    """Scan target for reflected XSS; one finding per reflected parameter."""
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
    out = []
    for entry in scan_url(target, ctx):
        contexts = [c for c in entry["contexts"] if c != CTX_ENCODED]
        if not contexts:
            continue
        worst = worst_context(contexts)
        severity = CTX_SEVERITY.get(worst, "low")
        confidence = "strong" if worst in EXECUTABLE_CONTEXTS else "review"
        evidence = "Contexts: %s" % ", ".join(contexts)
        if entry["snippet"]:
            evidence += "\nReflection excerpt: ...%s..." % entry["snippet"]
        out.append(_finding(
            target=target,
            severity=severity,
            confidence=confidence,
            title="Reflected XSS in parameter '%s'" % entry["parameter"],
            description=(
                "The value of query parameter '%s' is reflected in the "
                "response (%s). A crafted value may allow JavaScript "
                "execution in a victim's browser."
                % (entry["parameter"], ", ".join(contexts))
            ),
            evidence=evidence,
            cwe="CWE-79",
            remediation=(
                "Apply context-aware output encoding for '%s', validate input "
                "on the server, and deploy a Content-Security-Policy that "
                "blocks inline scripts." % entry["parameter"]
            ),
        ))
    return out
