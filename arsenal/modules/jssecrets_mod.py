"""jssecrets: find hard-coded secrets in client-side JavaScript.

TARGET_KIND "url". Fetches the target page, discovers same-host JavaScript
files (script src tags plus common bundle paths), downloads each file, and
scans the content for hard-coded secrets.

Detection rules adapted from pentrix-secrets
(~/workspace/pentrix-toolkit/pentrix-secrets/secrets.py).

Module contract: NAME, DESCRIPTION, TARGET_KIND, INTRUSIVE,
run(target, ctx) -> list[dict]. ctx provides .config, .log, .workspace,
.scope, .safe_mode and .allow_intrusive. Findings carry the keys module,
target, severity, confidence, title, description, evidence, cwe and
remediation.
"""

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from arsenal.http import fetch
from arsenal.findings import make_finding

NAME = "jssecrets"
DESCRIPTION = (
    "Discovers JavaScript files served by the target page and scans them "
    "for hard-coded secrets (API keys, tokens, private keys) using rules "
    "adapted from pentrix-secrets."
)
TARGET_KIND = "url"
INTRUSIVE = False

MAX_JS_FILES = 15
MAX_JS_BYTES = 500 * 1024
MAX_MATCHES_PER_FILE = 25
TIMEOUT = 10

COMMON_JS_PATHS = ["/app.js", "/main.js", "/bundle.js"]

# Detection rules: (rule name, compiled pattern, severity, CWE).
# Rule patterns adapted from pentrix-secrets; the JWT rule is added here
# because token literals are common in client-side bundles.
RULES = [
    (
        "AWS Access Key ID",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "high",
        "CWE-798",
    ),
    (
        "AWS Secret Key Assignment",
        re.compile(
            r"(?i)\baws[_-]?secret[_-]?access[_-]?key\b\s*[:=]\s*"
            r"['\"]?([A-Za-z0-9/+=]{30,})['\"]?"
        ),
        "high",
        "CWE-798",
    ),
    (
        "Private Key Block",
        re.compile(r"-----BEGIN (?:[A-Z ]*)PRIVATE KEY-----"),
        "high",
        "CWE-798",
    ),
    (
        "GitHub Token",
        re.compile(
            r"\b(ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|"
            r"github_pat_[A-Za-z0-9_]{20,})\b"
        ),
        "medium",
        "CWE-200",
    ),
    (
        "GitLab Token",
        re.compile(r"\bglpat-[A-Za-z0-9_\-]{16,}\b"),
        "medium",
        "CWE-200",
    ),
    (
        "Slack Token",
        re.compile(r"\bxox[bap]-[A-Za-z0-9-]{10,}\b"),
        "medium",
        "CWE-200",
    ),
    (
        "Google API Key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "medium",
        "CWE-200",
    ),
    (
        "Stripe Secret Key",
        re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b"),
        "medium",
        "CWE-798",
    ),
    (
        "JWT Token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        "medium",
        "CWE-200",
    ),
    (
        "Generic API Key Assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|apikey|api[_-]?secret|secret)\b\s*[:=]\s*"
            r"['\"][^'\"]{4,}['\"]"
        ),
        "medium",
        "CWE-798",
    ),
]


# ---------------------------------------------------------------------------
# Small internal helpers
# ---------------------------------------------------------------------------
class _ScriptSrcParser(HTMLParser):
    """Collects script src attributes from a page."""

    def __init__(self):
        super().__init__()
        self.srcs = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            for attr_name, value in attrs:
                if attr_name.lower() == "src" and value:
                    self.srcs.append(value)


def _log(ctx, message):
    log = getattr(ctx, "log", None)
    if callable(log):
        try:
            log(message)
        except Exception:
            pass


def _redact(text):
    """Mask a secret, keeping only a hint of its shape."""
    text = text.strip()
    if len(text) <= 8:
        return "***REDACTED***"
    return "%s...%s" % (text[:4], text[-2:])


def _make_finding(**fields):
    try:
        return make_finding(**fields)
    except Exception:
        return dict(fields)


def _http_get(url, timeout=TIMEOUT, max_bytes=None):
    """GET url. Returns (status, body text) via the canonical fetch()."""
    try:
        status, _headers, body, _final = fetch(url, timeout=timeout)
    except Exception:
        return None, ""
    text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)
    if max_bytes:
        text = text[:max_bytes]
    return status, text


def _http_text(url, timeout=TIMEOUT):
    status, text = _http_get(url, timeout=timeout)
    if not status or status >= 400:
        return ""
    return text


# ---------------------------------------------------------------------------
# Discovery and scanning
# ---------------------------------------------------------------------------
def _discover_js_urls(page_url, html):
    """Return ordered, deduplicated same-host JS URLs for a page."""
    found = []
    seen = set()
    base_netloc = urlparse(page_url).netloc.lower()

    def add(raw):
        if not raw or raw.startswith(("data:", "javascript:", "#")):
            return
        abs_url = urljoin(page_url, raw.strip())
        parts = urlparse(abs_url)
        if parts.scheme not in ("http", "https"):
            return
        if parts.netloc.lower() != base_netloc:
            return
        clean = parts._replace(fragment="").geturl()
        if clean not in seen:
            seen.add(clean)
            found.append(clean)

    parser = _ScriptSrcParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    for src in parser.srcs:
        add(src)
    # Fallback regex for unusual markup the parser may miss.
    for match in re.finditer(
        r"<script[^>]+src\s*=\s*[\"']([^\"']+)[\"']", html, re.IGNORECASE
    ):
        add(match.group(1))
    for path in COMMON_JS_PATHS:
        add(path)
    return found


def _safe_js_name(url, index):
    name = urlparse(url).path.rsplit("/", 1)[-1] or ("script-%d.js" % index)
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    if not name.endswith(".js"):
        name += ".js"
    return name


def _save_js(ctx, target, url, index, content):
    workspace = getattr(ctx, "workspace", None)
    if workspace is None or not hasattr(workspace, "save_blob"):
        return
    try:
        workspace.save_blob(
            target, "js/%s" % _safe_js_name(url, index), content
        )
    except Exception:
        pass


def _scan_content(url, content):
    """Scan JS text line by line. Returns a list of match dicts."""
    matches = []
    for lineno, line in enumerate(content.splitlines(), start=1):
        for rule_name, pattern, severity, cwe in RULES:
            for match in pattern.finditer(line):
                snippet = match.group(0).strip()
                matches.append(
                    {
                        "rule": rule_name,
                        "severity": severity,
                        "cwe": cwe,
                        "line": lineno,
                        "snippet": snippet,
                    }
                )
                if len(matches) >= MAX_MATCHES_PER_FILE:
                    return matches
    return matches


def _build_finding(target, url, match):
    rule = match["rule"]
    title = "%s exposed in JavaScript" % rule
    description = (
        "A value matching the '%s' pattern was found hard-coded in the "
        "client-side JavaScript file served at %s (line %d). Anything in "
        "client-side JavaScript is visible to every visitor of the page, so "
        "the value must be treated as public." % (rule, url, match["line"])
    )
    evidence = "%s:%d [%s] %s" % (
        url,
        match["line"],
        rule,
        _redact(match["snippet"]),
    )
    remediation = (
        "Rotate or revoke the exposed credential immediately and check access "
        "logs for misuse. Remove the secret from client-side code: move "
        "privileged calls behind a server-side proxy and ship only public, "
        "low-risk keys to the browser."
    )
    return _make_finding(
        module=NAME,
        target=target,
        severity=match["severity"],
        confidence="strong",
        title=title,
        description=description,
        evidence=evidence,
        cwe=match["cwe"],
        remediation=remediation,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def _run(target, ctx):
    findings = []
    html = _http_text(target, timeout=TIMEOUT)
    if not html:
        _log(ctx, "jssecrets: could not fetch page %s" % target)
        return findings

    js_urls = _discover_js_urls(target, html)[:MAX_JS_FILES]
    _log(ctx, "jssecrets: discovered %d JS file(s) for %s" % (len(js_urls), target))

    for index, js_url in enumerate(js_urls):
        status, body = _http_get(js_url, timeout=TIMEOUT, max_bytes=MAX_JS_BYTES)
        if status != 200 or not body:
            continue
        body = body[:MAX_JS_BYTES]
        _save_js(ctx, target, js_url, index, body)
        for match in _scan_content(js_url, body):
            findings.append(_build_finding(target, js_url, match))
    return findings


def run(target, ctx):
    """Scan the target page's JavaScript for hard-coded secrets."""
    try:
        return _run(target, ctx)
    except Exception as exc:
        _log(ctx, "jssecrets: unexpected error: %s" % exc)
        return []
