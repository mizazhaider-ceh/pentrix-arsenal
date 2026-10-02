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
from urllib.parse import urlparse

from arsenal.modules import jscrawl
from arsenal.modules import secret_rules
from arsenal.modules.base import BaseModule

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

# Shared helpers: secret rules come from the single canonical table in
# arsenal.modules.secret_rules, JS discovery from arsenal.modules.jscrawl.
_mod = BaseModule(NAME, TIMEOUT)
_log = _mod.log_msg
_finding = _mod.finding

RULES = secret_rules.RULES


# ---------------------------------------------------------------------------
# Discovery and scanning
# ---------------------------------------------------------------------------
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
    """Scan JS text against the shared secret_rules table."""
    return secret_rules.scan_text(content, max_matches=MAX_MATCHES_PER_FILE)


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
        secret_rules.redact(match["snippet"]),
    )
    remediation = (
        "Rotate or revoke the exposed credential immediately and check access "
        "logs for misuse. Remove the secret from client-side code: move "
        "privileged calls behind a server-side proxy and ship only public, "
        "low-risk keys to the browser."
    )
    return _finding(
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
    html = jscrawl.fetch_page_text(target, ctx, timeout=TIMEOUT)
    if not html:
        _log(ctx, "jssecrets: could not fetch page %s" % target)
        return findings

    js_urls = jscrawl.discover_js_urls(target, html)[:MAX_JS_FILES]
    _log(ctx, "jssecrets: discovered %d JS file(s) for %s" % (len(js_urls), target))

    for index, js_url in enumerate(js_urls):
        status, body = jscrawl.fetch_js(js_url, ctx, timeout=TIMEOUT,
                                          max_bytes=MAX_JS_BYTES)
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
