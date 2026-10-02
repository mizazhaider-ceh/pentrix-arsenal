"""PENTRIX ARSENAL module: CSRF checks.

Parses forms on the target page and flags state-changing POST forms
that carry no anti-CSRF token (hidden input with a token-like name).
Also analyzes Set-Cookie headers for missing or weak SameSite
attributes (SameSite=None without Secure is flagged), and notes GET
forms whose action looks state-changing.

Token-per-session rotation cannot be verified from one fetch, so it is
reported as manual guidance rather than a finding.

Non-intrusive: one page fetch, no form submissions.
"""

import re
import urllib.parse

from arsenal.findings import make_finding
from arsenal.http import fetch

NAME = "csrf"
DESCRIPTION = (
    "Detects missing CSRF tokens on state-changing forms and weak "
    "SameSite cookie attributes."
)
TARGET_KIND = "url"
INTRUSIVE = False

TIMEOUT = 10
TOKEN_NAME_RE = re.compile(
    r"(csrf|_token|authenticity|__requestverification|xsrf|token)",
    re.IGNORECASE)
STATE_WORDS = ("delete", "update", "transfer", "change", "remove",
               "create", "save", "order", "pay")


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


def _finding(**kwargs):
    kwargs.setdefault("module", NAME)
    return make_finding(**kwargs)


def _fetch(url, ctx):
    try:
        return fetch(url, timeout=_timeout(ctx), allow_redirects=True, ctx=ctx)
    except Exception as exc:
        _log(ctx, "debug", "%s: request failed for %s: %s" % (NAME, url, exc))
        return None


def _forms(page_text):
    out = []
    for m in re.finditer(r"<form\b([^>]*)>(.*?)</form>",
                         page_text or "", re.IGNORECASE | re.DOTALL):
        out.append((m.group(1), m.group(2)))
    return out


def _hidden_inputs(form_body):
    inputs = []
    for m in re.finditer(r"<input\b([^>]*)>", form_body, re.IGNORECASE):
        attrs = m.group(1)
        if re.search(r'type=["\']?hidden', attrs, re.IGNORECASE):
            n = re.search(r'name=["\']?([^"\'\s>]+)', attrs, re.IGNORECASE)
            v = re.search(r'value=["\']?([^"\'\s>]+)', attrs, re.IGNORECASE)
            inputs.append((n.group(1) if n else "",
                           v.group(1) if v else ""))
    return inputs


def _set_cookies(headers):
    raw = (headers or {}).get("set-cookie", "")
    if isinstance(raw, list):
        raw = "\n".join(raw)
    return [c.strip() for c in str(raw).split("\n") if c.strip()]


def run(target, ctx):
    """Check the target page for CSRF weaknesses."""
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
    findings = []
    resp = _fetch(target, ctx)
    if resp is None:
        return []
    _status, headers, body, _final = resp
    try:
        page = body.decode("utf-8", errors="replace")
    except Exception:
        page = ""

    for attrs, fbody in _forms(page):
        method = "get"
        m = re.search(r'method=["\']?([^"\'\s>]+)', attrs, re.IGNORECASE)
        if m:
            method = m.group(1).lower()
        a = re.search(r'action=["\']?([^"\'\s>]+)', attrs, re.IGNORECASE)
        action = a.group(1) if a else "(same page)"
        hidden = _hidden_inputs(fbody)
        has_token = any(TOKEN_NAME_RE.search(n) and len(v) >= 8
                        for n, v in hidden)
        stateful = any(w in action.lower() or w in fbody.lower()
                       for w in STATE_WORDS)
        if method == "post" and not has_token:
            findings.append(_finding(
                target=target,
                severity="medium" if stateful else "low",
                title="Form without CSRF token (%s %s)" % (method.upper(), action),
                description=(
                    "A %s form has no hidden anti-CSRF token input. If the "
                    "form performs a state change, an attacker site can "
                    "submit it in the victim's browser." % method.upper()),
                evidence="Form action: %s | hidden inputs: %s"
                         % (action, [n for n, _v in hidden] or "(none)"),
                confidence="review",
                cwe="CWE-352",
                remediation="Add a per-session (ideally per-request) CSRF "
                            "token validated server-side; prefer "
                            "SameSite=Lax cookies."))
        elif method == "get" and stateful and not has_token:
            findings.append(_finding(
                target=target, severity="low",
                title="State-changing action over GET (%s)" % action,
                description="A GET form performs a state-changing action, "
                            "which is CSRF-able by a simple link or image.",
                evidence="Form action: %s" % action,
                confidence="review", cwe="CWE-352",
                remediation="Use POST with a CSRF token for state changes."))

    for cookie in _set_cookies(headers):
        name = cookie.split("=", 1)[0].strip()
        low = cookie.lower()
        if "samesite" not in low:
            findings.append(_finding(
                target=target, severity="low",
                title="Cookie without SameSite (%s)" % name,
                description="The cookie sets no SameSite attribute, so the "
                            "browser default applies and CSRF exposure is "
                            "higher.",
                evidence="Set-Cookie: %s" % cookie[:200],
                confidence="strong", cwe="CWE-1275",
                remediation="Set SameSite=Lax or Strict."))
        elif "samesite=none" in low and "secure" not in low:
            findings.append(_finding(
                target=target, severity="medium",
                title="SameSite=None without Secure (%s)" % name,
                description="SameSite=None requires Secure; without it the "
                            "cookie is sent cross-site over plain HTTP.",
                evidence="Set-Cookie: %s" % cookie[:200],
                confidence="strong", cwe="CWE-1275",
                remediation="Add Secure, or drop to SameSite=Lax."))
    return findings
