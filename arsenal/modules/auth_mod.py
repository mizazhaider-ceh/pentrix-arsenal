"""PENTRIX ARSENAL module: broken authentication checks.

Passive and light-active checks around session management:

1. Session cookie analysis: flags missing Secure/HttpOnly/SameSite on
   session cookies, and weak session identifiers via a Shannon-entropy
   check on the cookie value.
2. Brute-force protection: when a login form is found, up to 3 failed
   login attempts are made and the responses are inspected for
   throttling signals (429, Retry-After, captcha, lockout message).
   Conservative by design: 3 attempts, spaced out, never a real attack.
3. Guidance findings (info): session-fixation test steps, logout
   invalidation checks, and password-reset token entropy tests, each
   with exact manual steps.

Non-intrusive: normal page fetches plus at most 3 failed logins.
"""

import math
import re
import time
import urllib.parse

from arsenal.findings import make_finding
from arsenal.http import fetch

NAME = "auth"
DESCRIPTION = (
    "Checks session cookie flags and entropy, brute-force throttling, "
    "and reports session-fixation, logout, and reset-token test guidance."
)
TARGET_KIND = "url"
INTRUSIVE = False

TIMEOUT = 10
SESSION_NAME_RE = re.compile(
    r"(sess|sid|session|token|auth|jwt|phpsessid|jsessionid|aspsession)",
    re.IGNORECASE)
MAX_LOGIN_PROBES = 3


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


def _fetch(url, ctx, method="GET", data=None, headers=None):
    try:
        return fetch(url, method=method, data=data,
                     headers=headers or {}, timeout=_timeout(ctx),
                     allow_redirects=True, ctx=ctx)
    except Exception as exc:
        _log(ctx, "debug", "%s: request failed for %s: %s" % (NAME, url, exc))
        return None


def _set_cookies(headers):
    raw = (headers or {}).get("set-cookie", "")
    if isinstance(raw, list):
        raw = "\n".join(raw)
    return [c.strip() for c in str(raw).split("\n") if c.strip()]


def _shannon_entropy(value):
    if not value:
        return 0.0
    freq = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    for count in freq.values():
        p = count / len(value)
        ent -= p * math.log2(p)
    return ent


def _is_session_cookie(cookie):
    name = cookie.split("=", 1)[0].strip()
    return bool(SESSION_NAME_RE.search(name)), name


def _forms(page_text):
    forms = []
    for m in re.finditer(r"<form\b([^>]*)>(.*?)</form>",
                         page_text or "", re.IGNORECASE | re.DOTALL):
        forms.append((m.group(1), m.group(2)))
    return forms


def _input_names(form_body):
    return re.findall(r'<input\b[^>]*\bname=["\']?([^"\'\s>]+)',
                      form_body, re.IGNORECASE)


def run(target, ctx):
    """Run broken-authentication checks against the target."""
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
    status, headers, body, _final = resp
    try:
        page = body.decode("utf-8", errors="replace")
    except Exception:
        page = ""
    is_https = target.startswith("https://")

    # 1. Session cookie flags and entropy.
    for cookie in _set_cookies(headers):
        is_sess, name = _is_session_cookie(cookie)
        if not is_sess:
            continue
        low = cookie.lower()
        value = cookie.split("=", 1)[1].split(";")[0].strip() if "=" in cookie else ""
        if is_https and "secure" not in low:
            findings.append(_finding(
                target=target, severity="low",
                title="Session cookie without Secure flag (%s)" % name,
                description="The session cookie is set without the Secure "
                            "flag, so browsers may send it over plain HTTP.",
                evidence="Set-Cookie: %s" % cookie[:200],
                confidence="strong", cwe="CWE-614",
                remediation="Set Secure on all session cookies."))
        if "httponly" not in low:
            findings.append(_finding(
                target=target, severity="low",
                title="Session cookie without HttpOnly flag (%s)" % name,
                description="The session cookie is readable from JavaScript, "
                            "which makes XSS session theft easier.",
                evidence="Set-Cookie: %s" % cookie[:200],
                confidence="strong", cwe="CWE-1004",
                remediation="Set HttpOnly on all session cookies."))
        if "samesite" not in low:
            findings.append(_finding(
                target=target, severity="low",
                title="Session cookie without SameSite attribute (%s)" % name,
                description="No SameSite attribute weakens the cookie "
                            "against CSRF.",
                evidence="Set-Cookie: %s" % cookie[:200],
                confidence="strong", cwe="CWE-1275",
                remediation="Set SameSite=Lax (or Strict) on session cookies."))
        ent = _shannon_entropy(value)
        bits = ent * len(value)
        if value and (len(value) < 16 or bits < 64):
            findings.append(_finding(
                target=target, severity="medium",
                title="Weak session identifier (%s)" % name,
                description=(
                    "The session value is short or low-entropy "
                    "(~%.0f bits), which makes session prediction or "
                    "brute-forcing feasible." % bits),
                evidence="Cookie %s length=%d entropy_bits=%.1f"
                         % (name, len(value), bits),
                confidence="review", cwe="CWE-330",
                remediation="Use a CSPRNG session ID of at least 128 bits."))

    # 2. Brute-force protection: find a login form, try a few bad logins.
    login_url = None
    login_fields = {}
    for attrs, fbody in _forms(page):
        names = _input_names(fbody)
        if any("pass" in n.lower() for n in names):
            m = re.search(r'action=["\']?([^"\'\s>]+)', attrs, re.IGNORECASE)
            action = m.group(1) if m else target
            login_url = urllib.parse.urljoin(target, action)
            user_field = next((n for n in names
                               if "user" in n.lower() or "mail" in n.lower()
                               or "login" in n.lower()), names[0] if names else "username")
            pass_field = next((n for n in names if "pass" in n.lower()), "password")
            login_fields = {user_field: "arsenal-probe-user",
                            pass_field: "arsenal-probe-pass"}
            break
    if login_url:
        throttled = False
        signals = []
        for i in range(MAX_LOGIN_PROBES):
            r = _fetch(login_url, ctx, method="POST",
                       data=urllib.parse.urlencode(login_fields),
                       headers={"Content-Type":
                                "application/x-www-form-urlencoded"})
            if r is None:
                break
            st, hdrs, bd, _fin = r
            try:
                txt = bd.decode("utf-8", errors="replace").lower()
            except Exception:
                txt = ""
            if st == 429 or "retry-after" in hdrs:
                throttled, signals = True, ["HTTP 429 / Retry-After"]
                break
            for sig in ("captcha", "too many attempts", "account locked",
                        "try again later", "rate limit"):
                if sig in txt:
                    throttled, signals = True, ["response mentions %r" % sig]
                    break
            if throttled:
                break
            time.sleep(1)
        if throttled:
            findings.append(_finding(
                target=target, severity="info",
                title="Brute-force protection detected on login",
                description="Failed-login probing triggered a throttling "
                            "signal, which is the desired behavior.",
                evidence="Login: %s | Signals: %s" % (login_url, "; ".join(signals)),
                confidence="strong", cwe="CWE-307",
                remediation="No action needed; protection is present."))
        else:
            findings.append(_finding(
                target=target, severity="low",
                title="No brute-force throttling observed in %d probes" % MAX_LOGIN_PROBES,
                description=(
                    "%d rapid failed logins produced no 429, captcha, or "
                    "lockout signal. This is only a light probe; confirm "
                    "with a controlled credential-stuffing test before "
                    "reporting." % MAX_LOGIN_PROBES),
                evidence="Login endpoint: %s" % login_url,
                confidence="review", cwe="CWE-307",
                remediation="Add rate limiting, captcha, and account lockout "
                            "on the login endpoint."))

    # 3. Guidance findings.
    if re.search(r'href=["\']?[^"\']*(logout|signout)', page, re.IGNORECASE):
        findings.append(_finding(
            target=target, severity="info",
            title="Logout invalidation: manual test steps",
            description=(
                "A logout link was found. Test: 1) log in and note the "
                "session cookie; 2) log out; 3) replay an authenticated "
                "request with the old cookie. If it still works, logout "
                "does not invalidate the server-side session."),
            evidence="Logout link present on the page.",
            confidence="review", cwe="CWE-613",
            remediation="Invalidate the session server-side on logout."))
    if re.search(r"(forgot|reset).{0,20}password|password.{0,20}(forgot|reset)",
                 page, re.IGNORECASE):
        findings.append(_finding(
            target=target, severity="info",
            title="Password-reset token: manual entropy test",
            description=(
                "A password-reset flow was found. Test: request a reset, "
                "capture the token, and check length/entropy (aim for 128+ "
                "bits from a CSPRNG), single-use, short expiry, and that it "
                "is not leaked in the Referer or logs."),
            evidence="Password-reset flow referenced on the page.",
            confidence="review", cwe="CWE-330",
            remediation="Use single-use, expiring, high-entropy reset tokens."))
    findings.append(_finding(
        target=target, severity="info",
        title="Session fixation: manual test steps",
        description=(
            "Test: 1) request the login page and note any pre-auth session "
            "cookie; 2) log in; 3) if the session ID is unchanged after "
            "login, fixation is possible. Also test whether the app accepts "
            "an attacker-chosen session ID via URL or cookie."),
        evidence="Session cookie analysis completed.",
        confidence="review", cwe="CWE-384",
        remediation="Regenerate the session ID on privilege changes (login)."))
    return findings
