"""PENTRIX ARSENAL module: HTTP security headers analysis.

Adapted from pentrix-headers: reuses the analyze() grading logic and the
per-check fix advice, emitting one finding per missing or weak security
header (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).

Non-intrusive: a single GET request per target. Standard library only.
"""

from arsenal.modules.base import BaseModule


NAME = "headers"
DESCRIPTION = (
    "Checks HTTP security headers (HSTS, CSP, X-Frame-Options, "
    "X-Content-Type-Options, Referrer-Policy) and reports each missing "
    "or weak header as a finding."
)
TARGET_KIND = "url"
INTRUSIVE = False

TIMEOUT = 10
HSTS_MIN_MAX_AGE = 31536000  # one year in seconds

HSTS_FIX = (
    "Add header Strict-Transport-Security: "
    "max-age=31536000; includeSubDomains; preload"
)
CSP_FIX = (
    "Add header Content-Security-Policy: "
    "default-src 'self'; frame-ancestors 'self'"
)
CSP_RO_FIX = (
    "Replace Content-Security-Policy-Report-Only with an enforcing "
    "Content-Security-Policy: default-src 'self'; frame-ancestors 'self'"
)
XFO_FIX = (
    "Add header X-Frame-Options: SAMEORIGIN "
    "(or set frame-ancestors 'self' in CSP)"
)
XCTO_FIX = "Add header X-Content-Type-Options: nosniff"
REFERRER_FIX = "Add header Referrer-Policy: strict-origin-when-cross-origin"


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

def _header_dump(headers, limit=900):
    lines = ["%s: %s" % (name, value) for name, value in sorted(headers.items())]
    dump = "\n".join(lines)
    if len(dump) > limit:
        dump = dump[:limit] + "..."
    return dump


# ---------------------------------------------------------------------------
# Header checks (adapted from pentrix-headers)
# ---------------------------------------------------------------------------

def parse_directives(value):
    """Split a semicolon separated header value into lowercase directives."""
    return [part.strip().lower() for part in value.split(";") if part.strip()]


def trim(value, limit=90):
    value = value.strip()
    if len(value) > limit:
        return value[:limit] + "..."
    return value


def check_hsts(headers):
    findings = []
    value = headers.get("strict-transport-security")
    if value is None:
        findings.append(("FAIL", "HSTS", -25,
                         "Strict-Transport-Security missing", HSTS_FIX))
        return findings
    directives = parse_directives(value)
    max_age = None
    for directive in directives:
        if directive.startswith("max-age="):
            try:
                max_age = int(directive.split("=", 1)[1].strip().strip('"'))
            except ValueError:
                max_age = None
    if max_age is None or max_age < HSTS_MIN_MAX_AGE:
        findings.append(("WARN", "HSTS", -10,
                         "Strict-Transport-Security max-age too short (< %d): %s"
                         % (HSTS_MIN_MAX_AGE, value), HSTS_FIX))
    elif "includesubdomains" not in directives:
        findings.append(("WARN", "HSTS", -5,
                         "Strict-Transport-Security lacks includeSubDomains: %s"
                         % value, HSTS_FIX))
    if not findings:
        findings.append(("PASS", "HSTS", 0,
                         "Strict-Transport-Security present with strong max-age: %s"
                         % value, None))
    return findings


def _csp_directive_map(value):
    """Parse a CSP value into {directive: [sources]}."""
    directives = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return directives


# Source expressions that make a script/style policy effectively open.
_CSP_WILDCARDS = ("*", "data:", "blob:", "https:", "http:")
_CSP_UNSAFE = ("'unsafe-inline'", "'unsafe-eval'")


def check_csp(headers):
    findings = []
    csp = headers.get("content-security-policy")
    report_only = headers.get("content-security-policy-report-only")
    if not csp:
        if report_only:
            findings.append(("WARN", "CSP", -10,
                             "Only Content-Security-Policy-Report-Only is set; nothing is enforced",
                             CSP_RO_FIX))
        else:
            findings.append(("FAIL", "CSP", -20,
                             "Content-Security-Policy missing", CSP_FIX))
        return findings

    directives = _csp_directive_map(csp)
    problems = []
    script_src = directives.get("script-src", directives.get("default-src", []))
    for source in script_src:
        if source in _CSP_WILDCARDS or source.endswith(":*"):
            problems.append("script-src allows wildcard source %r" % source)
        elif source in _CSP_UNSAFE:
            problems.append("script-src allows %s" % source)
    default_src = directives.get("default-src", [])
    if any(s in _CSP_WILDCARDS for s in default_src):
        problems.append("default-src allows wildcard sources")
    object_src = directives.get("object-src", [])
    if "'none'" not in object_src:
        problems.append("object-src is not restricted to 'none' "
                        "(plugin content can load)")
    if "base-uri" not in directives:
        problems.append("base-uri is not set (base-tag hijacking possible)")
    if problems:
        findings.append(("FAIL", "CSP", -20,
                         "Weak Content-Security-Policy: %s. Policy: %s"
                         % ("; ".join(problems), trim(csp)), CSP_FIX))
    else:
        findings.append(("PASS", "CSP", 0,
                         "Content-Security-Policy present and restrictive: %s"
                         % trim(csp), None))
    return findings


def check_framing(headers):
    xfo = headers.get("x-frame-options", "").strip().upper()
    csp = headers.get("content-security-policy", "")
    frame_ancestors = any(
        d.startswith("frame-ancestors") for d in parse_directives(csp)
    )
    if xfo in ("DENY", "SAMEORIGIN"):
        return [("PASS", "Framing", 0,
                 "X-Frame-Options: %s blocks clickjacking" % xfo, None)]
    if frame_ancestors:
        return [("PASS", "Framing", 0,
                 "CSP frame-ancestors directive blocks clickjacking (no X-Frame-Options needed)",
                 None)]
    if xfo:
        return [("WARN", "Framing", -5,
                 "X-Frame-Options has an unusual value: %s" % xfo, XFO_FIX)]
    return [("WARN", "Framing", -10,
             "No X-Frame-Options and no CSP frame-ancestors: clickjacking possible",
             XFO_FIX)]


def check_xcto(headers):
    value = headers.get("x-content-type-options", "").strip().lower()
    if value == "nosniff":
        return [("PASS", "MIME", 0, "X-Content-Type-Options: nosniff", None)]
    if value:
        return [("FAIL", "MIME", -10,
                 "X-Content-Type-Options has wrong value: %s" % value, XCTO_FIX)]
    return [("FAIL", "MIME", -10, "X-Content-Type-Options missing", XCTO_FIX)]


# Referrer-Policy values ordered from safest to least safe. Anything not
# on this list (including "unsafe-url") leaks more than it should.
_REFERRER_SAFE = (
    "no-referrer",
    "same-origin",
    "strict-origin",
    "no-referrer-when-downgrade",
    "strict-origin-when-cross-origin",
    "origin",
    "origin-when-cross-origin",
)


def check_referrer_policy(headers):
    value = (headers.get("referrer-policy") or "").strip().lower()
    if not value:
        return [("WARN", "Referrer", -5, "Referrer-Policy missing",
                 REFERRER_FIX)]
    if value == "unsafe-url":
        return [("FAIL", "Referrer", -10,
                 "Referrer-Policy is 'unsafe-url': the full URL (including "
                 "query strings and tokens) leaks to every third party",
                 REFERRER_FIX)]
    if value not in _REFERRER_SAFE:
        return [("WARN", "Referrer", -5,
                 "Referrer-Policy has an unusual value: %r" % value,
                 REFERRER_FIX)]
    return [("PASS", "Referrer", 0,
             "Referrer-Policy: %s" % value, None)]


def analyze(final_url, headers):
    """Run all checks. Returns (findings, score, letter)."""
    findings = []
    findings.extend(check_hsts(headers))
    findings.extend(check_csp(headers))
    findings.extend(check_framing(headers))
    findings.extend(check_xcto(headers))
    findings.extend(check_referrer_policy(headers))
    score = max(0, 100 + sum(points for _, _, points, _, _ in findings))

    def grade(value):
        if value >= 90:
            return "A"
        if value >= 80:
            return "B"
        if value >= 70:
            return "C"
        if value >= 60:
            return "D"
        return "F"

    return findings, score, grade(score)


# ---------------------------------------------------------------------------
# Mapping of check results to findings
# ---------------------------------------------------------------------------

def _map_finding(check, result, detail, fix):
    """Map (check, result) to (severity, title, cwe), or None to skip."""
    if check == "HSTS" and result == "FAIL":
        return ("medium", "Missing Strict-Transport-Security header", "CWE-319")
    if check == "HSTS" and result == "WARN":
        return ("low", "Weak Strict-Transport-Security header", "CWE-319")
    if check == "CSP" and result == "FAIL":
        if detail.startswith("Weak"):
            return ("medium", "Weak Content-Security-Policy allows unsafe sources",
                    "CWE-693")
        return ("medium", "Missing Content-Security-Policy header", "CWE-693")
    if check == "CSP" and result == "WARN":
        return ("low", "Content-Security-Policy is report-only (not enforced)",
                "CWE-693")
    if check == "Framing" and result == "WARN":
        return ("low",
                "Missing clickjacking protection (X-Frame-Options / frame-ancestors)",
                "CWE-1021")
    if check == "MIME" and result == "FAIL":
        return ("low", "Missing X-Content-Type-Options header", "CWE-693")
    if check == "Referrer" and result == "WARN":
        return ("info", "Missing Referrer-Policy header", "CWE-200")
    if check == "Referrer" and result == "FAIL":
        return ("low", "Referrer-Policy leaks full URLs (unsafe-url)",
                "CWE-200")
    return None


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(target, ctx):
    """Scan target and return one finding per missing/weak header."""
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
    resp = _get(target, ctx)
    if resp is None:
        return []
    status, headers, body, final_url = resp
    findings, score, letter = analyze(final_url, headers)
    evidence = "HTTP %s\n%s" % (status, _header_dump(headers))
    out = []
    for result, check, points, detail, fix in findings:
        mapped = _map_finding(check, result, detail, fix)
        if mapped is None:
            continue
        severity, title, cwe = mapped
        out.append(_finding(
            target=target,
            severity=severity,
            confidence="strong",
            title=title,
            description="%s (security headers grade: %s, %d/100)" % (detail, letter, score),
            evidence=evidence,
            cwe=cwe,
            remediation=fix,
        ))
    return out
