"""PENTRIX ARSENAL module: IDOR / BOLA mass checker.

Finds numeric identifiers in URL path segments and query parameters,
fetches the baseline plus small ID variants (id-1, id+1, id+10), and
compares status code, body length and content hash. When a neighboring
ID returns 200 with different content than the baseline, the endpoint
may expose other users' objects (IDOR); on /api/* or JSON endpoints the
same signal is reported as BOLA.

This is single-session differential testing: it cannot prove the other
object belongs to another user, so findings stay at "review" confidence
with explicit two-session confirmation steps. Only a few neighboring
IDs are probed, never a full enumeration.

Non-intrusive: a handful of GET requests per identifier.
"""

import hashlib
import re
import urllib.parse

from arsenal.findings import make_finding
from arsenal.http import fetch

NAME = "idor"
DESCRIPTION = (
    "Detects insecure direct object references and broken object-level "
    "authorization by differential testing of numeric identifiers."
)
TARGET_KIND = "url"
INTRUSIVE = False

TIMEOUT = 10
MAX_IDS = 3


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


def _fingerprint(resp):
    if resp is None:
        return (0, 0, "")
    status, headers, body, _final = resp
    body = body or b""
    digest = hashlib.sha256(body).hexdigest()[:16]
    return (status, len(body), digest)


def _find_ids(target):
    """Return list of (kind, locator, value) for numeric identifiers."""
    out = []
    parts = urllib.parse.urlsplit(target)
    segs = parts.path.split("/")
    for i, seg in enumerate(segs):
        if seg.isdigit() and 0 < int(seg) < 10 ** 9:
            out.append(("path", i, int(seg)))
    for j, (k, v) in enumerate(
            urllib.parse.parse_qsl(parts.query, keep_blank_values=True)):
        if v.isdigit() and 0 < int(v) < 10 ** 9:
            out.append(("query", j, int(v)))
    return out[:MAX_IDS]


def _swap_id(target, kind, locator, new_id):
    parts = urllib.parse.urlsplit(target)
    if kind == "path":
        segs = parts.path.split("/")
        segs[locator] = str(new_id)
        return urllib.parse.urlunsplit(
            (parts.scheme, parts.netloc, "/".join(segs), parts.query,
             parts.fragment))
    q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    q[locator] = (q[locator][0], str(new_id))
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path,
         urllib.parse.urlencode(q), parts.fragment))


def _is_api(target, headers):
    if "/api/" in target:
        return True
    ctype = (headers or {}).get("content-type", "")
    return "json" in ctype


def run(target, ctx):
    """Differential-test numeric IDs for IDOR/BOLA."""
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
    ids = _find_ids(target)
    if not ids:
        return []
    findings = []

    baseline_resp = _fetch(target, ctx)
    if baseline_resp is None:
        return []
    b_status, b_headers, _b_body, _b_final = baseline_resp
    b_fp = _fingerprint(baseline_resp)
    api = _is_api(target, b_headers)
    label = "BOLA" if api else "IDOR"
    checked = False

    for kind, locator, value in ids:
        for delta in (-1, 1, 10):
            new_id = value + delta
            if new_id <= 0:
                continue
            variant_url = _swap_id(target, kind, locator, new_id)
            resp = _fetch(variant_url, ctx)
            if resp is None:
                continue
            checked = True
            v_fp = _fingerprint(resp)
            if v_fp[0] == 200 and b_fp[0] == 200 and v_fp[2] != b_fp[2]:
                findings.append(_finding(
                    target=target,
                    severity="high",
                    title="Possible %s: neighboring ID returns different object" % label,
                    description=(
                        "Changing the numeric identifier from %d to %d "
                        "returned HTTP 200 with different content than the "
                        "baseline. The endpoint may expose objects belonging "
                        "to other users. Confirm with two sessions: request "
                        "both IDs as user A and as user B and compare "
                        "ownership." % (value, new_id)),
                    evidence=(
                        "Baseline-URL: %s\nBaseline: status=%s len=%s hash=%s\n"
                        "Variant-URL: %s\nVariant: status=%s len=%s hash=%s"
                        % (target, b_fp[0], b_fp[1], b_fp[2],
                           variant_url, v_fp[0], v_fp[1], v_fp[2])),
                    confidence="review",
                    cwe="CWE-639" if api else "CWE-862",
                    remediation=(
                        "Enforce object-level authorization on every request: "
                        "check that the authenticated principal owns (or may "
                        "access) the requested ID; use unpredictable IDs.")))
                break

    if checked:
        findings.append(_finding(
            target=target,
            severity="info",
            title="IDOR follow-up: two-session confirmation steps",
            description=(
                "Differential testing is single-session and cannot prove "
                "cross-user access. To confirm: 1) create two accounts A and "
                "B; 2) as A, create/access object with ID N and note the "
                "response; 3) as B, request ID N directly; 4) if B sees A's "
                "object, the IDOR is confirmed. Also test IDOR on write "
                "paths (PUT/POST/DELETE with swapped IDs) and on nested "
                "routes like /api/users/{id}/orders."),
            evidence="Identifiers tested: %d" % len(ids),
            confidence="review",
            cwe="CWE-639",
            remediation="Document the two-session matrix in the report."))
    return findings
