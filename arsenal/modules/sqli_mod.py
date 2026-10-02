"""PENTRIX ARSENAL module: error-based SQL injection probing.

Adapted from pentrix-sqli: reuses the run_scan()/probe logic. For each
query parameter of a URL, sends a small set of classic break-out payloads
and compares each response against the baseline. Response bodies are
matched against a table of DBMS error signatures to identify the likely
database engine. One finding per vulnerable parameter.

Intrusive: sends crafted payloads. Detection only: no data extraction.
"""

import re
import urllib.parse

from arsenal.findings import make_finding
from arsenal.http import fetch

NAME = "sqli"
DESCRIPTION = (
    "Probes URL query parameters for error-based SQL injection by sending "
    "break-out payloads and matching responses against DBMS error "
    "signatures."
)
TARGET_KIND = "url"
INTRUSIVE = True

TIMEOUT = 10
MAX_BODY_BYTES = 2 * 1024 * 1024

PAYLOADS = [
    "'",
    '"',
    "\\",
    "' OR '1'='1",
    '" OR "1"="1',
    "') OR ('1'='1",
]

# Maps a DBMS label to the list of substrings that, when found in a
# response body, indicate an error message from that engine.
DBMS_SIGNATURES = [
    ("MySQL", [
        "You have an error in your SQL syntax",
        "mysql_fetch",
        "MySQL server",
        "Warning: mysql_",
        "mysqli::",
    ]),
    ("PostgreSQL", [
        "pg_query()",
        "unterminated quoted string",
        "PostgreSQL",
        "pg_fetch_",
    ]),
    ("MSSQL", [
        "Unclosed quotation mark",
        "Microsoft SQL Server",
        "ODBC SQL Server",
        "SqlException",
        "ODBC Microsoft Access Driver",
    ]),
    ("Oracle", [
        "ORA-",
        "Oracle error",
        "Oracle() query",
    ]),
    ("SQLite", [
        "sqlite3",
        "SQLITE_ERROR",
        'near "syntax error"',
        "SQLite3::",
    ]),
]


# ---------------------------------------------------------------------------
# Small helpers (module-local so the module stays self-contained)
# ---------------------------------------------------------------------------

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


def _get(url, ctx):
    try:
        return fetch(url, timeout=_timeout(ctx), allow_redirects=True)
    except Exception as exc:
        _log(ctx, "debug", "%s: request failed for %s: %s" % (NAME, url, exc))
        return None


def _finding(**kwargs):
    kwargs.setdefault("module", NAME)
    return make_finding(**kwargs)


# ---------------------------------------------------------------------------
# Probe logic (adapted from pentrix-sqli)
# ---------------------------------------------------------------------------

def decode_body(headers, body):
    content_type = headers.get("content-type", "")
    match = re.search(r"charset=([\w-]+)", content_type or "", re.IGNORECASE)
    charset = match.group(1) if match else "utf-8"
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def match_dbms(body):
    """Return (dbms_label, signature) for the first matching DBMS, else None."""
    for label, signatures in DBMS_SIGNATURES:
        for signature in signatures:
            if signature in body:
                return label, signature
    return None


def build_probe_url(base, params, target_param, payload):
    probed = [
        (name, payload if name == target_param else value)
        for name, value in params
    ]
    query = urllib.parse.urlencode(probed)
    return "%s?%s" % (base, query)


def error_snippet(body, signature, radius=140):
    idx = body.find(signature)
    if idx == -1:
        return signature
    start = max(0, idx - radius)
    end = min(len(body), idx + len(signature) + radius)
    return " ".join(body[start:end].split())


def probe_param(base, params, param, baseline_signatures, ctx):
    """Probe one parameter. Returns (verdict, hits)."""
    hits = []
    for payload in PAYLOADS:
        url = build_probe_url(base, params, param, payload)
        resp = _get(url, ctx)
        if resp is None:
            continue
        status, headers, body, _final = resp
        if len(body) > MAX_BODY_BYTES:
            continue
        text = decode_body(headers, body)
        match = match_dbms(text)
        if match is None:
            continue
        dbms, signature = match
        if signature in baseline_signatures:
            # Already present in the baseline response, not caused by us.
            continue
        hits.append((payload, dbms, signature, status,
                     error_snippet(text, signature)))
    if hits:
        return "VULNERABLE", hits
    return "NOT VULNERABLE", hits


def run_scan(url, ctx):
    """Run the full scan. Returns a list of per-parameter result dicts."""
    parts = urllib.parse.urlsplit(url)
    params = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if not params:
        return []
    base = urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, "", parts.fragment))
    names = []
    for name, _ in params:
        if name not in names:
            names.append(name)

    resp = _get(url, ctx)
    if resp is None:
        raise RuntimeError("baseline request failed for %s" % url)
    _status, headers, body, _final = resp
    baseline_body = decode_body(headers, body)
    baseline_signatures = set()
    baseline_match = match_dbms(baseline_body)
    if baseline_match:
        baseline_signatures.add(baseline_match[1])

    results = []
    for name in names:
        verdict, hits = probe_param(base, params, name, baseline_signatures, ctx)
        results.append({"parameter": name, "verdict": verdict, "hits": hits})
    return results


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(target, ctx):
    """Probe target for error-based SQLi; one finding per vulnerable parameter."""
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
    for entry in run_scan(target, ctx):
        if entry["verdict"] != "VULNERABLE":
            continue
        votes = {}
        for _payload, dbms, _sig, _status, _snip in entry["hits"]:
            votes[dbms] = votes.get(dbms, 0) + 1
        likely = max(votes, key=votes.get)
        evidence_lines = []
        for payload, dbms, signature, status, snippet in entry["hits"]:
            evidence_lines.append(
                "payload %r -> HTTP %s, matched '%s' (%s)\n  %s"
                % (payload, status, signature, dbms, snippet)
            )
        out.append(_finding(
            target=target,
            severity="high",
            confidence="strong",
            title="SQL injection in parameter '%s' (likely DBMS: %s)"
                  % (entry["parameter"], likely),
            description=(
                "Parameter '%s' appears vulnerable to error-based SQL "
                "injection: crafted break-out payloads triggered database "
                "error messages consistent with %s."
                % (entry["parameter"], likely)
            ),
            evidence="\n".join(evidence_lines),
            cwe="CWE-89",
            remediation=(
                "Use parameterized queries / prepared statements for '%s', "
                "apply least-privilege DB accounts, and stop leaking "
                "database errors to clients." % entry["parameter"]
            ),
        ))
    return out
