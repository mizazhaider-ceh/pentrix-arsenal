"""PENTRIX ARSENAL: finding verification (auto-verify).

verify_finding(finding, ctx) re-tests a finding's claim and upgrades its
confidence; verify_all(findings, ctx) applies it to a list. Rules:

- redirect_mod (open redirect): re-fetch with redirects disabled and walk
  up to 3 hops manually. If any hop's Location points at an external host
  (different from the target's host, or the evil.example.com canary host),
  confidence becomes "proven".
- cors_mod: resend with Origin https://evil.example.com. If
  Access-Control-Allow-Origin echoes it exactly or is "*", confidence
  becomes "proven".
- xss_mod: an existing "strong" confidence is kept. verify_xss_browser()
  is a documented stub for an optional browser (playwright) confirmation
  hook; it returns None because no browser is available offline, so the
  confidence stays as the module set it.
- sqli_mod: when the evidence names an identified DBMS, confidence
  becomes "strong".
- graphql_mod: when the evidence contains schema data (__schema),
  confidence becomes "proven".
- Everything else keeps its existing confidence, defaulting to "review"
  when none is set.

Standard library only. Never raises on a single bad finding: failures
leave the finding's confidence untouched.
"""

import urllib.parse

from arsenal.http import fetch

TIMEOUT = 10
EVIL_ORIGIN = "https://evil.example.com"
EVIL_HOST = "evil.example.com"
MAX_HOPS = 3

DBMS_LABELS = ("MySQL", "PostgreSQL", "MSSQL", "Oracle", "SQLite")


def _timeout(ctx):
    cfg = getattr(ctx, "config", None) if ctx is not None else None
    if isinstance(cfg, dict):
        return cfg.get("timeout", TIMEOUT)
    if cfg is not None:
        return getattr(cfg, "timeout", TIMEOUT)
    return TIMEOUT


def _log(ctx, level, msg):
    log = getattr(ctx, "log", None) if ctx is not None else None
    if log is None:
        return
    try:
        getattr(log, level, log.warning)(msg)
    except Exception:
        pass


def _host_of(url):
    try:
        return urllib.parse.urlsplit(url).hostname or ""
    except Exception:
        return ""


def _fetch(url, ctx, headers=None, allow_redirects=True):
    try:
        return fetch(url, headers=headers or {}, timeout=_timeout(ctx),
                     allow_redirects=allow_redirects)
    except Exception as exc:
        _log(ctx, "debug", "verify: request failed for %s: %s" % (url, exc))
        return None


# ---------------------------------------------------------------------------
# Optional browser hook (stub)
# ---------------------------------------------------------------------------

def verify_xss_browser(url):
    """Optional browser-based XSS confirmation hook.

    In a full deployment this would drive a headless browser (playwright)
    to the URL and report whether the payload executes. It is a stub here:
    no browser automation is available offline, so it always returns None
    and xss findings keep the confidence the module assigned.
    """
    return None


# ---------------------------------------------------------------------------
# Per-module verifiers
# ---------------------------------------------------------------------------

def _verify_redirect(finding, ctx):
    """Walk the redirect chain manually; prove external redirection.

    The finding's evidence carries the exact proof-of-concept request URL
    ("Request: ..." line); verification starts from there so it replays
    the same redirect instead of the benign original target.
    """
    target = finding.get("target", "")
    evidence = finding.get("evidence") or ""
    start_url = target
    for line in evidence.splitlines():
        if line.startswith("Request: "):
            candidate = line[len("Request: "):].strip()
            if candidate:
                start_url = candidate
            break
    origin_host = _host_of(target).lower()
    url = start_url
    for _ in range(MAX_HOPS):
        resp = _fetch(url, ctx, allow_redirects=False)
        if resp is None:
            break
        _status, headers, _body, _final = resp
        location = headers.get("location", "")
        if not location:
            break
        resolved = urllib.parse.urljoin(url, location)
        loc_host = _host_of(resolved).lower()
        if loc_host and (loc_host == EVIL_HOST or loc_host != origin_host):
            return "proven"
        url = resolved
    return None


def _verify_cors(finding, ctx):
    """Re-send the evil Origin and check for reflection or wildcard."""
    target = finding.get("target", "")
    resp = _fetch(target, ctx, headers={"Origin": EVIL_ORIGIN})
    if resp is None:
        return None
    _status, headers, _body, _final = resp
    acao = headers.get("access-control-allow-origin", "").strip()
    if acao == EVIL_ORIGIN or acao == "*":
        return "proven"
    return None


def _verify_xss(finding, ctx):
    """Keep an existing strong confidence; browser hook is unavailable."""
    target = finding.get("target", "")
    verify_xss_browser(target)  # stub: returns None offline
    return finding.get("confidence") or "review"


def _verify_sqli(finding, ctx):
    """Promote to strong when the evidence identifies a DBMS."""
    evidence = finding.get("evidence") or ""
    description = finding.get("description") or ""
    haystack = "%s\n%s" % (evidence, description)
    if any(label in haystack for label in DBMS_LABELS):
        return "strong"
    return finding.get("confidence") or "review"


def _verify_graphql(finding, ctx):
    """Promote to proven when schema evidence is present."""
    evidence = finding.get("evidence") or ""
    if '"__schema"' in evidence or "__schema" in evidence:
        return "proven"
    return finding.get("confidence") or "review"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_finding(finding, ctx):
    """Re-test one finding and return an updated copy with new confidence."""
    try:
        return _verify_finding(dict(finding), ctx)
    except Exception as exc:
        _log(ctx, "warning", "verify failed for finding %r: %s"
             % (finding.get("title"), exc))
        updated = dict(finding)
        updated.setdefault("confidence", "review")
        return updated


def _verify_finding(finding, ctx):
    module = finding.get("module", "")
    if module == "redirect_mod":
        proven = _verify_redirect(finding, ctx)
        finding["confidence"] = proven or finding.get("confidence") or "review"
    elif module == "cors_mod":
        proven = _verify_cors(finding, ctx)
        finding["confidence"] = proven or finding.get("confidence") or "review"
    elif module == "xss_mod":
        finding["confidence"] = _verify_xss(finding, ctx)
    elif module == "sqli_mod":
        finding["confidence"] = _verify_sqli(finding, ctx)
    elif module == "graphql_mod":
        finding["confidence"] = _verify_graphql(finding, ctx)
    else:
        finding.setdefault("confidence", "review")
    return finding


def verify_all(findings, ctx):
    """Verify every finding in the list; never raises on a bad entry."""
    verified = []
    for finding in findings or []:
        try:
            verified.append(verify_finding(finding, ctx))
        except Exception as exc:
            _log(ctx, "warning", "verify_all skipped a finding: %s" % exc)
            verified.append(finding)
    return verified
