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
- ssrf_mod: replays the evidence "Request:" URL; when cloud metadata
  markers appear in the response, or a "Callback-Tag:" inbox hit is
  recorded, confidence becomes "proven".
- lfi_mod: replays the evidence "Request:" URL; when a file canary
  (root:x:0:0, [extensions]) appears, or a "Callback-Tag:" inbox hit
  is recorded, confidence becomes "proven".
- xxe_mod: replays the evidence "Payload:" via POST; when the passwd
  canary appears, or a "Callback-Tag:" inbox hit is recorded,
  confidence becomes "proven".
- idor_mod: re-fetches the evidence "Baseline-URL:" and "Variant-URL:";
  when both still return 200 with different content, confidence
  becomes "strong".
- Everything else keeps its existing confidence, defaulting to "review"
  when none is set.

Standard library only. Never raises on a single bad finding: failures
leave the finding's confidence untouched.
"""

import hashlib
import json
import urllib.parse
from pathlib import Path

from arsenal.http import fetch

TIMEOUT = 10
EVIL_ORIGIN = "https://evil.example.com"
EVIL_HOST = "evil.example.com"
MAX_HOPS = 3

DBMS_LABELS = ("MySQL", "PostgreSQL", "MSSQL", "Oracle", "SQLite")

SSRF_METADATA_MARKERS = (
    "ami-id", "instance-id", "computeMetadata", "Metadata-Flavor",
    "metadata.google.internal",
)
LFI_CANARIES = ("root:x:0:0", "root:*:0:0", "[extensions]", "[fonts]")


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


def _request_line_url(evidence):
    """Extract the replay URL from an evidence "Request:" line."""
    for line in (evidence or "").splitlines():
        if line.startswith("Request: "):
            url = line[len("Request: "):].strip()
            if url.startswith("POST "):
                url = url[len("POST "):].strip()
            return url.split(" ")[0]
    return ""


def _callback_tag(evidence):
    for line in (evidence or "").splitlines():
        if line.startswith("Callback-Tag: "):
            return line[len("Callback-Tag: "):].strip()
    return ""


def _inbox_has_hit(tag):
    """True when the local arsenal inbox recorded a hit for tag."""
    if not tag:
        return False
    path = Path.home() / ".arsenal" / "inbox.jsonl"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return False
    for line in lines[-200:]:
        try:
            rec = json.loads(line)
        except Exception:
            continue
        hay = "%s %s" % (rec.get("path", ""), rec.get("query", ""))
        if tag in hay:
            return True
    return False


def _body_text(resp):
    if resp is None:
        return ""
    _status, _headers, body, _final = resp
    try:
        return (body or b"").decode("utf-8", errors="replace")
    except Exception:
        return ""


def _verify_ssrf(finding, ctx):
    """Replay the SSRF probe; prove fetched metadata or a callback hit."""
    evidence = finding.get("evidence") or ""
    if _inbox_has_hit(_callback_tag(evidence)):
        return "proven"
    url = _request_line_url(evidence)
    if not url:
        return None
    text = _body_text(_fetch(url, ctx))
    if any(m in text for m in SSRF_METADATA_MARKERS):
        return "proven"
    return None


def _verify_lfi(finding, ctx):
    """Replay the LFI probe; prove canary content or a callback hit."""
    evidence = finding.get("evidence") or ""
    if _inbox_has_hit(_callback_tag(evidence)):
        return "proven"
    url = _request_line_url(evidence)
    if not url:
        return None
    text = _body_text(_fetch(url, ctx))
    if any(m in text for m in LFI_CANARIES):
        return "proven"
    return None


def _verify_xxe(finding, ctx):
    """Re-POST the XXE payload; prove canary content or a callback hit."""
    evidence = finding.get("evidence") or ""
    if _inbox_has_hit(_callback_tag(evidence)):
        return "proven"
    url = _request_line_url(evidence)
    payload = ""
    for line in evidence.splitlines():
        if line.startswith("Payload: "):
            payload = line[len("Payload: "):].strip()
            break
    if not url or not payload:
        return None
    try:
        resp = fetch(url, method="POST", timeout=_timeout(ctx),
                     headers={"Content-Type": "application/xml"},
                     data=payload.encode("utf-8"),
                     allow_redirects=True, ctx=ctx)
    except Exception:
        return None
    if "root:x:0:0" in _body_text(resp):
        return "proven"
    return None


def _fp_resp(resp):
    if resp is None:
        return (0, 0, "")
    status, _h, body, _f = resp
    body = body or b""
    return (status, len(body), hashlib.sha256(body).hexdigest()[:16])


def _verify_idor(finding, ctx):
    """Re-fetch baseline and variant; confirm the differential persists."""
    evidence = finding.get("evidence") or ""
    baseline_url, variant_url = "", ""
    for line in evidence.splitlines():
        if line.startswith("Baseline-URL: "):
            baseline_url = line[len("Baseline-URL: "):].strip()
        elif line.startswith("Variant-URL: "):
            variant_url = line[len("Variant-URL: "):].strip()
    if not baseline_url or not variant_url:
        return None
    b_fp = _fp_resp(_fetch(baseline_url, ctx))
    v_fp = _fp_resp(_fetch(variant_url, ctx))
    if b_fp[0] == 200 and v_fp[0] == 200 and b_fp[2] != v_fp[2]:
        return "strong"
    return None


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
    elif module in ("ssrf", "ssrf_mod"):
        proven = _verify_ssrf(finding, ctx)
        finding["confidence"] = proven or finding.get("confidence") or "review"
    elif module in ("lfi", "lfi_mod"):
        proven = _verify_lfi(finding, ctx)
        finding["confidence"] = proven or finding.get("confidence") or "review"
    elif module in ("xxe", "xxe_mod"):
        proven = _verify_xxe(finding, ctx)
        finding["confidence"] = proven or finding.get("confidence") or "review"
    elif module in ("idor", "idor_mod"):
        proven = _verify_idor(finding, ctx)
        finding["confidence"] = proven or finding.get("confidence") or "review"
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
