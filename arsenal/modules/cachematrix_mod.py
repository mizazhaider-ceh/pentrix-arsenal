"""PENTRIX ARSENAL module: cache deception / poisoning matrix.

Cache bugs are pure manual methodology today (Burp documents the
technique, no scanner automates it). This module automates the matrix:

1. CACHE-KEY PROBING: which parts of the request actually key the cache
   (unkeyed query params, delimiters, extensions, normalization).
2. HIT/MISS analysis via cache headers (x-cache, cf-cache-status, age,
   x-served-by) across paired requests.
3. POISON PROOF: two-request proof that crafted content was served from
   cache to a second (victim) request.
4. DECEPTION: two-account confirmation guidance for web cache deception
   (attacker URL cached, victim content served).

Intrusive: sends crafted cache-busting requests to the target.
Authorized engagements only.
"""

import re
import time
import urllib.parse

from arsenal.findings import make_finding
from arsenal.http import fetch

NAME = "cachematrix"
DESCRIPTION = (
    "Automated web-cache deception/poisoning matrix: cache-key probing, "
    "HIT/MISS analysis, two-request poison proof, deception guidance."
)
TARGET_KIND = "url"
INTRUSIVE = True

TIMEOUT = 12

# --- probe sets -----------------------------------------------------------

UNKEYED_PARAMS = ["utm_source", "utm_medium", "x", "cb", "foo", "a", "test"]
DELIMITERS = [";", "%3b", "%23", "%3f", "%2e", "/..;/", "%2f"]
EXTENSIONS = [".css", ".js", ".png", ".ico", ".txt", "/x.css", "/x.js"]
NORMALIZATIONS = [
    ("trailing slash", lambda u: u.rstrip("/") + "/"),
    ("double slash", lambda u: _double_slash(u)),
    ("case variant", lambda u: _case_path(u)),
    ("dot segment", lambda u: u.rstrip("/") + "/./"),
    ("encoded slash", lambda u: u.replace("/", "%2f", 1)),
]


def _double_slash(url):
    parts = urllib.parse.urlsplit(url)
    path = parts.path if parts.path.startswith("/") else "/" + parts.path
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, "/" + path, parts.query, parts.fragment))


def _case_path(url):
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path.upper(), parts.query, parts.fragment))


def _with_param(url, name, value):
    parts = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    q.append((name, value))
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path,
         urllib.parse.urlencode(q), parts.fragment))


CACHE_HIT_MARKERS = ("hit", "tcp_hit")
CACHE_MISS_MARKERS = ("miss", "tcp_miss", "dynamic", "bypass")


def _cache_status(headers):
    """Return 'HIT', 'MISS', or 'UNKNOWN' from cache-indicating headers."""
    h = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    for name in ("x-cache", "cf-cache-status", "x-cache-status",
                 "x-drupal-cache", "x-varnish", "x-fastly-cache-status"):
        val = h.get(name, "")
        if any(m in val for m in CACHE_HIT_MARKERS):
            return "HIT"
        if any(m in val for m in CACHE_MISS_MARKERS):
            return "MISS"
    if h.get("age", "").strip().isdigit() and int(h["age"]) > 0:
        return "HIT"
    return "UNKNOWN"


def _fetch(url, ctx):
    try:
        status, headers, body, _final = fetch(url, ctx=ctx, timeout=TIMEOUT)
    except Exception:
        return None
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body)
    return {"status": status, "body": text, "headers": dict(headers or {}),
            "cache": _cache_status(headers)}


def _log(ctx, level, msg):
    log = getattr(ctx, "log", None)
    if log:
        getattr(log, level, log.info)(msg)


# --- matrix stages --------------------------------------------------------

def probe_cache_key(target, ctx):
    """Stage 1: find what is/is not part of the cache key."""
    base = _fetch(target, ctx)
    if not base:
        return {"error": "target unreachable"}
    results = {"base_cache": base["cache"], "unkeyed_params": [],
               "delimiters": [], "extensions": [], "normalizations": []}
    # unkeyed params: same body + HIT means the param is not keyed
    for p in UNKEYED_PARAMS:
        url = _with_param(target, p, "cacheprobe123")
        r1, r2 = _fetch(url, ctx), _fetch(url, ctx)
        if r1 and r2:
            same_body = r1["body"] == base["body"]
            results["unkeyed_params"].append(
                {"param": p, "first": r1["cache"], "second": r2["cache"],
                 "same_body_as_base": same_body,
                 "likely_unkeyed": same_body and r2["cache"] == "HIT"})
        time.sleep(0.2)
    # delimiters / extensions / normalization: HIT on weird URL = key confusion
    parts = urllib.parse.urlsplit(target)
    for d in DELIMITERS:
        url = urllib.parse.urlunsplit(
            (parts.scheme, parts.netloc, parts.path + d, parts.query, parts.fragment))
        r = _fetch(url, ctx)
        if r:
            results["delimiters"].append(
                {"trick": d, "status": r["status"], "cache": r["cache"]})
    for e in EXTENSIONS:
        url = urllib.parse.urlunsplit(
            (parts.scheme, parts.netloc, parts.path + e, parts.query, parts.fragment))
        r = _fetch(url, ctx)
        if r:
            results["extensions"].append(
                {"trick": e, "status": r["status"], "cache": r["cache"]})
    for label, fn in NORMALIZATIONS:
        try:
            url = fn(target)
        except Exception:
            continue
        if url == target:
            continue
        r = _fetch(url, ctx)
        if r:
            results["normalizations"].append(
                {"trick": label, "status": r["status"], "cache": r["cache"],
                 "same_body": r["body"] == base["body"]})
    return results


def poison_proof(target, ctx, payload_marker="CACHEPOISON-ar7x1"):
    """Stage 2: two-request proof that poisoned content is served from cache.

    Request 1 carries an unkeyed input reflected in the page (e.g. a
    header or param); request 2 (victim, no poison input) must show the
    same marker served from cache. Returns a verdict dict.
    """
    bust = "pb%d" % int(time.time())
    poisoned_url = _with_param(target, "utm_source", payload_marker + "-" + bust)
    r1 = _fetch(poisoned_url, ctx)
    if not r1:
        return {"verdict": "error", "reason": "poison request failed"}
    marker_hit = payload_marker in r1["body"]
    time.sleep(1.0)
    victim_url = _with_param(target, "utm_source", "victim-" + bust)
    r2 = _fetch(victim_url, ctx)
    if not r2:
        return {"verdict": "error", "reason": "victim request failed"}
    served_from_cache = r2["cache"] == "HIT" and payload_marker in r2["body"]
    return {
        "verdict": "VULNERABLE" if (marker_hit and served_from_cache)
                   else ("reflected-not-cached" if marker_hit else "not-reflected"),
        "poison_reflected": marker_hit,
        "victim_served_marker": payload_marker in r2["body"],
        "victim_cache": r2["cache"],
        "evidence_urls": [poisoned_url, victim_url],
    }


def deception_guidance(target):
    """Stage 3: two-account web cache deception confirmation steps."""
    parts = urllib.parse.urlsplit(target)
    trick = urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path + "/x.css",
         parts.query, parts.fragment))
    return [
        "1. Log in as VICTIM in browser A; load %s and note private content." % target,
        "2. As ATTACKER (logged out / other account), request the deception URL: %s" % trick,
        "3. If step 2 returns the VICTIM's private content (check for your "
        "own account name, CSRF token, or PII), the cache stored an "
        "authenticated response under an attacker-reachable key.",
        "4. Confirm with a second fresh session: private content must still "
        "be served without any victim cookies (proves cache, not session).",
        "5. Report with both request/response pairs and the differing "
        "Set-Cookie / Authorization state.",
    ]


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(target, ctx):
    try:
        return _run(target, ctx)
    except Exception as exc:
        _log(ctx, "warning", "%s failed on %s: %s" % (NAME, target, exc))
        return []


def _run(target, ctx):
    if INTRUSIVE and getattr(ctx, "safe_mode", False) \
            and not getattr(ctx, "allow_intrusive", False):
        _log(ctx, "warning", "%s skipped: safe mode blocks intrusive modules" % NAME)
        return []
    findings = []
    key = probe_cache_key(target, ctx)
    if key.get("error"):
        return findings

    unkeyed = [u["param"] for u in key["unkeyed_params"] if u["likely_unkeyed"]]
    if unkeyed:
        findings.append(make_finding(
            NAME, target, "medium",
            "Cache key ignores parameters: %s" % ", ".join(unkeyed),
            "These query parameters do not change the cached response "
            "(same body as base, second request served as HIT). Unkeyed "
            "inputs are the precondition for both cache poisoning and "
            "web cache deception.",
            evidence="unkeyed=%s base_cache=%s" % (unkeyed, key["base_cache"]),
            confidence="strong",
            remediation="Include all user-influenced input in the cache "
                        "key, or mark responses containing it as "
                        "non-cacheable."))

    suspicious = [d for d in key["delimiters"] + key["extensions"]
                  if d["cache"] == "HIT" and d["status"] == 200]
    if suspicious:
        tricks = ", ".join(d["trick"] for d in suspicious)
        findings.append(make_finding(
            NAME, target, "medium",
            "Cache confusion via path tricks: %s" % tricks,
            "The cache served HIT for URLs with path delimiters or "
            "appended static extensions while the backend returned 200. "
            "This mismatch is the classic web-cache-deception shape: the "
            "cache keys on a normalized path the backend interprets "
            "differently.",
            evidence="tricks=%s" % tricks, confidence="review",
            remediation="Normalize cache keys the same way the backend "
                        "normalizes paths; do not cache authenticated "
                        "responses under extension-mapped keys."))

    proof = poison_proof(target, ctx)
    if proof.get("verdict") == "VULNERABLE":
        findings.append(make_finding(
            NAME, target, "high",
            "Web cache poisoning confirmed (two-request proof)",
            "A poisoned marker reflected in request 1 was served to a "
            "second victim request from cache (%s). Full two-request "
            "evidence below." % proof["victim_cache"],
            evidence="poison_url=%s victim_url=%s" % tuple(proof["evidence_urls"]),
            confidence="strong", cwe="CWE-444",
            remediation="Fix cache-key inclusion and strip unkeyed input "
                        "from cacheable responses."))
    elif proof.get("verdict") == "reflected-not-cached":
        findings.append(make_finding(
            NAME, target, "info",
            "Unkeyed input reflected but not served from cache",
            "The poison marker reflected in the response but the victim "
            "request did not receive it from cache. Poisoning not proven; "
            "retry with header-based inputs (X-Forwarded-Host) or a longer "
            "cache window.",
            evidence="victim_cache=%s" % proof.get("victim_cache"),
            confidence="review"))

    findings.append(make_finding(
        NAME, target, "info",
        "Web cache deception: two-account confirmation steps",
        "Automated probing cannot log in as two users; follow these steps "
        "to confirm deception manually:\n" + "\n".join(deception_guidance(target)),
        evidence="deception_url=%s/x.css" % target.rstrip("/"),
        confidence="review"))
    return findings
