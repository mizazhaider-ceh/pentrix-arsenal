#!/usr/bin/env python3
"""PENTRIX ARSENAL target prioritization.

rank_targets() scores candidate hosts 0-100 from recon signals so a hunter
knows where to start. Each input is a dict:

    {
        "host": "api.example.com",
        "alive_url": "https://api.example.com",
        "tech": ["WordPress 6.4.1", "jQuery 3.7.1"],
        "has_login": True,
        "param_count": 4,
        "is_new": True,
        "has_js_secrets": False,
        "keywords": ["staging"],
    }

Returns a list sorted by score (desc) of:
    {"host": ..., "score": ..., "reasons": [...],
     "verdict": "start here" | "worth a look" | "low priority"}
"""

import re

# Hostname tokens that usually mark higher-value targets.
PRIORITY_KEYWORDS = (
    "staging", "stage", "dev", "test", "admin", "api", "beta", "qa",
    "uat", "demo", "sandbox", "internal", "preprod", "preview",
    "canary", "legacy", "old",
)

# Technologies worth extra attention when a version is disclosed.
INTERESTING_TECH = (
    "wordpress", "laravel", "django", "drupal", "joomla",
    "magento", "struts", "sharepoint", "sitecore",
)

VERSION_RE = re.compile(r"\d+(?:\.\d+)+")


def _exploitable_modules():
    try:
        from arsenal.modules import REGISTRY
        known = set(REGISTRY)
    except Exception:
        known = set()
    return {m for m in ("xss", "sqli", "ssrf", "rce", "lfi", "idor",
                        "auth-bypass")
            if (not known) or m in known}


_SEV_POINTS = {"critical": 40, "high": 30, "medium": 15, "low": 5, "info": 0}
_CONF_POINTS = {"proven": 20, "strong": 10, "review": 0}


def score_finding(finding):
    """Score one finding 0-100 for hunt priority (autopilot ordering).

    Returns {"score", "reasons", "verdict"} where verdict is
    "verify now" | "triage first" | "context".
    """
    if not isinstance(finding, dict):
        return {"score": 0, "reasons": [], "verdict": "context"}
    score = 0
    reasons = []
    sev = str(finding.get("severity") or "info").lower()
    pts = _SEV_POINTS.get(sev, 0)
    if pts:
        score += pts
        reasons.append("%s severity (+%d)" % (sev, pts))
    conf = str(finding.get("confidence") or "review").lower()
    cpts = _CONF_POINTS.get(conf, 0)
    if cpts:
        score += cpts
        reasons.append("%s confidence (+%d)" % (conf, cpts))
    module = str(finding.get("module") or "").lower()
    if module in _exploitable_modules():
        score += 15
        reasons.append("directly-exploitable class %s (+15)" % module)
    if finding.get("param") or finding.get("parameter"):
        score += 5
        reasons.append("has an injection parameter (+5)")
    evidence = str(finding.get("evidence") or "")
    if len(evidence) > 120:
        score += 5
        reasons.append("substantial evidence captured (+5)")
    score = min(100, score)
    if score >= 50:
        verdict = "verify now"
    elif score >= 25:
        verdict = "triage first"
    else:
        verdict = "context"
    return {"score": score, "reasons": reasons, "verdict": verdict}


def _hostname_tokens(host):
    """Split a hostname into lowercase tokens on dots, dashes, underscores."""
    return [t for t in re.split(r"[.\-_]+", (host or "").lower()) if t]


def rank_targets(host_infos):
    """Score and rank target hosts. Returns a new sorted list."""
    ranked = []
    for info in host_infos or []:
        if not isinstance(info, dict):
            continue
        host = info.get("host") or ""
        score = 0
        reasons = []

        tokens = set(_hostname_tokens(host))
        hits = sorted(t for t in PRIORITY_KEYWORDS if t in tokens)
        if hits:
            score += 25
            reasons.append(
                "interesting keyword(s) in hostname: %s" % ", ".join(hits)
            )

        if info.get("has_login"):
            score += 20
            reasons.append("login form present")

        try:
            param_count = int(info.get("param_count") or 0)
        except (TypeError, ValueError):
            param_count = 0
        if param_count >= 3:
            score += 15
            reasons.append("%d URL parameters observed" % param_count)

        if info.get("is_new"):
            score += 15
            reasons.append("new host, not seen in previous runs")

        if info.get("has_js_secrets"):
            score += 10
            reasons.append("possible secrets found in JavaScript")

        tech = info.get("tech") or []
        versioned = []
        for entry in tech:
            low = str(entry).lower()
            if any(k in low for k in INTERESTING_TECH) and VERSION_RE.search(low):
                versioned.append(str(entry))
        if versioned:
            score += 10
            reasons.append(
                "versioned interesting tech: %s" % ", ".join(versioned[:3])
            )

        alive_url = str(info.get("alive_url") or "")
        if alive_url.startswith("https://"):
            score += 5
            reasons.append("reachable over HTTPS")

        extra_keywords = info.get("keywords") or []
        if extra_keywords and not hits:
            shown = ", ".join(str(k) for k in extra_keywords[:5])
            reasons.append("analyst keywords: %s" % shown)

        score = min(score, 100)
        if score >= 60:
            verdict = "start here"
        elif score >= 30:
            verdict = "worth a look"
        else:
            verdict = "low priority"

        ranked.append(
            {
                "host": host,
                "score": score,
                "reasons": reasons,
                "verdict": verdict,
            }
        )

    ranked.sort(key=lambda r: r["score"], reverse=True)
    return ranked
