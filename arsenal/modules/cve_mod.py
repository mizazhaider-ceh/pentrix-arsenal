"""CVE lookup module backed by the NVD API 2.0.

Searches the National Vulnerability Database by keyword and returns one
info finding per CVE, with the CVE ID, CVSS score and a summary.
Severity is mapped from the CVSS base score:
>=9 critical, >=7 high, >=4 medium, otherwise low.

Adapted from pentrix-cve (search / normalize / cvss parsing).
"""

import urllib.parse

from arsenal.findings import make_finding
from arsenal.http import fetch_json

NAME = "cve"
DESCRIPTION = "Search NVD for CVEs matching a keyword."
TARGET_KIND = "keyword"
INTRUSIVE = False

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_DEFAULT_LIMIT = 5
_MAX_LIMIT = 10
_DEFAULT_TIMEOUT = 15


def cvss_for(cve):
    """Return (version, score, severity) preferring CVSS v3.x, then v2.

    Adapted from pentrix-cve.
    """
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key)
        if entries:
            data = entries[0]["cvssData"]
            return (data.get("version"), data.get("baseScore"),
                    data.get("baseSeverity"))
    entries = metrics.get("cvssMetricV2")
    if entries:
        data = entries[0]["cvssData"]
        return (data.get("version"), data.get("baseScore"),
                entries[0].get("baseSeverity"))
    return (None, None, None)


def cwe_for(cve):
    """Return the first CWE id (e.g. 'CWE-79') found in weaknesses, or None."""
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.upper().startswith("CWE-"):
                return value.upper()
    return None


def english_description(cve):
    """Return the English description of a CVE, or a fallback message.

    Adapted from pentrix-cve.
    """
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return "No English description available."


def truncate(text, limit=280):
    """Shorten text to roughly `limit` chars, cutting at a word boundary."""
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0]
    return cut + "..."


def normalize(cve):
    """Flatten one NVD "cve" object into a plain dict.

    Adapted from pentrix-cve.
    """
    version, score, severity = cvss_for(cve)
    return {
        "id": cve.get("id", "UNKNOWN"),
        "cvss_version": version,
        "cvss_score": score,
        "severity": severity or "UNKNOWN",
        "published": (cve.get("published") or "UNKNOWN")[:10],
        "description": truncate(english_description(cve)),
        "references": len(cve.get("references", [])),
        "cwe": cwe_for(cve),
    }


def search(keyword, limit, timeout):
    """Search NVD by keyword, returning up to `limit` normalized dicts.

    Adapted from pentrix-cve; uses arsenal.http.fetch_json.
    """
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": min(max(limit, 1), 50),
        "startIndex": 0,
    }
    url = NVD_BASE + "?" + urllib.parse.urlencode(params)
    status, data, _final = fetch_json(url, timeout=timeout)
    if status == 0 or not isinstance(data, dict):
        raise RuntimeError("NVD request failed (status %s)" % status)
    vulns = data.get("vulnerabilities", [])
    return [normalize(v["cve"]) for v in vulns[:limit]]


def _severity_from_cvss(score):
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _finding_for_item(item, keyword):
    score = item["cvss_score"]
    score_str = ("%.1f" % score) if score is not None else "N/A"
    version = "v%s" % item["cvss_version"] if item["cvss_version"] else "no CVSS data"
    return make_finding(
        module=NAME,
        target=keyword,
        severity=_severity_from_cvss(score),
        confidence="strong",
        title="CVE %s (CVSS %s)" % (item["id"], score_str),
        description="Summary: %s Published: %s. Severity reported by NVD: %s "
                    "(%s). References listed by NVD: %d."
                    % (item["description"], item["published"], item["severity"],
                       version, item["references"]),
        evidence="cve: %s | cvss: %s | published: %s"
                 % (item["id"], score_str, item["published"]),
        cwe=item["cwe"],
        remediation="Review the NVD entry and vendor advisories for %s; apply "
                    "available patches or documented mitigations." % item["id"],
    )


def run(target, ctx):
    """Search NVD for target keyword; one finding per CVE (cap 10).

    ctx may carry "limit" and "timeout". Network/rate-limit failures are
    handled gracefully with a single explanatory info finding.
    """
    ctx = ctx or {}
    cfg = getattr(ctx, "config", ctx) or {}
    if not isinstance(cfg, dict):
        cfg = {}
    try:
        limit = int(cfg.get("limit", _DEFAULT_LIMIT))
    except (TypeError, ValueError):
        limit = _DEFAULT_LIMIT
    limit = max(1, min(limit, _MAX_LIMIT))
    try:
        timeout = int(cfg.get("timeout", _DEFAULT_TIMEOUT))
    except (TypeError, ValueError):
        timeout = _DEFAULT_TIMEOUT
    timeout = max(1, timeout)

    try:
        items = search(target, limit, timeout)
    except Exception as exc:
        return [make_finding(
            module=NAME,
            target=target,
            severity="info",
            confidence="review",
            title="NVD lookup failed",
            description="The CVE search for %r could not complete: %s. This is "
                        "usually a network issue or NVD rate limiting; no CVEs "
                        "were returned, not a clean bill of health." % (target, exc),
            evidence="keyword: %s" % target,
            cwe=None,
            remediation="Wait a few minutes and retry, or request a free NVD "
                        "API key at https://nvd.nist.gov/developers/request-an-api-key.",
        )]
    except Exception as exc:
        return [make_finding(
            module=NAME,
            target=target,
            severity="info",
            confidence="review",
            title="NVD lookup failed",
            description="The CVE search for %r raised an unexpected error: %s."
                        % (target, exc),
            evidence="keyword: %s" % target,
            cwe=None,
            remediation="Retry the lookup; check network connectivity to services.nvd.nist.gov.",
        )]

    if not items:
        return [make_finding(
            module=NAME,
            target=target,
            severity="info",
            confidence="strong",
            title="No CVEs matched the keyword",
            description="NVD returned no CVEs for %r." % target,
            evidence="keyword: %s" % target,
            cwe=None,
            remediation="Try a broader keyword (e.g. just the product name).",
        )]
    return [_finding_for_item(item, target) for item in items]
