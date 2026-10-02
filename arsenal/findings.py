"""Finding data model for PENTRIX ARSENAL.

A finding is a plain dict so it serialises to JSON without conversion.
Use make_finding() to build one and validate() to check one.

Contract:
    make_finding(module, target, severity, title, description,
                 evidence="", confidence="review", cwe="",
                 remediation="") -> dict
    validate(finding) -> bool

Confidence vocabulary (canonical):
    proven  - exploitability was demonstrated automatically
    strong  - strong evidence, manual confirmation still wise
    review  - needs manual review

Every finding also carries:
    cvss         - CVSS 3.1 base score (float) suggested for the finding,
                   computed via arsenal.cvss from an explicit vector or a
                   heuristic vector matched on the module/title.
    cvss_vector  - the metric vector the score was computed from (dict).
    dedup_key    - stable sha256 key (module + target host + normalized
                   title) for cross-run deduplication.
"""

import hashlib
import urllib.parse
from datetime import datetime, timezone

from arsenal import cvss as cvss_lib

SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("proven", "strong", "review")

# Forgiving mapping for out-of-vocabulary confidence values so findings
# built against older drafts still land on the canonical scale.
_CONFIDENCE_ALIASES = {
    "confirmed": "proven",
    "likely": "strong",
    "high": "strong",
    "medium": "review",
    "low": "review",
}

_REQUIRED = ("module", "target", "severity", "title", "description")


def make_finding(module, target, severity, title, description,
                 evidence="", confidence="review", cwe="", remediation="",
                 cvss=None, cvss_vector=None):
    """Build a normalized finding dict.

    severity and confidence are lowercased; unknown severities fall back
    to "info" and unknown confidences are mapped through
    _CONFIDENCE_ALIASES, falling back to "review", so the result always
    passes validate().

    cvss: explicit CVSS 3.1 base score (float). When None, the score is
    computed from cvss_vector when given, else from a heuristic vector
    suggested by arsenal.cvss for the module/title. Pass cvss=False to
    skip scoring entirely.
    """
    severity = str(severity or "info").lower()
    if severity not in SEVERITIES:
        severity = "info"
    confidence = str(confidence or "review").lower()
    if confidence not in CONFIDENCES:
        confidence = _CONFIDENCE_ALIASES.get(confidence, "review")
    score, vector = _resolve_cvss(module, title, cvss, cvss_vector)
    finding = {
        "module": module,
        "target": target,
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence,
        "confidence": confidence,
        "cwe": cwe,
        "remediation": remediation,
        "cvss": score,
        "cvss_vector": vector,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    finding["dedup_key"] = dedup_key(finding)
    return finding


def _resolve_cvss(module, title, score, vector):
    """Return (score: float|None, vector: dict|None) for a finding."""
    if score is False:
        return None, None
    if score is not None:
        try:
            return round(float(score), 1), (dict(vector) if vector else None)
        except (TypeError, ValueError):
            return None, (dict(vector) if vector else None)
    if vector:
        try:
            return cvss_lib.cvss31(vector), dict(vector)
        except (ValueError, TypeError, KeyError):
            return None, None
    try:
        suggested = cvss_lib.suggest_vector(
            {"module": module or "", "title": title or ""})
        return cvss_lib.cvss31(suggested), suggested
    except Exception:
        return None, None


def _target_host(target):
    text = str(target or "").strip()
    if "://" in text:
        try:
            host = urllib.parse.urlsplit(text).hostname
            if host:
                return host.lower()
        except Exception:
            pass
    return text.lower().split("/")[0].split(":")[0].strip()


def dedup_key(finding):
    """Stable deduplication key for a finding dict.

    sha256 hex of "module | target host | normalized title". Two runs of
    the same module against the same target produce the same key even if
    the evidence text or timestamps differ; findings that differ only by
    parameter name or port in the title intentionally get different keys.
    """
    try:
        module = str(finding.get("module", "")).lower().strip()
        host = _target_host(finding.get("target", ""))
        title = " ".join(str(finding.get("title", "")).lower().split())
        raw = "%s|%s|%s" % (module, host, title)
    except Exception:
        raw = repr(finding)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def validate(f):
    """Return True when f looks like a well-formed finding, else False."""
    try:
        if not isinstance(f, dict):
            return False
        for key in _REQUIRED:
            if not f.get(key):
                return False
        if str(f.get("severity", "")).lower() not in SEVERITIES:
            return False
        if str(f.get("confidence", "review")).lower() not in CONFIDENCES:
            return False
        return True
    except Exception:
        return False
