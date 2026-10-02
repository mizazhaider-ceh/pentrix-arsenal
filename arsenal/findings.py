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
"""

from datetime import datetime, timezone

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
                 evidence="", confidence="review", cwe="", remediation=""):
    """Build a normalized finding dict.

    severity and confidence are lowercased; unknown severities fall back
    to "info" and unknown confidences are mapped through
    _CONFIDENCE_ALIASES, falling back to "review", so the result always
    passes validate().
    """
    severity = str(severity or "info").lower()
    if severity not in SEVERITIES:
        severity = "info"
    confidence = str(confidence or "review").lower()
    if confidence not in CONFIDENCES:
        confidence = _CONFIDENCE_ALIASES.get(confidence, "review")
    return {
        "module": module,
        "target": target,
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence,
        "confidence": confidence,
        "cwe": cwe,
        "remediation": remediation,
        "ts": datetime.now(timezone.utc).isoformat(),
    }


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
