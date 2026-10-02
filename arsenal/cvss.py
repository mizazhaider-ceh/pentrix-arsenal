"""CVSS 3.1 base score calculator and vector suggester for PENTRIX ARSENAL.

Implements the official CVSS v3.1 base score equations (FIRST.org spec):
exploitability, impact sub-score, scope handling and the RoundUp rule.

Public API:
    cvss31(vector: dict) -> float
        vector keys: AV, AC, PR, UI, S, C, I, A with the standard
        abbreviated values, e.g. {"AV": "N", "AC": "L", "PR": "N",
        "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}.
    suggest_vector(finding: dict) -> dict
        Heuristic base vector derived from the finding's module name.
    label(score) -> str | None
        None, Low, Medium, High or Critical per the CVSS qualitative scale.
"""

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}

_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def _roundup(value: float) -> float:
    """CVSS RoundUp: smallest number with one decimal place >= value."""
    if value <= 0:
        return 0.0
    return math.ceil(value * 10) / 10.0


def cvss31(vector: dict) -> float:
    """Compute the CVSS 3.1 base score (0.0 to 10.0) for a metric vector.

    Raises ValueError when a required metric is missing or has an
    unknown value. Accepts lowercase keys/values as well.
    """
    v = {}
    for key, val in (vector or {}).items():
        v[str(key).upper()] = str(val).upper()

    missing = [k for k in _REQUIRED if k not in v]
    if missing:
        raise ValueError("Missing CVSS metrics: %s" % ", ".join(missing))

    try:
        av = _AV[v["AV"]]
        ac = _AC[v["AC"]]
        ui = _UI[v["UI"]]
        c = _CIA[v["C"]]
        i = _CIA[v["I"]]
        a = _CIA[v["A"]]
    except KeyError as exc:
        raise ValueError("Unknown CVSS metric value: %s" % exc)

    scope_changed = v["S"] == "C"
    if v["S"] not in ("U", "C"):
        raise ValueError("Unknown CVSS metric value: S=%s" % v["S"])
    pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
    try:
        pr = pr_table[v["PR"]]
    except KeyError:
        raise ValueError("Unknown CVSS metric value: PR=%s" % v["PR"])

    exploitability = 8.22 * av * ac * pr * ui
    isc_base = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)

    if not scope_changed:
        impact = 6.42 * isc_base
        score = min(impact + exploitability, 10.0)
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * pow(isc_base - 0.029, 15)
        if impact <= 0:
            return 0.0
        score = min(1.08 * (impact + exploitability), 10.0)

    return _roundup(score)


# Heuristic base vectors keyed by module-name fragment. Values are sane
# defaults for triage, not authoritative ratings; analysts should adjust.
_SUGGESTIONS = [
    ("xss", {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"}),
    ("sqli", {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}),
    ("sql_injection", {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}),
    ("ssrf", {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "L", "A": "N"}),
    ("rce", {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}),
    ("lfi", {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"}),
    ("xxe", {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "L", "A": "N"}),
    ("idor", {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "L", "A": "N"}),
    ("auth_bypass", {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"}),
    ("default_cred", {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}),
    ("csrf", {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "N", "I": "L", "A": "N"}),
    ("open_redirect", {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"}),
    ("cors", {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"}),
    ("clickjacking", {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "N", "I": "L", "A": "N"}),
    ("jwt", {"AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "H", "A": "N"}),
    ("takeover", {"AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "C", "C": "L", "I": "L", "A": "N"}),
    ("git_exposure", {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"}),
    ("env_exposure", {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"}),
    ("info_disclosure", {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"}),
    ("secret", {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"}),
    ("missing_header", {"AV": "N", "AC": "H", "PR": "N", "UI": "R", "S": "U", "C": "N", "I": "L", "A": "N"}),
    ("verbose_error", {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"}),
    ("rate_limit", {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "L", "A": "L"}),
]

_FALLBACK = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"}


def suggest_vector(finding: dict) -> dict:
    """Return a heuristic CVSS 3.1 base vector for a finding dict.

    Matches on the finding's "module" (and title as a fallback) against
    known vulnerability classes. Returns a generic network vector when
    nothing matches. Never raises on missing data.
    """
    text = ""
    try:
        text = "%s %s" % (finding.get("module", ""), finding.get("title", ""))
    except Exception:
        pass
    text = text.lower()
    for fragment, vector in _SUGGESTIONS:
        if fragment in text:
            return dict(vector)
    return dict(_FALLBACK)


def label(score) -> str | None:
    """Qualitative CVSS 3.1 severity label for a numeric score."""
    if score is None:
        return None
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s <= 0.0:
        return None
    if s < 4.0:
        return "Low"
    if s < 7.0:
        return "Medium"
    if s < 9.0:
        return "High"
    return "Critical"
