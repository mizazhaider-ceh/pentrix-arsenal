"""Shared secret-detection rule table for PENTRIX ARSENAL.

One canonical RULES table used by secrets_mod (local files), jssecrets_mod
(JS bundles) and jsintel_mod (JS endpoint responses). Rule patterns were
adapted from pentrix-secrets; the JWT rule covers token literals common in
client-side bundles. Keep new patterns here, not in the modules.

Each rule is (name, compiled_pattern, severity, CWE).
"""

import re

RULES = [
    (
        "AWS Access Key ID",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "high",
        "CWE-798",
    ),
    (
        "AWS Secret Key Assignment",
        re.compile(
            r"(?i)\baws[_-]?secret[_-]?access[_-]?key\b\s*[:=]\s*"
            r"['\"]?([A-Za-z0-9/+=]{30,})['\"]?"
        ),
        "high",
        "CWE-798",
    ),
    (
        "Private Key Block",
        re.compile(r"-----BEGIN (?:[A-Z ]*)PRIVATE KEY-----"),
        "high",
        "CWE-798",
    ),
    (
        "GitHub Token",
        re.compile(
            r"\b(ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|"
            r"github_pat_[A-Za-z0-9_]{20,})\b"
        ),
        "medium",
        "CWE-200",
    ),
    (
        "GitLab Token",
        re.compile(r"\bglpat-[A-Za-z0-9_\-]{16,}\b"),
        "medium",
        "CWE-200",
    ),
    (
        "Slack Token",
        re.compile(r"\bxox[bap]-[A-Za-z0-9-]{10,}\b"),
        "medium",
        "CWE-200",
    ),
    (
        "Google API Key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "medium",
        "CWE-200",
    ),
    (
        "Stripe Secret Key",
        re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b"),
        "medium",
        "CWE-798",
    ),
    (
        "JWT Token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        "medium",
        "CWE-200",
    ),
    (
        "Generic API Key Assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|apikey|api[_-]?secret|secret)\b\s*[:=]\s*"
            r"['\"][^'\"]{4,}['\"]"
        ),
        "medium",
        "CWE-798",
    ),
]


def redact(text):
    """Mask a matched secret, keeping only a hint of its shape."""
    text = (text or "").strip()
    if len(text) <= 8:
        return "***REDACTED***"
    return "%s...%s" % (text[:4], text[-2:])


def scan_text(content, max_matches=25):
    """Scan text line by line against RULES.

    Returns a list of {"rule", "severity", "cwe", "line", "snippet"} dicts,
    capped at max_matches. Pure function: no network, no ctx needed.
    """
    matches = []
    for lineno, line in enumerate(str(content or "").splitlines(), start=1):
        for rule_name, pattern, severity, cwe in RULES:
            for match in pattern.finditer(line):
                matches.append({
                    "rule": rule_name,
                    "severity": severity,
                    "cwe": cwe,
                    "line": lineno,
                    "snippet": match.group(0).strip(),
                })
                if len(matches) >= max_matches:
                    return matches
    return matches
