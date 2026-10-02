"""secrets: scan a local file or directory for exposed secrets.

TARGET_KIND "path". Walks the target path, skips binary files, and scans
text line by line against detection rules for API keys, tokens and private
key blocks. Findings are reported per match with the evidence redacted.

File iteration and scanning logic adapted from pentrix-secrets
(~/workspace/pentrix-toolkit/pentrix-secrets/secrets.py).

Module contract: NAME, DESCRIPTION, TARGET_KIND, INTRUSIVE,
run(target, ctx) -> list[dict]. ctx provides .config, .log, .workspace,
.scope, .safe_mode and .allow_intrusive. Findings carry the keys module,
target, severity, confidence, title, description, evidence, cwe and
remediation.
"""

import os
import re
from pathlib import Path

from arsenal.findings import make_finding

NAME = "secrets"
DESCRIPTION = (
    "Scans a local file or directory for exposed secrets (API keys, tokens, "
    "private keys) using rules adapted from pentrix-secrets, with redacted "
    "evidence."
)
TARGET_KIND = "path"
INTRUSIVE = False

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_MATCHES_PER_FILE = 25

DEFAULT_EXCLUDES = [".git", "node_modules", "__pycache__", ".venv"]

# Detection rules: (rule name, compiled pattern, severity, CWE).
# Rule patterns adapted from pentrix-secrets.
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


# ---------------------------------------------------------------------------
# Helpers adapted from pentrix-secrets
# ---------------------------------------------------------------------------
def _log(ctx, message):
    log = getattr(ctx, "log", None)
    if callable(log):
        try:
            log(message)
        except Exception:
            pass


def _make_finding(**fields):
    try:
        return make_finding(**fields)
    except Exception:
        return dict(fields)


def _redact(text):
    """Show only the first 4 and last 2 characters of a matched secret."""
    text = text.strip()
    if len(text) <= 8:
        return "***REDACTED***"
    return "%s...%s" % (text[:4], text[-2:])


def _is_binary(path):
    try:
        with open(path, "rb") as handle:
            return b"\x00" in handle.read(8192)
    except OSError:
        return True


def _iter_target_files(target, recursive, excludes):
    """Yield text files under target, honouring recursion and exclusions."""
    if target.is_file():
        if not _is_binary(target):
            yield target
        return
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if not any(e in d for e in excludes)]
        for name in files:
            path = Path(root) / name
            if any(e in str(path) for e in excludes):
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            if not _is_binary(path):
                yield path
        if not recursive:
            break


def _scan_file(path):
    """Scan one file line by line. Returns a list of match dicts."""
    matches = []
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return matches
    except OSError:
        return matches
    try:
        with open(path, "r", encoding="utf-8", errors="strict") as handle:
            lines = handle.readlines()
    except (OSError, UnicodeDecodeError):
        return matches
    for lineno, line in enumerate(lines, start=1):
        for rule_name, pattern, severity, cwe in RULES:
            for match in pattern.finditer(line):
                snippet = match.group(0).strip()
                matches.append(
                    {
                        "rule": rule_name,
                        "severity": severity,
                        "cwe": cwe,
                        "line": lineno,
                        "snippet": snippet,
                    }
                )
                if len(matches) >= MAX_MATCHES_PER_FILE:
                    return matches
    return matches


def _build_finding(target, path, match):
    rule = match["rule"]
    title = "%s found in %s" % (rule, path.name)
    description = (
        "A value matching the '%s' pattern was found in the local file %s "
        "(line %d). Secrets stored in files can leak through backups, "
        "shared archives or version control, and must be treated as exposed."
        % (rule, path, match["line"])
    )
    evidence = "%s:%d [%s] %s" % (
        path,
        match["line"],
        rule,
        _redact(match["snippet"]),
    )
    remediation = (
        "Rotate or revoke the exposed credential immediately and check for "
        "misuse. Move the secret out of the file into a proper secret store "
        "or environment variable, and verify it was never committed to "
        "version control history."
    )
    return _make_finding(
        module=NAME,
        target=str(target),
        severity=match["severity"],
        confidence="strong",
        title=title,
        description=description,
        evidence=evidence,
        cwe=match["cwe"],
        remediation=remediation,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def _run(target, ctx):
    findings = []
    path = Path(str(target)).expanduser()
    if not path.exists():
        _log(ctx, "secrets: path not found: %s" % target)
        return findings
    count = 0
    for file_path in _iter_target_files(path, True, DEFAULT_EXCLUDES):
        count += 1
        try:
            matches = _scan_file(file_path)
        except Exception as exc:
            _log(ctx, "secrets: could not scan %s: %s" % (file_path, exc))
            continue
        for match in matches:
            findings.append(_build_finding(target, file_path, match))
    _log(ctx, "secrets: scanned %d file(s) under %s" % (count, target))
    return findings


def run(target, ctx):
    """Scan a local file or directory for exposed secrets."""
    try:
        return _run(target, ctx)
    except Exception as exc:
        _log(ctx, "secrets: unexpected error: %s" % exc)
        return []
