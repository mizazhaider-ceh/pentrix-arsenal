"""Hash algorithm identification module.

Identifies a hash string by matching it against a signature table of
regular expressions (length + character set + known prefixes), and
returns the plausible candidate algorithms for each hash.

Adapted from pentrix-hashid (identify / signature table).
"""

import os
import re

from arsenal.findings import make_finding

NAME = "hashid"
DESCRIPTION = "Identify the algorithm of one or more hash strings by format."
TARGET_KIND = "hash"
INTRUSIVE = False

_MAX_FILE_HASHES = 100

_WEAK_CANDIDATES = {
    "MD5", "MD4", "MD2", "NTLM", "LM", "SHA-1", "DES crypt",
    "descrypt", "MySQL 3.x (old_password)", "CRC32", "Adler-32",
}


def build_signatures():
    """Return the signature table as a list of dicts (pattern, candidates, note).

    Adapted from pentrix-hashid. Order matters: specific prefixed formats
    come before generic hex-length formats so they rank first.
    """
    return [
        {
            "pattern": re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$"),
            "candidates": ["bcrypt"],
            "note": "bcrypt modular crypt format: $2a$/$2b$/$2y$ + cost + 53-char salt/hash",
        },
        {
            "pattern": re.compile(r"^\$argon2(?:id|i|d)\$.*$"),
            "candidates": ["Argon2"],
            "note": "Argon2 password hash (PHC string format, $argon2i$/$argon2d$/$argon2id$)",
        },
        {
            "pattern": re.compile(r"^\$scrypt\$.*$"),
            "candidates": ["scrypt"],
            "note": "scrypt password hash (PHC string format, $scrypt$)",
        },
        {
            "pattern": re.compile(r"^\$7\$.*$"),
            "candidates": ["scrypt"],
            "note": "scrypt modular crypt format ($7$)",
        },
        {
            "pattern": re.compile(
                r"^\$6\$(?:rounds=\d+\$)?[./A-Za-z0-9]+\$[./A-Za-z0-9]{86}$"
            ),
            "candidates": ["SHA-512 crypt", "sha512crypt"],
            "note": "SHA-512 crypt ($6$): glibc/POSIX password hash, 86-char base64-ish payload",
        },
        {
            "pattern": re.compile(
                r"^\$5\$(?:rounds=\d+\$)?[./A-Za-z0-9]+\$[./A-Za-z0-9]{43}$"
            ),
            "candidates": ["SHA-256 crypt", "sha256crypt"],
            "note": "SHA-256 crypt ($5$): glibc/POSIX password hash, 43-char base64-ish payload",
        },
        {
            "pattern": re.compile(
                r"^\$1\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{22}$"
            ),
            "candidates": ["MD5 crypt", "md5crypt"],
            "note": "MD5 crypt ($1$): classic Unix password hash, 22-char base64-ish payload",
        },
        {
            "pattern": re.compile(r"^\$pbkdf2-sha(?:1|256|512)\$.*$"),
            "candidates": ["PBKDF2"],
            "note": "PBKDF2 password hash (PHC string format, $pbkdf2-sha...$)",
        },
        {
            "pattern": re.compile(r"^\*[0-9A-F]{40}$"),
            "candidates": ["MySQL 4.1+", "MySQL5"],
            "note": "MySQL 4.1+ native password: '*' followed by 40 uppercase hex chars (SHA1(SHA1(password)))",
        },
        {
            "pattern": re.compile(r"^\$SHA\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$"),
            "candidates": ["SHA-1 crypt (Cisco)"],
            "note": "SHA-1 crypt ($SHA$): Cisco-IOS style password hash",
        },
        {
            "pattern": re.compile(r"^[a-f0-9]{32}$"),
            "candidates": ["MD5", "MD4", "MD2", "NTLM", "LM", "RIPEMD-128", "Haval-128"],
            "note": "32 lowercase hex chars: MD5, NTLM, MD4 and others share this exact format",
        },
        {
            "pattern": re.compile(r"^[A-F0-9]{32}$"),
            "candidates": ["MD5", "MD4", "NTLM", "LM"],
            "note": "32 uppercase hex chars: MD5, NTLM and others (often NTLM stored uppercase)",
        },
        {
            "pattern": re.compile(
                r"^(?=.*[a-f])(?=.*[A-F])[a-fA-F0-9]{32}$"
            ),
            "candidates": ["MD5", "MD4", "NTLM"],
            "note": "32 mixed-case hex chars: MD5, NTLM and others share this format",
        },
        {
            "pattern": re.compile(r"^[a-f0-9]{40}$"),
            "candidates": ["SHA-1", "RIPEMD-160", "Haval-160"],
            "note": "40 lowercase hex chars: SHA-1, RIPEMD-160 and others share this format",
        },
        {
            "pattern": re.compile(
                r"^(?=.*[a-f])(?=.*[A-F])[a-fA-F0-9]{40}$"
            ),
            "candidates": ["SHA-1"],
            "note": "40 mixed-case hex chars: SHA-1 and others share this format",
        },
        {
            "pattern": re.compile(r"^[a-fA-F0-9]{56}$"),
            "candidates": ["SHA-224", "Haval-224"],
            "note": "56 hex chars: SHA-224 (SHA-2 family), Haval-224",
        },
        {
            "pattern": re.compile(r"^[a-fA-F0-9]{64}$"),
            "candidates": ["SHA-256", "RIPEMD-256", "Haval-256", "GOST R 34.11-94"],
            "note": "64 hex chars: SHA-256 (SHA-2 family) and others share this format",
        },
        {
            "pattern": re.compile(r"^[a-fA-F0-9]{96}$"),
            "candidates": ["SHA-384"],
            "note": "96 hex chars: SHA-384 (SHA-2 family)",
        },
        {
            "pattern": re.compile(r"^[a-fA-F0-9]{128}$"),
            "candidates": ["SHA-512", "Whirlpool"],
            "note": "128 hex chars: SHA-512 (SHA-2 family), Whirlpool",
        },
        {
            "pattern": re.compile(r"^[a-fA-F0-9]{8}$"),
            "candidates": ["CRC32", "Adler-32"],
            "note": "8 hex chars: likely CRC32 or Adler-32 checksum",
        },
        {
            "pattern": re.compile(r"^[a-fA-F0-9]{16}$"),
            "candidates": ["MySQL 3.x (old_password)", "DES crypt (truncated?)", "half-MD5"],
            "note": "16 hex chars: MySQL 3.x old_password, or a truncated hash",
        },
        {
            "pattern": re.compile(r"^[./A-Za-z0-9]{13}$"),
            "candidates": ["DES crypt", "descrypt"],
            "note": "13-char crypt-base64: traditional DES crypt (2-char salt + 11-char hash)",
        },
    ]


def identify(hash_string):
    """Match hash_string against the signature table.

    Returns a list of dicts with keys 'candidates' and 'note',
    in ranking order. Empty list means no format matched.
    Adapted from pentrix-hashid.
    """
    matches = []
    for sig in build_signatures():
        if sig["pattern"].match(hash_string):
            matches.append(
                {"candidates": list(sig["candidates"]), "note": sig["note"]}
            )
    return matches


def _load_hashes(target):
    """Resolve target to a list of hash strings.

    If target is a path to a readable file, hashes are read line by line
    (capped at _MAX_FILE_HASHES). Otherwise target itself is the hash.
    """
    if os.path.isfile(target):
        hashes = []
        with open(target, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                hashes.append(line)
                if len(hashes) >= _MAX_FILE_HASHES:
                    break
        return hashes
    return [target.strip()]


def _finding_for_hash(h):
    matches = identify(h)
    candidates = [c for m in matches for c in m["candidates"]]
    if matches:
        title = "Hash identified: %s" % ", ".join(candidates)
        description = (
            "The hash format matches %d known signature(s). "
            "Identification is format-based only: several algorithms can "
            "share the same length and character set, so every plausible "
            "candidate is listed. %s"
            % (len(matches), " ".join(m["note"] for m in matches))
        )
        confidence = "high" if len(matches) == 1 else "medium"
        weak = [c for c in candidates if c in _WEAK_CANDIDATES]
        cwe = "CWE-327" if weak else None
        remediation = (
            "Weak algorithm identified (%s): migrate stored values to a "
            "memory-hard password hash such as Argon2id or bcrypt, and treat "
            "any data protected by it as potentially compromised."
            % ", ".join(weak) if weak else
            "Use the identified format to select the right analysis method "
            "(e.g. the correct hashcat mode or dictionary ruleset) before "
            "further testing."
        )
    else:
        title = "Hash format not recognized"
        description = (
            "The input did not match any known hash signature. It may be a "
            "custom or composite format, encoded data, or not a hash at all."
        )
        confidence = "low"
        cwe = None
        remediation = (
            "Inspect the source context of the value to determine what it "
            "is before attempting to crack or compare it."
        )
    return make_finding(
        module=NAME,
        target=h,
        severity="info",
        confidence=confidence,
        title=title,
        description=description,
        evidence="hash: %s" % (h if len(h) <= 80 else h[:77] + "..."),
        cwe=cwe,
        remediation=remediation,
    )


def run(target, ctx):
    """Identify the algorithm of the hash(es) in target.

    target: a hash string, or a path to a file with one hash per line
    (capped at 100). ctx: unused, kept for the module contract.
    Returns a list of info findings, one per hash.
    """
    findings = []
    try:
        hashes = _load_hashes(target)
    except OSError as exc:
        return [make_finding(
            module=NAME,
            target=target,
            severity="info",
            confidence="low",
            title="Could not read hash input",
            description="The target was treated as a file path but could not "
                        "be read: %s" % exc,
            evidence="target: %s" % target,
            cwe=None,
            remediation="Pass a hash string directly, or a readable file with "
                        "one hash per line.",
        )]
    if not hashes:
        return [make_finding(
            module=NAME,
            target=target,
            severity="info",
            confidence="low",
            title="No hashes supplied",
            description="The input contained no hash strings to identify.",
            evidence="target: %s" % target,
            cwe=None,
            remediation="Provide a hash string or a non-empty file.",
        )]
    for h in hashes:
        try:
            findings.append(_finding_for_hash(h))
        except Exception:
            continue
    return findings
