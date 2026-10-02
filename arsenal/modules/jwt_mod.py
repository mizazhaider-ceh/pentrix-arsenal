"""PENTRIX ARSENAL module: JSON Web Token weakness analysis.

Adapted from pentrix-jwt: reuses parse_token() and run_checks() (alg=none,
weak/legacy algorithm, weak HMAC secret, exp claim checks) and adds header
checks for jku/x5u pointing at external URLs and suspicious kid values.

TARGET_KIND is "token": the target is normally a compact JWT string. If the
target looks like a URL instead, the page is fetched and JWT-looking strings
are extracted from the body (including Authorization: Bearer patterns) and
each candidate token is analyzed. One finding per weakness.

Non-intrusive: only decodes and analyzes; the weak-secret check tries a
small built-in secret list locally and never contacts the target.
"""

import base64
import hashlib
import hmac
import json
import re
import time
import urllib.parse
from arsenal.modules.base import BaseModule


NAME = "jwt"
DESCRIPTION = (
    "Decodes JSON Web Tokens and reports common weaknesses: alg=none, weak "
    "HMAC secrets, weak algorithms, exp claim problems, untrusted jku/x5u "
    "URLs, and suspicious kid values."
)
TARGET_KIND = "token"
INTRUSIVE = False

TIMEOUT = 10
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_TOKENS_PER_URL = 5

COMMON_SECRETS = [
    "secret", "password", "123456", "12345678", "123456789", "1234567890",
    "jwt", "jwtsecret", "jwts3cr3t", "token", "admin", "administrator",
    "your-256-bit-secret", "your-secret-key", "mysecret", "my-secret",
    "supersecret", "secretkey", "secret123", "password123", "passw0rd",
    "changeme", "changeit", "letmein", "welcome", "qwerty", "abc123",
    "test", "test123", "key", "key123", "development", "dev",
    "1q2w3e", "iloveyou", "dragon", "monkey", "football", "master",
]

HMAC_ALGS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

EXP_FAR_FUTURE_SECONDS = 10 * 365 * 24 * 60 * 60

JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*(?![A-Za-z0-9_-])"
)
BEARER_RE = re.compile(
    r"Bearer\s+([A-Za-z0-9_.\-~+/]+=*)", re.IGNORECASE
)

KID_SAFE_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-."
)


# ---------------------------------------------------------------------------
# Shared module helpers, bound from arsenal.modules.base (replaces the old
# per-module copies). All HTTP goes through arsenal.http with ctx, so
# stealth sleeps, UA rotation and proxy settings apply to module traffic.
# ---------------------------------------------------------------------------
_mod = BaseModule(NAME, TIMEOUT)
_timeout = _mod.timeout
_log = _mod.log
_is_http_url = _mod.is_http_url
_host_of = _mod.host_of
_in_scope = _mod.in_scope
_get = _mod.get
_finding = _mod.finding

# ---------------------------------------------------------------------------
# Token handling (adapted from pentrix-jwt)
# ---------------------------------------------------------------------------

def b64url_decode(data):
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def split_token(token):
    token = token.strip().strip("\"'")
    if not token:
        raise ValueError("empty token")
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(
            "a JWT must have exactly 3 dot-separated parts, got %d" % len(parts)
        )
    if not parts[0] or not parts[1]:
        raise ValueError("header or payload part is empty")
    return parts[0], parts[1], parts[2]


def decode_segment(segment, name):
    try:
        raw = b64url_decode(segment)
    except Exception:
        raise ValueError("%s is not valid base64url" % name)
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        raise ValueError("%s is not valid JSON" % name)


def parse_token(token):
    """Parse a compact JWT. Returns (header, payload, signing_input, signature)."""
    header_b64, payload_b64, signature_b64 = split_token(token)
    header = decode_segment(header_b64, "header")
    payload = decode_segment(payload_b64, "payload")
    if not isinstance(header, dict):
        raise ValueError("header must be a JSON object")
    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object")
    signing_input = (header_b64 + "." + payload_b64).encode("ascii")
    try:
        signature = b64url_decode(signature_b64) if signature_b64 else b""
    except Exception:
        raise ValueError("signature is not valid base64url")
    return header, payload, signing_input, signature


# ---------------------------------------------------------------------------
# Weakness checks (adapted from pentrix-jwt)
# ---------------------------------------------------------------------------

def check_alg_none(header, signature):
    alg = header.get("alg", "")
    if alg == "none":
        detail = "alg=none: no signature is required"
        if signature:
            detail += " (a signature is present but servers often ignore it)"
        return ("FAIL", "alg=none accepted", detail)
    return ("PASS", "alg=none accepted",
            "header alg is %r, a signature is expected" % alg)


def check_alg_strength(header):
    alg = header.get("alg", "")
    if not alg:
        return ("WARN", "weak/legacy algorithm",
                "no alg field in header; verifier behaviour is undefined")
    if alg == "none":
        return ("WARN", "weak/legacy algorithm",
                "alg=none is never acceptable (see alg=none check above)")
    if alg in HMAC_ALGS:
        return ("PASS", "weak/legacy algorithm",
                "%s is fine, as long as the secret is strong" % alg)
    if alg in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512",
               "PS256", "PS384", "PS512", "EdDSA"):
        return ("PASS", "weak/legacy algorithm",
                "%s is asymmetric; key confusion is the main risk" % alg)
    return ("WARN", "weak/legacy algorithm",
            "%r is unknown or legacy; verify it is intentional" % alg)


def check_weak_secret(header, signing_input, signature):
    alg = header.get("alg", "")
    if alg == "none":
        return ("FAIL", "weak HMAC secret",
                "alg=none: there is no secret to crack, anyone can forge tokens")
    if alg not in HMAC_ALGS:
        return ("PASS", "weak HMAC secret",
                "alg is %r, not HMAC; this check does not apply" % alg)
    if not signature:
        return ("WARN", "weak HMAC secret",
                "alg is %s but the signature part is empty" % alg)
    digest = HMAC_ALGS[alg]
    for secret in COMMON_SECRETS:
        expected = hmac.new(secret.encode("utf-8"), signing_input,
                            digest).digest()
        if hmac.compare_digest(expected, signature):
            return ("FAIL", "weak HMAC secret",
                    "signature verifies with common secret %r" % secret)
    return ("PASS", "weak HMAC secret",
            "signature did not match any of %d common secrets"
            % len(COMMON_SECRETS))


def check_exp_missing(payload):
    if "exp" not in payload:
        return ("WARN", "missing exp claim",
                "no exp: the token never expires unless revoked")
    return ("PASS", "missing exp claim", "exp claim is present")


def check_exp_expired(payload):
    if "exp" not in payload:
        return ("PASS", "expired token", "no exp claim to evaluate")
    exp = payload["exp"]
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        return ("WARN", "expired token",
                "exp is %r, not a number; verifiers may reject it" % exp)
    now = time.time()
    if exp <= now:
        return ("FAIL", "expired token",
                "exp is in the past (expired %d seconds ago)" % int(now - exp))
    if exp - now > EXP_FAR_FUTURE_SECONDS:
        return ("WARN", "expired token",
                "exp is more than 10 years out; effectively never expires")
    return ("PASS", "expired token", "exp is in the future")


def check_exp_before_iat(payload):
    exp = payload.get("exp")
    iat = payload.get("iat")
    if isinstance(exp, (int, float)) and isinstance(iat, (int, float)) \
            and not isinstance(exp, bool) and not isinstance(iat, bool):
        if exp < iat:
            return ("WARN", "exp before iat",
                    "exp predates iat; the token is expired by construction")
    return ("PASS", "exp before iat", "exp/iat ordering looks sane")


def run_checks(header, payload, signing_input, signature):
    """Run every check, return a list of (status, name, detail)."""
    return [
        check_alg_none(header, signature),
        check_alg_strength(header),
        check_weak_secret(header, signing_input, signature),
        check_exp_missing(payload),
        check_exp_expired(payload),
        check_exp_before_iat(payload),
    ]


# ---------------------------------------------------------------------------
# Extra header checks: jku / x5u / kid
# ---------------------------------------------------------------------------

def check_jku_x5u(header):
    """FAIL when jku/x5u point at an external URL."""
    results = []
    for key in ("jku", "x5u"):
        value = header.get(key)
        if not value or not isinstance(value, str):
            continue
        parts = urllib.parse.urlsplit(value)
        if parts.scheme in ("http", "https") and parts.netloc:
            results.append((
                "FAIL",
                "untrusted %s URL" % key,
                "%s points to external URL %r: if the verifier fetches keys "
                "from it, an attacker-controlled URL enables key confusion "
                "and SSRF." % (key, value),
            ))
        else:
            results.append((
                "PASS",
                "untrusted %s URL" % key,
                "%s is %r, not an external URL" % (key, value),
            ))
    return results


def check_kid(header):
    """WARN when the kid value looks injectable."""
    kid = header.get("kid")
    if kid is None:
        return [("PASS", "suspicious kid value", "no kid in header")]
    text = str(kid)
    if (".." in text or "\\" in text
            or text.startswith(("http://", "https://", "/"))
            or any(ch not in KID_SAFE_CHARS for ch in text)):
        return [(
            "WARN",
            "suspicious kid value",
            "kid=%r looks injectable: if the verifier maps kid to a file "
            "path or key identifier, path traversal or key confusion may "
            "be possible." % text,
        )]
    return [("PASS", "suspicious kid value",
             "kid=%r looks like a plain identifier" % text)]


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

CHECK_SEVERITY = {
    "alg=none accepted": ("high", "CWE-327"),
    "weak HMAC secret": ("high", "CWE-798"),
    "weak/legacy algorithm": ("medium", "CWE-327"),
    "missing exp claim": ("low", "CWE-613"),
    "expired token": ("medium", "CWE-613"),
    "exp before iat": ("low", "CWE-613"),
    "untrusted jku URL": ("high", "CWE-345"),
    "untrusted x5u URL": ("high", "CWE-345"),
    "suspicious kid value": ("medium", "CWE-74"),
}


def _remediation_for(name):
    advice = {
        "alg=none accepted": "Reject alg=none on the server; whitelist expected algorithms.",
        "weak HMAC secret": "Use a long, random HMAC secret stored server-side; rotate it.",
        "weak/legacy algorithm": "Use a modern algorithm (HS256 with strong secret, or RS256/ES256).",
        "missing exp claim": "Add a short-lived exp claim to every token.",
        "expired token": "Do not accept expired tokens; issue fresh ones.",
        "exp before iat": "Fix token issuance so exp is after iat.",
        "untrusted jku URL": "Never fetch keys from a token-supplied URL; pin trusted key sources.",
        "untrusted x5u URL": "Never fetch certificates from a token-supplied URL; pin trusted sources.",
        "suspicious kid value": "Treat kid as untrusted input; map it through a strict allow-list.",
    }
    return advice.get(name, "Review the token handling for this weakness.")


# ---------------------------------------------------------------------------
# Token extraction from URL targets
# ---------------------------------------------------------------------------

def extract_tokens_from_url(url, ctx):
    resp = _get(url, ctx)
    if resp is None:
        return []
    _status, headers, body, _final = resp
    if len(body) > MAX_BODY_BYTES:
        body = body[:MAX_BODY_BYTES]
    text = body.decode("utf-8", errors="replace")
    found = []
    for match in JWT_RE.finditer(text):
        token = match.group(0)
        if token not in found:
            found.append(token)
    for match in BEARER_RE.finditer(text):
        candidate = match.group(1).strip().strip("\"'")
        if candidate.count(".") == 2 and candidate not in found:
            found.append(candidate)
    return found[:MAX_TOKENS_PER_URL]


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(target, ctx):
    """Analyze the target token (or tokens extracted from a target URL)."""
    try:
        return _run(target, ctx)
    except Exception as exc:
        _log(ctx, "warning", "%s failed on %s: %s" % (NAME, target, exc))
        return []


def _run(target, ctx):
    if _is_http_url(target):
        if not _in_scope(target, ctx):
            _log(ctx, "warning", "%s: target out of scope: %s" % (NAME, target))
            return []
        tokens = extract_tokens_from_url(target, ctx)
        if not tokens:
            _log(ctx, "debug", "%s: no JWT-looking strings found at %s"
                 % (NAME, target))
            return []
    else:
        tokens = [target]
    out = []
    for token in tokens:
        out.extend(_analyze_token(token, target, ctx))
    return out


def _analyze_token(token, target, ctx):
    try:
        header, payload, signing_input, signature = parse_token(token)
    except ValueError as exc:
        _log(ctx, "debug", "%s: not a parseable JWT: %s" % (NAME, exc))
        return []
    checks = run_checks(header, payload, signing_input, signature)
    checks.extend(check_jku_x5u(header))
    checks.extend(check_kid(header))
    evidence_head = "header: %s\npayload claims: %s" % (
        json.dumps(header, sort_keys=True)[:400],
        ", ".join(sorted(payload.keys())) if payload else "(none)",
    )
    out = []
    for status, name, detail in checks:
        if status == "PASS":
            continue
        severity, cwe = CHECK_SEVERITY.get(name, ("medium", "CWE-327"))
        confidence = "strong" if status == "FAIL" else "review"
        short_token = token[:24] + "..." if len(token) > 27 else token
        out.append(_finding(
            target=target,
            severity=severity,
            confidence=confidence,
            title="JWT weakness: %s" % name,
            description="%s (token %s)" % (detail, short_token),
            evidence="%s\ncheck: %s\n%s" % (evidence_head, name, detail),
            cwe=cwe,
            remediation=_remediation_for(name),
        ))
    return out
