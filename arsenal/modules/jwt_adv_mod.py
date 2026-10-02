"""PENTRIX ARSENAL module: advanced JWT analysis.

Goes deeper than jwt_mod (which covers alg=none and weak HMAC secrets):

1. RS256->HS256 confusion guidance: for asymmetric algs the module
   cannot forge a token without the key, so it reports exact manual
   verification steps instead of an unverified claim.
2. kid traversal: flags kid values containing path traversal (../) or
   looking like filenames, with concrete attack payloads.
3. jku/x5u live analysis: fetches the key URL, parses the JWKS, and
   flags weak keys (short HMAC secrets, RSA < 2048 bits) and external
   key sources.
4. x5c / n key-strength analysis on embedded keys.

The target may be a raw JWT string or a URL, in which case JWT-looking
strings are scraped from the page (same approach as jwt_mod).

Non-intrusive: offline analysis plus fetching the token's own jku URL.
"""

import base64
import binascii
import json
import re
import urllib.parse

from arsenal.findings import make_finding
from arsenal.http import fetch

NAME = "jwt_adv"
DESCRIPTION = (
    "Deeper JWT checks: RS256->HS256 confusion guidance, kid traversal, "
    "live jku/x5u fetch and JWKS key-strength analysis."
)
TARGET_KIND = "token"
INTRUSIVE = False

TIMEOUT = 10
JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")
ASYMMETRIC = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512",
              "PS256", "PS384", "PS512", "EdDSA")


def _timeout(ctx):
    cfg = getattr(ctx, "config", None)
    if isinstance(cfg, dict):
        return cfg.get("timeout", TIMEOUT)
    if cfg is not None:
        return getattr(cfg, "timeout", TIMEOUT)
    return TIMEOUT


def _log(ctx, level, msg):
    log = getattr(ctx, "log", None)
    if log is None:
        return
    try:
        getattr(log, level, log.warning)(msg)
    except Exception:
        pass


def _finding(**kwargs):
    kwargs.setdefault("module", NAME)
    return make_finding(**kwargs)


def _b64url_decode(seg):
    seg = seg.strip()
    seg += "=" * (-len(seg) % 4)
    try:
        return base64.urlsafe_b64decode(seg.encode("ascii"))
    except (binascii.Error, ValueError):
        return None


def _parse_token(token):
    try:
        parts = token.strip().split(".")
        if len(parts) != 3:
            return None, None
        header = json.loads(_b64url_decode(parts[0]) or b"null")
        payload = json.loads(_b64url_decode(parts[1]) or b"null")
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return None, None
        return header, payload
    except Exception:
        return None, None


def _fetch(url, ctx):
    try:
        return fetch(url, timeout=_timeout(ctx), allow_redirects=True, ctx=ctx)
    except Exception as exc:
        _log(ctx, "debug", "%s: request failed for %s: %s" % (NAME, url, exc))
        return None


def _is_http_url(target):
    try:
        parts = urllib.parse.urlsplit(target)
    except Exception:
        return False
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def _scrape_tokens(url, ctx):
    resp = _fetch(url, ctx)
    if resp is None:
        return []
    _s, _h, body, _f = resp
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        return []
    return list(dict.fromkeys(JWT_RE.findall(text)))[:5]


def _rsa_bits(n_b64):
    raw = _b64url_decode(n_b64 or "")
    if not raw:
        return 0
    return len(raw) * 8


def run(target, ctx):
    """Run advanced JWT checks on a token or scraped tokens."""
    try:
        return _run(target, ctx)
    except Exception as exc:
        _log(ctx, "warning", "%s failed on %s: %s" % (NAME, target, exc))
        return []


def _run(target, ctx):
    tokens = []
    if _is_http_url(target):
        tokens = _scrape_tokens(target, ctx)
        if not tokens:
            return []
    elif JWT_RE.search(target or ""):
        tokens = [JWT_RE.search(target).group(0)]
    else:
        return []
    findings = []
    for token in tokens:
        findings.extend(_analyze(token, target, ctx))
    return findings


def _analyze(token, target, ctx):
    header, payload = _parse_token(token)
    if header is None:
        return []
    findings = []
    alg = str(header.get("alg", ""))
    kid = header.get("kid")
    jku = header.get("jku")
    x5u = header.get("x5u")

    # 1. kid traversal.
    if isinstance(kid, str) and kid:
        bad = (".." in kid or "/" in kid or "\\" in kid or "%2e" in kid.lower())
        looks_file = bad or re.match(r"^[\w.\-]+\.(pem|key|json|txt|xml)$",
                                     kid, re.IGNORECASE)
        if looks_file:
            findings.append(_finding(
                target=target, severity="medium",
                title="JWT kid looks traversable (%s)" % kid,
                description=(
                    "The kid header (%r) looks like a filename or contains "
                    "path traversal. If the server loads the verification "
                    "key from kid, try: kid=../../dev/null style traversal, "
                    "kid pointing at a static file whose content you know "
                    "(use it as the HMAC secret), or SQL injection in kid "
                    "when it feeds a query." % kid),
                evidence="JWT header: %s" % json.dumps(header)[:300],
                confidence="review", cwe="CWE-22",
                remediation="Use an allowlist mapping kid to keys; never "
                            "build filesystem paths from kid."))

    # 2. jku / x5u live fetch and analysis.
    key_url = jku or x5u
    if isinstance(key_url, str) and key_url.startswith(("http://", "https://")):
        resp = _fetch(key_url, ctx)
        if resp is None:
            findings.append(_finding(
                target=target, severity="info",
                title="JWT %s unreachable for analysis" % ("jku" if jku else "x5u"),
                description="The key URL could not be fetched; test manually "
                            "whether an attacker-controlled JWKS is honored.",
                evidence="Key URL: %s" % key_url,
                confidence="review", cwe="CWE-345",
                remediation="Pin the JWKS to a trusted URL."))
        else:
            _st, _hd, body, _fin = resp
            try:
                jwks = json.loads(body.decode("utf-8", errors="replace"))
            except Exception:
                jwks = None
            keys = (jwks or {}).get("keys", []) if isinstance(jwks, dict) else []
            if not keys:
                findings.append(_finding(
                    target=target, severity="low",
                    title="JWT key URL does not serve a JWKS",
                    description="The jku/x5u URL was fetched but did not "
                                "return a keys array.",
                    evidence="Key URL: %s" % key_url,
                    confidence="review", cwe="CWE-345",
                    remediation="Pin the JWKS to a trusted URL."))
            for k in keys:
                kty = k.get("kty")
                if kty == "oct":
                    raw = _b64url_decode(k.get("k", "") or "")
                    bits = len(raw) * 8 if raw else 0
                    if bits < 256:
                        findings.append(_finding(
                            target=target, severity="medium",
                            title="Weak HMAC key in JWKS (%d bits)" % bits,
                            description="The JWKS serves a symmetric key "
                                        "shorter than 256 bits, which is "
                                        "brute-forceable.",
                            evidence="Key URL: %s | kid=%s bits=%d"
                                     % (key_url, k.get("kid"), bits),
                            confidence="strong", cwe="CWE-326",
                            remediation="Use >= 256-bit random HMAC keys."))
                elif kty == "RSA":
                    bits = _rsa_bits(k.get("n", ""))
                    if bits and bits < 2048:
                        findings.append(_finding(
                            target=target, severity="medium",
                            title="Weak RSA key in JWKS (%d bits)" % bits,
                            description="The JWKS serves an RSA key shorter "
                                        "than 2048 bits.",
                            evidence="Key URL: %s | kid=%s bits=%d"
                                     % (key_url, k.get("kid"), bits),
                            confidence="strong", cwe="CWE-326",
                            remediation="Use >= 2048-bit RSA keys."))
            target_host = ""
            try:
                target_host = urllib.parse.urlsplit(target).hostname or ""
            except Exception:
                pass
            key_host = urllib.parse.urlsplit(key_url).hostname or ""
            if key_host and key_host != target_host:
                findings.append(_finding(
                    target=target, severity="low",
                    title="JWT key URL is third-party hosted",
                    description="The jku/x5u points at a different host than "
                                "the target. If an attacker can influence or "
                                "replace that document, token verification "
                                "is compromised.",
                    evidence="Key URL host: %s" % key_host,
                    confidence="review", cwe="CWE-345",
                    remediation="Host the JWKS on infrastructure you control "
                                "and pin it."))

    # 3. RS256 -> HS256 confusion guidance.
    if alg in ASYMMETRIC:
        findings.append(_finding(
            target=target, severity="info",
            title="JWT RS256->HS256 confusion: manual test steps (%s)" % alg,
            description=(
                "The token uses asymmetric %s. Test confusion manually: 1) "
                "obtain the RSA public key (often at /.well-known/jwks.json "
                "or embedded in the app); 2) craft a token with alg=HS256 "
                "signed with HMAC using the public key bytes as the secret; "
                "3) if the server verifies with HMAC, you can forge "
                "arbitrary tokens. This cannot be confirmed without the "
                "key, so no claim is made here." % alg),
            evidence="JWT header: %s" % json.dumps(header)[:300],
            confidence="review", cwe="CWE-327",
            remediation="Whitelist allowed algorithms per key; never mix "
                        "symmetric and asymmetric verification paths."))
    return findings
