"""PENTRIX ARSENAL module: technology-aware smart fuzzing.

Injects canary payloads into each query parameter and compares the
response (status, length, reflection) against the unmodified baseline.
The payload set is chosen from ctx.tech_hint (a list of technology
strings the pipeline may set; defaults to []): php hints select PHP
wrapper/traversal probes, node hints select prototype pollution probes,
python hints select SSTI probes, and anything else falls back to a generic
XSS/SQLi canary set. One finding per anomalous parameter.

Intrusive: sends crafted payloads. Findings are "review" confidence; they
are anomalies worth manual follow-up, not confirmed vulnerabilities.
"""

import re
import urllib.parse
from arsenal.modules.base import BaseModule


NAME = "fuzz"
DESCRIPTION = (
    "Technology-aware parameter fuzzing: injects canary payloads chosen "
    "from ctx.tech_hint into each query parameter and flags anomalous "
    "responses versus the baseline."
)
TARGET_KIND = "url"
INTRUSIVE = True

TIMEOUT = 10
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_PAYLOADS_PER_PARAM = 4

PAYLOAD_SETS = {
    "php": [
        "php://filter/convert.base64-encode/resource=PFZCANARY",
        "../../../../etc/passwdPFZCANARY",
        "PFZCANARY<?php echo 'pfz'; ?>",
    ],
    "node": [
        '{"__proto__":{"PFZCANARY":1}}',
        "__proto__[PFZCANARY]=1",
        "constructor.prototype.PFZCANARY=1",
    ],
    "python": [
        "{{7*7}}PFZCANARY",
        "${7*7}PFZCANARY",
        "{%PFZCANARY%}",
    ],
    "generic": [
        "<PFZCANARY>",
        "'\"PFZCANARY",
        "PFZCANARY{{7*7}}",
    ],
}

CHARSET_RE = re.compile(r"charset=([\w-]+)", re.IGNORECASE)


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

def decode_body(headers, body):
    content_type = headers.get("content-type", "")
    match = CHARSET_RE.search(content_type or "")
    charset = match.group(1) if match else "utf-8"
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def choose_payloads(ctx):
    """Pick payload templates from ctx.tech_hint (list of tech strings).

    tech_hint is written by the pipeline/service-aware layer (another
    crew owns that wiring); when it is absent or empty every run falls
    back to the generic set, so the module works standalone too.
    """
    hints = getattr(ctx, "tech_hint", None) or []
    hint_text = " ".join(str(h).lower() for h in hints)
    chosen = []
    if any(t in hint_text for t in ("php", "laravel", "wordpress", "symfony")):
        chosen.extend(PAYLOAD_SETS["php"])
    if any(t in hint_text for t in ("node", "express", "javascript", "nextjs", "nestjs")):
        chosen.extend(PAYLOAD_SETS["node"])
    if any(t in hint_text for t in ("python", "django", "flask", "fastapi")):
        chosen.extend(PAYLOAD_SETS["python"])
    if not chosen:
        chosen.extend(PAYLOAD_SETS["generic"])
    else:
        # Always add one generic canary so input handling is still probed.
        chosen.append(PAYLOAD_SETS["generic"][0])
    seen = []
    for template in chosen:
        if template not in seen:
            seen.append(template)
    return seen[:MAX_PAYLOADS_PER_PARAM]


def build_test_url(url, params, target_idx, value):
    parts = urllib.parse.urlparse(url)
    new_params = [
        (name, value if i == target_idx else val)
        for i, (name, val) in enumerate(params)
    ]
    query = urllib.parse.urlencode(new_params)
    return urllib.parse.urlunparse(parts._replace(query=query))


def run(target, ctx):
    """Fuzz each query parameter; one finding per anomalous parameter."""
    try:
        return _run(target, ctx)
    except Exception as exc:
        _log(ctx, "warning", "%s failed on %s: %s" % (NAME, target, exc))
        return []


def _run(target, ctx):
    if INTRUSIVE and getattr(ctx, "safe_mode", False) \
            and not getattr(ctx, "allow_intrusive", False):
        _log(ctx, "warning", "%s skipped: safe mode blocks intrusive modules"
             % NAME)
        return []
    if not _is_http_url(target):
        return []
    if not _in_scope(target, ctx):
        _log(ctx, "warning", "%s: target out of scope: %s" % (NAME, target))
        return []

    params = urllib.parse.parse_qsl(
        urllib.parse.urlsplit(target).query, keep_blank_values=True)
    if not params:
        return []

    base_resp = _get(target, ctx)
    if base_resp is None:
        return []
    base_status, base_headers, base_body, _final = base_resp
    base_len = len(base_body)
    base_text = decode_body(base_headers, base_body)

    payloads = choose_payloads(ctx)
    out = []
    for pidx, (name, _value) in enumerate(params):
        anomalies = []
        for sidx, template in enumerate(payloads):
            canary = "pfz%dx%d" % (pidx, sidx)
            payload = template.replace("PFZCANARY", canary)
            test_url = build_test_url(target, params, pidx, payload)
            resp = _get(test_url, ctx)
            if resp is None:
                continue
            status, headers, body, _final = resp
            if len(body) > MAX_BODY_BYTES:
                continue
            text = decode_body(headers, body)
            reasons = []
            if status != base_status and (status >= 500 or status // 100 != base_status // 100):
                reasons.append("status %s -> %s" % (base_status, status))
            length_delta = abs(len(body) - base_len)
            if length_delta > max(400, int(base_len * 0.3)):
                reasons.append("length %d -> %d bytes" % (base_len, len(body)))
            if canary in text and canary not in base_text:
                reasons.append("canary reflected in response")
            if "49" in text and "49" not in base_text and "7*7" in payload:
                reasons.append("template math evaluated (49 in response)")
            if reasons:
                anomalies.append((payload, "; ".join(reasons)))
        if anomalies:
            evidence_lines = ["baseline: HTTP %s, %d bytes" % (base_status, base_len)]
            for payload, reasons in anomalies:
                evidence_lines.append("payload %r -> %s" % (payload, reasons))
            out.append(_finding(
                target=target,
                severity="medium",
                confidence="review",
                title="Anomalous parameter behavior: '%s'" % name,
                description=(
                    "Parameter '%s' produced anomalous responses to fuzz "
                    "payloads compared with the baseline. This suggests the "
                    "value reaches interesting server-side handling and is "
                    "worth manual follow-up." % name
                ),
                evidence="\n".join(evidence_lines),
                cwe="CWE-20",
                remediation=(
                    "Validate and sanitize '%s' server-side; investigate why "
                    "the anomalous responses differ from the baseline." % name
                ),
            ))
    return out
