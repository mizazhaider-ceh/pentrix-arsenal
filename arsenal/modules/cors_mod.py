"""PENTRIX ARSENAL module: CORS misconfiguration detection.

Sends an Origin of https://evil.example.com and inspects the
Access-Control-Allow-Origin (ACAO) response. If the server reflects the
arbitrary origin (especially with Access-Control-Allow-Credentials: true),
any site can read cross-origin responses, which is high severity. A
wildcard ACAO (*) is medium severity. Confidence starts at "review"; the
verify step re-tests and can promote to "proven".

Non-intrusive: one GET request with a custom Origin header.
"""

from arsenal.modules.base import BaseModule


NAME = "cors"
DESCRIPTION = (
    "Tests for CORS misconfiguration by sending a foreign Origin and "
    "checking whether Access-Control-Allow-Origin reflects it or uses a "
    "wildcard."
)
TARGET_KIND = "url"
INTRUSIVE = False

TIMEOUT = 10
EVIL_ORIGIN = "https://evil.example.com"


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

def run(target, ctx):
    """Test the target for CORS misconfiguration."""
    try:
        return _run(target, ctx)
    except Exception as exc:
        _log(ctx, "warning", "%s failed on %s: %s" % (NAME, target, exc))
        return []


def _run(target, ctx):
    if not _is_http_url(target):
        return []
    if not _in_scope(target, ctx):
        _log(ctx, "warning", "%s: target out of scope: %s" % (NAME, target))
        return []
    resp = _get(target, ctx, {"Origin": EVIL_ORIGIN})
    if resp is None:
        return []
    _status, headers, _body, _final = resp
    acao = headers.get("access-control-allow-origin", "").strip()
    acac = headers.get("access-control-allow-credentials", "").strip().lower()
    evidence = (
        "Request header: Origin: %s\n"
        "Response Access-Control-Allow-Origin: %s\n"
        "Response Access-Control-Allow-Credentials: %s"
        % (EVIL_ORIGIN, acao or "(absent)", acac or "(absent)")
    )
    if acao == EVIL_ORIGIN:
        if acac == "true":
            return [_finding(
                target=target,
                severity="high",
                confidence="review",
                title="CORS misconfiguration (origin reflected)",
                description=(
                    "The server reflects the arbitrary Origin "
                    "https://evil.example.com and sets "
                    "Access-Control-Allow-Credentials: true, so any website "
                    "can read authenticated cross-origin responses."
                ),
                evidence=evidence,
                cwe="CWE-942",
                remediation=(
                    "Validate the Origin against an allow-list of trusted "
                    "domains instead of reflecting it, and only send "
                    "Access-Control-Allow-Credentials for trusted origins."
                ),
            )]
        return [_finding(
            target=target,
            severity="medium",
            confidence="review",
            title="CORS reflects arbitrary origin",
            description=(
                "The server reflects the arbitrary Origin "
                "https://evil.example.com in Access-Control-Allow-Origin "
                "(without credentials). Any website can read unauthenticated "
                "cross-origin responses."
            ),
            evidence=evidence,
            cwe="CWE-942",
            remediation=(
                "Validate the Origin against an allow-list of trusted "
                "domains instead of reflecting it."
            ),
        )]
    if acao == "*":
        return [_finding(
            target=target,
            severity="medium",
            confidence="review",
            title="CORS allows any origin (wildcard)",
            description=(
                "The server responds with Access-Control-Allow-Origin: *, "
                "permitting any website to read cross-origin responses from "
                "this endpoint."
            ),
            evidence=evidence,
            cwe="CWE-942",
            remediation=(
                "Replace the wildcard with an explicit allow-list of trusted "
                "origins."
            ),
        )]
    return []
