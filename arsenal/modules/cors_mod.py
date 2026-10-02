"""PENTRIX ARSENAL module: CORS misconfiguration detection.

Sends an Origin of https://evil.example.com and inspects the
Access-Control-Allow-Origin (ACAO) response. If the server reflects the
arbitrary origin (especially with Access-Control-Allow-Credentials: true),
any site can read cross-origin responses, which is high severity. A
wildcard ACAO (*) is medium severity. Confidence starts at "review"; the
verify step re-tests and can promote to "proven".

Non-intrusive: one GET request with a custom Origin header.
"""

import urllib.parse

from arsenal.findings import make_finding
from arsenal.http import fetch

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


def _is_http_url(target):
    try:
        parts = urllib.parse.urlsplit(target)
    except Exception:
        return False
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def _host_of(url):
    try:
        return urllib.parse.urlsplit(url).hostname or ""
    except Exception:
        return ""


def _in_scope(target, ctx):
    scope = getattr(ctx, "scope", None)
    if scope is None:
        return True
    try:
        return bool(scope.contains(_host_of(target)))
    except Exception:
        return True


def _get(url, ctx, headers):
    try:
        return fetch(url, headers=headers, timeout=_timeout(ctx),
                     allow_redirects=True)
    except Exception as exc:
        _log(ctx, "debug", "%s: request failed for %s: %s" % (NAME, url, exc))
        return None


def _finding(**kwargs):
    kwargs.setdefault("module", NAME)
    return make_finding(**kwargs)


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
