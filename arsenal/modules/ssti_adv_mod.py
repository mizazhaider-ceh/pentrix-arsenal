"""PENTRIX ARSENAL module: advanced SSTI detection.

Extends ssti_mod with more template engines and error-based detection:

Arithmetic probes per engine family (expect "49" in the response when
the baseline does not contain it):
- {{7*7}}      Jinja2 / Twig / Django-ish
- ${7*7}       FreeMarker / Velocity / JSP EL
- #{7*7}       Ruby ERB / Slim
- *{7*7}       Thymeleaf
- <%= 7*7 %>   ERB / EJS / ASP

String-concatenation probes (expect "77"):
- {{7*'7'}}    Jinja2/Twig string concat
- ${7+'7'}     FreeMarker numeric-plus-string path

Error-based detection: sends broken template syntax and matches
engine stack-trace markers (jinja2, Twig, Smarty, FreeMarker,
Velocity, ERB, Mako) filtered against the baseline.

Non-intrusive: GET requests only, small payload set.
"""

import urllib.parse

from arsenal.findings import make_finding
from arsenal.http import fetch

NAME = "ssti_adv"
DESCRIPTION = (
    "Detects server-side template injection across more engines "
    "(Ruby #{}, Thymeleaf *{}, string-concat probes) plus error-based "
    "engine fingerprinting."
)
TARGET_KIND = "url"
INTRUSIVE = False

TIMEOUT = 10
MAX_PARAMS = 3

ARITHMETIC_PROBES = [
    ("{{7*7}}", "Jinja2/Twig"),
    ("${7*7}", "FreeMarker/Velocity"),
    ("#{7*7}", "Ruby ERB/Slim"),
    ("*{7*7}", "Thymeleaf"),
    ("<%= 7*7 %>", "ERB/EJS"),
]
ARITHMETIC_EXPECTED = "49"

CONCAT_PROBES = [
    ("{{7*'7'}}", "Jinja2/Twig"),
    ('${7+"7"}', "FreeMarker"),
]
CONCAT_EXPECTED = "77"

ERROR_PROBES = ["{{", "${", "#{", "*{"]
ERROR_MARKERS = (
    "jinja2", "twig", "smarty", "freemarker", "velocity", "erb",
    "mako", "templatesyntaxerror", "undefinederror", "template error",
    "on line 1", "unexpected end",
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


def _params(url):
    try:
        return urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query,
                                      keep_blank_values=True)
    except Exception:
        return []


def _with_param(url, idx, new_value):
    parts = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    q[idx] = (q[idx][0], new_value)
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path,
         urllib.parse.urlencode(q), parts.fragment))


def _fetch(url, ctx):
    try:
        return fetch(url, timeout=_timeout(ctx), allow_redirects=True, ctx=ctx)
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
    """Probe URL parameters for SSTI across engine families."""
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
    params = _params(target)
    if not params:
        return []
    findings = []

    baseline_resp = _fetch(target, ctx)
    baseline_text = _body_text(baseline_resp) if baseline_resp else ""

    for idx, (pname, pval) in enumerate(params[:MAX_PARAMS]):
        # Arithmetic probes.
        for payload, engine in ARITHMETIC_PROBES:
            probe_url = _with_param(target, idx, pval + payload)
            resp = _fetch(probe_url, ctx)
            if resp is None:
                continue
            text = _body_text(resp)
            if ARITHMETIC_EXPECTED in text \
                    and ARITHMETIC_EXPECTED not in baseline_text:
                findings.append(_finding(
                    target=target,
                    severity="high",
                    title="SSTI: template evaluated %s (%s engine)" % (payload, engine),
                    description=(
                        "The payload %s in parameter %s was evaluated "
                        "server-side (response contains %s). This is "
                        "server-side template injection for the %s family."
                        % (payload, pname, ARITHMETIC_EXPECTED, engine)),
                    evidence="Request: %s\nPayload evaluated to %s."
                             % (probe_url, ARITHMETIC_EXPECTED),
                    confidence="strong",
                    cwe="CWE-94",
                    remediation="Never render user input as a template; use "
                                "logic-less templates with autoescaping and "
                                "sandboxing."))
                break
        else:
            # String-concat probes (catch engines where 7*7 is not valid).
            for payload, engine in CONCAT_PROBES:
                probe_url = _with_param(target, idx, pval + payload)
                resp = _fetch(probe_url, ctx)
                if resp is None:
                    continue
                text = _body_text(resp)
                if CONCAT_EXPECTED in text \
                        and CONCAT_EXPECTED not in baseline_text:
                    findings.append(_finding(
                        target=target,
                        severity="high",
                        title="SSTI via string concat %s (%s)" % (payload, engine),
                        description=(
                            "The payload %s in %s was evaluated to %s, "
                            "which confirms template injection for the %s "
                            "family." % (payload, pname, CONCAT_EXPECTED,
                                         engine)),
                        evidence="Request: %s" % probe_url,
                        confidence="strong",
                        cwe="CWE-94",
                        remediation="Same as above: never template user input."))
                    break
        # Error-based engine fingerprinting.
        for payload in ERROR_PROBES:
            probe_url = _with_param(target, idx, pval + payload)
            resp = _fetch(probe_url, ctx)
            if resp is None:
                continue
            text = _body_text(resp).lower()
            markers = [m for m in ERROR_MARKERS
                       if m in text and m not in baseline_text.lower()]
            if markers:
                findings.append(_finding(
                    target=target, severity="medium",
                    title="Template engine error leak via %s" % pname,
                    description=(
                        "Broken template syntax in %s leaked an engine "
                        "stack trace, which fingerprints the template "
                        "engine and confirms user input reaches it."
                        % pname),
                    evidence="Request: %s\nMarkers: %s"
                             % (probe_url, ", ".join(markers)),
                    confidence="review",
                    cwe="CWE-94",
                    remediation="Disable debug stack traces in production; "
                                "do not render user input as templates."))
                break
    return findings
