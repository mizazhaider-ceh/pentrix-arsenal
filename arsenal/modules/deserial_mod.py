"""PENTRIX ARSENAL module: insecure deserialization probe pack.

Two passive/active layers, no gadget chains ever executed:

1. Language fingerprints: inspects Set-Cookie values, query parameters
   and __VIEWSTATE fields for serialized-object markers:
   - Java: base64 decoding to bytes starting with AC ED 00 05
   - PHP: O:<n>: / a:<n>:{ / s:<n>: object notation
   - Python pickle: base64 decoding to bytes starting with \\x80\\x04
     (protocol 2+) or ASCII pickle opcodes
   - .NET: __VIEWSTATE parameter present (MAC state reported as
     guidance, since MAC validity cannot be verified remotely)
2. Safe type-confusion probes: sends array-shaped (param[]=1) and
   JSON-shaped values to parameters and notes 500s or behavior
   changes, which hint at unsafe type juggling. No serialized exploit
   payloads are ever sent.

Non-intrusive: normal fetches plus a couple of type probes.
"""

import base64
import binascii
import re
import urllib.parse

from arsenal.findings import make_finding
from arsenal.http import fetch

NAME = "deserial"
DESCRIPTION = (
    "Fingerprints serialized objects (Java, PHP, Python pickle, .NET "
    "ViewState) and runs safe type-confusion probes; never sends gadget "
    "chains."
)
TARGET_KIND = "url"
INTRUSIVE = False

TIMEOUT = 10
MAX_PARAMS = 3

JAVA_MAGIC = b"\xac\xed\x00\x05"
PICKLE_MAGIC = b"\x80\x04"
PHP_RE = re.compile(r'^[OaCs]:\d+[:{"]')


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


def _fetch(url, ctx):
    try:
        return fetch(url, timeout=_timeout(ctx), allow_redirects=True, ctx=ctx)
    except Exception as exc:
        _log(ctx, "debug", "%s: request failed for %s: %s" % (NAME, url, exc))
        return None


def _b64decode(value):
    s = urllib.parse.unquote(value).strip()
    if len(s) < 8 or len(s) % 4:
        return None
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def _fingerprint_value(value):
    """Return a language label when value looks like a serialized object."""
    raw = _b64decode(value)
    if raw is not None:
        if raw.startswith(JAVA_MAGIC):
            return "Java serialization (AC ED 00 05)"
        if raw.startswith(PICKLE_MAGIC):
            return "Python pickle"
        if raw[:1] in (b"(", b"c", b"]", b"}") and b"\n" in raw[:64]:
            return "Python pickle (ASCII protocol)"
    if PHP_RE.match(value):
        return "PHP serialization (O:/a:/s: notation)"
    return None


def _cookie_values(headers):
    raw = (headers or {}).get("set-cookie", "")
    if isinstance(raw, list):
        raw = "\n".join(raw)
    out = []
    for line in str(raw).split("\n"):
        line = line.strip()
        if "=" in line:
            name, rest = line.split("=", 1)
            out.append((name.strip(), rest.split(";")[0].strip()))
    return out


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


def run(target, ctx):
    """Fingerprint serialized objects and probe type confusion."""
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
    resp = _fetch(target, ctx)
    if resp is None:
        return []
    status, headers, body, _final = resp
    try:
        page = body.decode("utf-8", errors="replace")
    except Exception:
        page = ""

    # 1. Fingerprint cookies and query params.
    sources = [("cookie", n, v) for n, v in _cookie_values(headers)]
    sources += [("query param", n, v) for n, v in _params(target)]
    for src, name, value in sources:
        lang = _fingerprint_value(value)
        if lang:
            findings.append(_finding(
                target=target,
                severity="medium",
                title="Serialized %s object in %s '%s'" % (lang.split()[0], src, name),
                description=(
                    "The %s '%s' looks like a %s. If the server "
                    "deserializes it without integrity protection, this is "
                    "a deserialization entry point. No gadget payload was "
                    "sent; verify manually whether the value is "
                    "authenticated (HMAC) before reporting." % (src, name, lang)),
                evidence="%s '%s' fingerprint: %s" % (src, name, lang),
                confidence="review",
                cwe="CWE-502",
                remediation=(
                    "Do not accept serialized objects from clients; use "
                    "JSON with integrity protection (signed tokens) "
                    "instead.")))

    # .NET ViewState.
    m = re.search(r'name=["\']?__VIEWSTATE["\']?\s+value=["\']?([^"\'\s>]+)',
                  page, re.IGNORECASE)
    if m or "__viewstate" in target.lower():
        findings.append(_finding(
            target=target, severity="info",
            title=".NET ViewState detected",
            description=(
                "The page uses __VIEWSTATE. Check that ViewState MAC "
                "validation (enableViewStateMac / ViewStateEncryptionMode) "
                "is on; without a MAC, ViewState deserialization is "
                "exploitable. This cannot be verified remotely."),
            evidence="__VIEWSTATE field present.",
            confidence="review", cwe="CWE-502",
            remediation="Enable ViewState MAC validation and encryption."))

    # 2. Safe type-confusion probes.
    baseline_len = len(body or b"")
    for idx, (pname, pval) in enumerate(_params(target)[:MAX_PARAMS]):
        for probe, label in (("a[]", "array"), ('{"a":1}', "object")):
            probe_url = _with_param(target, idx, probe)
            r = _fetch(probe_url, ctx)
            if r is None:
                continue
            st, _h, bd, _f = r
            if st >= 500 or abs(len(bd or b"") - baseline_len) > max(500, baseline_len):
                findings.append(_finding(
                    target=target, severity="info",
                    title="Type-confusion behavior on %s (%s-shaped input)" % (pname, label),
                    description=(
                        "Sending a %s-shaped value for %s changed server "
                        "behavior (status %s), which hints at unsafe type "
                        "juggling in deserialization or parameter binding. "
                        "Investigate manually; no exploit payload was sent."
                        % (label, pname, st)),
                    evidence="Request: %s\nStatus: %s" % (probe_url, st),
                    confidence="review", cwe="CWE-704",
                    remediation="Bind parameters to strict types; reject "
                                "unexpected shapes."))
                break
    return findings
