#!/usr/bin/env python3
"""PENTRIX ARSENAL recon module (TARGET_KIND="domain").

Passive subdomain enumeration from certificate-transparency logs and a
passive DNS service, followed by lightweight HTTP alive checks and
subdomain-takeover triage via DNS-over-HTTPS.

Adapted from pentrix-recon: the crt.sh / certspotter / hackertarget source
functions and the normalize() dedupe logic are reused here, rewired onto
the arsenal.http client so every network call carries an explicit timeout.
"""

import json
import socket
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError

from arsenal.http import fetch, fetch_json, fetch_text
from arsenal.findings import make_finding

NAME = "recon"
DESCRIPTION = (
    "Passive subdomain enumeration (crt.sh, CertSpotter, hackertarget, "
    "AlienVault OTX, BufferOverrun, urlscan.io) with HTTP alive checks "
    "and subdomain-takeover triage"
)
TARGET_KIND = "domain"
INTRUSIVE = False

SOURCE_TIMEOUT = 20
ALIVE_TIMEOUT = 8
DOH_TIMEOUT = 8
DOH_URL = "https://cloudflare-dns.com/dns-query"
MAX_ALIVE_CHECKS = 250
MAX_TAKEOVER_CHECKS = 50

# CNAME targets ending in one of these suffixes are hosted on services that
# historically allowed dangling records to be claimed by a third party.
DEAD_SERVICE_SUFFIXES = (
    "github.io",
    "herokuapp.com",
    "s3.amazonaws.com",
    "azurewebsites.net",
    "cloudfront.net",
    "netlify.app",
    "vercel.app",
    "bitbucket.io",
    "shopify.com",
    "wordpress.com",
    "tumblr.com",
    "zendesk.com",
    "statuspage.io",
    "ghost.io",
    "helpjuice.com",
)


# ---------------------------------------------------------------------------
# enumeration sources (adapted from pentrix-recon)
# ---------------------------------------------------------------------------
# enumeration sources
#
# Every source takes (domain, timeout, ctx) and returns a set of hostnames.
# fetch_json/fetch_text return (status, payload, final_url) tuples, so the
# payload is unpacked explicitly (an earlier revision forgot this and every
# source silently returned nothing).
# ---------------------------------------------------------------------------

def _fetch_json_retry(url, timeout, ctx, retries=2):
    """GET JSON with a small backoff on empty/failed responses."""
    delay = 1.0
    for attempt in range(retries + 1):
        try:
            status, data, _final = fetch_json(url, timeout=timeout, ctx=ctx)
        except Exception:
            status, data = 0, None
        if data is not None and status not in (429,) and not (
                status and status >= 500):
            return data
        if attempt < retries:
            time.sleep(delay)
            delay *= 2
    return None


def _fetch_text_retry(url, timeout, ctx, retries=2):
    """GET text with a small backoff on empty/failed responses."""
    delay = 1.0
    for attempt in range(retries + 1):
        try:
            status, text, _final = fetch_text(url, timeout=timeout, ctx=ctx)
        except Exception:
            status, text = 0, ""
        if text and status not in (429,) and not (status and status >= 500):
            return text
        if attempt < retries:
            time.sleep(delay)
            delay *= 2
    return ""


def _clean_name(name):
    name = str(name or "").strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    return name


def _source_crtsh(domain, timeout, ctx):
    """Enumerate via crt.sh certificate transparency search."""
    q = urllib.parse.quote("%%.%s" % domain, safe="")
    url = "https://crt.sh/?q=%s&output=json" % q
    found = set()
    data = _fetch_json_retry(url, timeout, ctx)
    if not isinstance(data, list):
        return found
    for entry in data:
        names = entry.get("name_value", "") if isinstance(entry, dict) else ""
        for name in str(names or "").splitlines():
            name = _clean_name(name)
            if name:
                found.add(name)
    return found


def _source_certspotter(domain, timeout, ctx):
    """Enumerate via the CertSpotter v1 issuances API."""
    q = urllib.parse.quote(domain, safe="")
    url = "https://api.certspotter.com/v1/issuances?domain=%s&expand=dns_names" % q
    found = set()
    data = _fetch_json_retry(url, timeout, ctx)
    if not isinstance(data, list):
        return found
    for issuance in data:
        names = (issuance.get("dns_names") or []) if isinstance(issuance, dict) else []
        for name in names:
            name = _clean_name(name)
            if name:
                found.add(name)
    return found


def _source_hackertarget(domain, timeout, ctx):
    """Enumerate via the hackertarget hostsearch API (rate-limited, flaky)."""
    q = urllib.parse.quote(domain, safe="")
    url = "https://api.hackertarget.com/hostsearch/?q=%s" % q
    found = set()
    body = _fetch_text_retry(url, timeout, ctx)
    if not isinstance(body, str) or not body.strip():
        return found
    if "error" in body.lower():
        return found
    for line in body.splitlines():
        line = line.strip()
        if not line or "," not in line:
            continue
        host = _clean_name(line.split(",", 1)[0])
        if host:
            found.add(host)
    return found


def _source_otx(domain, timeout, ctx):
    """Enumerate via AlienVault OTX passive DNS (no key needed)."""
    q = urllib.parse.quote(domain, safe="")
    url = ("https://otx.alienvault.com/api/v1/indicators/domain/%s/"
           "passive_dns" % q)
    found = set()
    data = _fetch_json_retry(url, timeout, ctx)
    if not isinstance(data, dict):
        return found
    for record in data.get("passive_dns") or []:
        name = _clean_name(record.get("hostname") if isinstance(record, dict) else "")
        if name:
            found.add(name)
    return found


def _source_bufferover(domain, timeout, ctx):
    """Enumerate via BufferOverrun TLS certificate search (free, no key)."""
    q = urllib.parse.quote(domain, safe="")
    url = "https://tls.bufferover.run/dns?q=.%s" % q
    found = set()
    data = _fetch_json_retry(url, timeout, ctx)
    if not isinstance(data, dict):
        return found
    for entry in data.get("Results") or []:
        for part in str(entry).split(","):
            name = _clean_name(part)
            if name:
                found.add(name)
    return found


def _source_urlscan(domain, timeout, ctx):
    """Enumerate via the urlscan.io search API (free, rate-limited)."""
    q = urllib.parse.quote(domain, safe="")
    url = "https://urlscan.io/api/v1/search/?q=domain:%s" % q
    found = set()
    data = _fetch_json_retry(url, timeout, ctx)
    if not isinstance(data, dict):
        return found
    for result in data.get("results") or []:
        page = result.get("page") if isinstance(result, dict) else None
        name = _clean_name(page.get("domain") if isinstance(page, dict) else "")
        if name:
            found.add(name)
    return found


SOURCES = (
    ("crtsh", _source_crtsh),
    ("certspotter", _source_certspotter),
    ("hackertarget", _source_hackertarget),
    ("otx", _source_otx),
    ("bufferover", _source_bufferover),
    ("urlscan", _source_urlscan),
)


def normalize(subs, domain):
    """Dedupe (case-insensitive), strip trailing dots, keep only subdomains."""
    domain = domain.lower()
    clean = set()
    for s in subs:
        s = str(s).strip().rstrip(".").lower()
        if not s:
            continue
        if s == domain or s.endswith("." + domain):
            clean.add(s)
    return sorted(clean)


# ---------------------------------------------------------------------------
# alive checks
# ---------------------------------------------------------------------------

def _check_alive(host, timeout=ALIVE_TIMEOUT, ctx=None):
    """Try https://host then http://host. Returns (alive, scheme, status, final_url)."""
    for scheme in ("https", "http"):
        try:
            status, _headers, _body, final_url = fetch(
                "%s://%s" % (scheme, host), timeout=timeout, ctx=ctx
            )
        except Exception:
            status, final_url = 0, None
        if status and status < 500:
            return True, scheme, status, final_url
    return False, None, 0, None


# ---------------------------------------------------------------------------
# subdomain-takeover triage
# ---------------------------------------------------------------------------

def _doh_cname(host, timeout=DOH_TIMEOUT, ctx=None):
    """Return the CNAME target for host via DNS-over-HTTPS, or None."""
    url = "%s?name=%s&type=CNAME" % (
        DOH_URL, urllib.parse.quote(host, safe="")
    )
    try:
        status, _headers, body, _final = fetch(url, timeout=timeout, ctx=ctx)
    except Exception:
        return None
    if status != 200 or not body:
        return None
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    for answer in data.get("Answer") or []:
        if (
            isinstance(answer, dict)
            and answer.get("type") == 5
            and answer.get("data")
        ):
            return str(answer["data"]).rstrip(".").lower()
    return None


def _resolves(name, timeout=5):
    """True if name resolves via DNS, False on NXDOMAIN/timeout/error."""
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                socket.getaddrinfo, name, 443, type=socket.SOCK_STREAM
            )
            future.result(timeout=timeout)
        return True
    except (FutureTimeoutError, socket.gaierror, OSError, ValueError):
        return False


def _takeover_candidate(host, timeout=DOH_TIMEOUT, ctx=None):
    """Return the dangling CNAME target if host looks takeable, else None."""
    cname = _doh_cname(host, timeout, ctx)
    if not cname:
        return None
    if not any(
        cname == suffix or cname.endswith("." + suffix)
        for suffix in DEAD_SERVICE_SUFFIXES
    ):
        return None
    if _resolves(cname):
        return None
    return cname


# ---------------------------------------------------------------------------
# module entry point
# ---------------------------------------------------------------------------

def run(target, ctx):
    findings = []

    log = getattr(ctx, "log", None)
    config = getattr(ctx, "config", None) or {}
    scope = getattr(ctx, "scope", None)

    def _log(level, message):
        try:
            if log is not None:
                getattr(log, level)(message)
        except Exception:
            pass

    def _in_scope(host):
        if scope is None or not hasattr(scope, "contains"):
            return True
        try:
            return bool(scope.contains(host))
        except Exception:
            return True

    domain = (target or "").strip().lower().rstrip(".")
    if not domain or "." not in domain:
        _log("warning", "recon: invalid domain target %r" % (target,))
        return findings
    if not _in_scope(domain):
        _log("info", "recon: %s outside scope, skipping" % domain)
        return findings

    # 1. passive enumeration
    all_subs = set()
    source_timeout = config.get("recon_source_timeout", SOURCE_TIMEOUT)
    for key, func in SOURCES:
        try:
            got = func(domain, source_timeout, ctx)
        except Exception as exc:  # one source must not kill the run
            _log("warning", "recon: source %s failed: %s" % (key, exc))
            continue
        _log("info", "recon: %s returned %d names" % (key, len(got)))
        all_subs |= set(got)
    subdomains = normalize(all_subs, domain)
    _log("info", "recon: %d unique subdomains for %s" % (len(subdomains), domain))

    # 2. alive checks (https first, then http)
    alive_count = 0
    for host in subdomains[:MAX_ALIVE_CHECKS]:
        if not _in_scope(host):
            continue
        try:
            ok, scheme, status, final_url = _check_alive(host, ALIVE_TIMEOUT, ctx)
        except Exception as exc:  # never let one host kill the run
            _log("debug", "recon: alive check for %s failed: %s" % (host, exc))
            continue
        if not ok:
            continue
        alive_count += 1
        evidence = "%s %s" % (scheme, status)
        if final_url:
            evidence += " (final URL: %s)" % final_url
        findings.append(
            make_finding(
                module=NAME,
                target=host,
                severity="info",
                confidence="strong",
                title="Alive host: %s" % host,
                description=(
                    "Host responded to an HTTP(S) request during recon "
                    "alive checks."
                ),
                evidence=evidence,
                cwe=None,
                remediation=None,
            )
        )
    if len(subdomains) > MAX_ALIVE_CHECKS:
        _log(
            "info",
            "recon: alive checks capped at %d of %d subdomains"
            % (MAX_ALIVE_CHECKS, len(subdomains)),
        )

    # 3. subdomain-takeover triage (capped)
    for host in subdomains[:MAX_TAKEOVER_CHECKS]:
        if not _in_scope(host):
            continue
        try:
            cname = _takeover_candidate(host, DOH_TIMEOUT, ctx)
        except Exception as exc:
            _log("debug", "recon: takeover check for %s failed: %s" % (host, exc))
            continue
        if not cname:
            continue
        findings.append(
            make_finding(
                module=NAME,
                target=host,
                severity="high",
                confidence="review",
                title="Possible subdomain takeover: %s" % host,
                description=(
                    "Subdomain %s has a CNAME record pointing at %s, a "
                    "hosting service known to allow takeover of dangling "
                    "records, and the target does not resolve (NXDOMAIN). "
                    "Verify manually before claiming." % (host, cname)
                ),
                evidence="CNAME %s -> %s (NXDOMAIN on resolve)" % (host, cname),
                cwe="CWE-284",
                remediation=(
                    "Remove the dangling DNS record or reclaim the resource "
                    "on the hosting service."
                ),
            )
        )

    # 4. summary
    findings.append(
        make_finding(
            module=NAME,
            target=domain,
            severity="info",
            confidence="strong",
            title="Subdomain enumeration summary: %s" % domain,
            description=(
                "Passive enumeration across crt.sh, CertSpotter and "
                "hackertarget, followed by HTTP alive checks and "
                "subdomain-takeover triage."
            ),
            evidence=(
                "%d unique subdomains from 3 sources; %d alive "
                "(HTTP status < 500)" % (len(subdomains), alive_count)
            ),
            cwe=None,
            remediation=None,
        )
    )
    return findings
