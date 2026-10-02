#!/usr/bin/env python3
"""PENTRIX ARSENAL technology fingerprinting module (TARGET_KIND="url").

Fetches the target homepage and fingerprints the stack from response
headers (Server, X-Powered-By, Via), meta generator tags, JavaScript
library/framework markers in the HTML, the favicon MD5 hash, and
WAF/CDN header signatures.
"""

import hashlib
import re
import urllib.parse

from arsenal.http import fetch
from arsenal.findings import make_finding

NAME = "tech"
DESCRIPTION = "Technology fingerprinting from headers, HTML markers and favicon hash"
TARGET_KIND = "url"
INTRUSIVE = False

FETCH_TIMEOUT = 10
BODY_SCAN_LIMIT = 2_000_000

# (technology, kind, [regexes]); first capture group, if numeric, is a version.
LIB_PATTERNS = [
    ("jQuery", "JavaScript library", [r"jquery[.-](\d[\d.]*)", r"jQuery"]),
    ("React", "JavaScript library", [r"react-dom[.-](\d[\d.]*)", r"data-reactroot", r"__react"]),
    ("Vue.js", "JavaScript library", [r"vue[.-](\d[\d.]*)", r"data-v-[a-f0-9]+", r"__vue__"]),
    ("Angular", "JavaScript library", [r"angular[.-](\d[\d.]*)", r"ng-app", r"ng-version="]),
    ("Next.js", "Framework", [r"_next/static", r"__NEXT_DATA__"]),
    ("Nuxt.js", "Framework", [r"__nuxt", r"_nuxt/"]),
    ("WordPress", "CMS", [r"wp-content/", r"wp-includes/", r"wp-json/"]),
    ("Drupal", "CMS", [r"drupal(?:[.-](\d[\d.]*))?", r"sites/all/modules"]),
    ("Joomla", "CMS", [r"joomla", r"media/jui/"]),
    ("Laravel", "Framework", [r"laravel", r"XSRF-TOKEN"]),
    ("Django", "Framework", [r"csrf(?:middleware)?token", r"django"]),
    ("Ruby on Rails", "Framework", [r"csrf-param", r"_rails", r"actionpack"]),
    ("ASP.NET", "Framework", [r"__VIEWSTATE", r"ASP\.NET_SessionId", r"asp\.net"]),
    ("PHP", "Language", [r"\.php(?:[?\"'])", r"PHPSESSID"]),
    ("Bootstrap", "CSS framework", [r"bootstrap[.-](\d[\d.]*)"]),
    ("Tailwind CSS", "CSS framework", [r"tailwind"]),
]

# (waf/cdn name, [match strings looked for in header names/values/server])
WAF_SIGNATURES = [
    ("Cloudflare", ["cf-ray", "cf-cache-status", "__cf_bm", "cloudflare"]),
    ("AWS CloudFront / ELB", ["x-amz-cf-id", "x-amzn-", "awselb", "cloudfront"]),
    ("Akamai", ["akamai", "x-akamai"]),
    ("Sucuri", ["x-sucuri", "sucuri"]),
    ("Imperva Incapsula", ["x-iinfo", "incap_ses", "incapsula", "imperva"]),
    ("Fastly", ["x-fastly", "fastly"]),
    ("CloudFront", ["x-amz-cf-id"]),
    ("Varnish", ["varnish", "x-varnish"]),
    ("F5 BIG-IP", ["bigipserver", "f5-"]),
]

VERSION_RE = re.compile(r"\d+(?:\.\d+)+")
GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']+)',
    re.IGNORECASE,
)


def _to_text(body):
    if body is None:
        return ""
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    return str(body)


def _headers_lower(headers):
    out = {}
    try:
        items = headers.items() if hasattr(headers, "items") else headers
        for key, value in items:
            out[str(key).lower()] = str(value)
    except Exception:
        pass
    return out


def _tech_name(base, match):
    version = None
    try:
        candidate = match.group(1)
        if candidate and VERSION_RE.search(candidate):
            version = VERSION_RE.search(candidate).group(0)
    except IndexError:
        pass
    return "%s %s" % (base, version) if version else base


def _detect_from_headers(headers):
    """Return (tech_findings, server_value, waf_hits)."""
    tech = []
    server_value = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    via = headers.get("via", "")
    if powered:
        tech.append(("Technology: %s" % powered.strip(),
                     "X-Powered-By header: %s" % powered.strip()))
    if via:
        tech.append(("Technology hint: %s" % via.strip(),
                     "Via header: %s" % via.strip()))
    waf_hits = []
    haystack = " ".join(headers.keys()) + " " + " ".join(headers.values())
    haystack_low = haystack.lower()
    for waf_name, markers in WAF_SIGNATURES:
        for marker in markers:
            if marker in haystack_low:
                waf_hits.append((waf_name, marker))
                break
    return tech, server_value, waf_hits


def _detect_from_body(body):
    found = []
    seen = set()
    for name, kind, patterns in LIB_PATTERNS:
        for pattern in patterns:
            try:
                match = re.search(pattern, body, re.IGNORECASE)
            except re.error:
                continue
            if match:
                tech_name = _tech_name(name, match)
                if tech_name not in seen:
                    seen.add(tech_name)
                    found.append(
                        (tech_name, kind,
                         "matched %r in page HTML" % pattern)
                    )
                break
    generator = GENERATOR_RE.search(body)
    generator_name = generator.group(1).strip() if generator else None
    return found, generator_name


def _favicon_md5(target_url):
    """Fetch /favicon.ico and return its MD5 hex digest, or None."""
    try:
        parts = urllib.parse.urlsplit(target_url)
        base = "%s://%s" % (parts.scheme or "https", parts.netloc)
        status, _headers, body, _final = fetch(
            base + "/favicon.ico", timeout=FETCH_TIMEOUT
        )
    except Exception:
        return None
    if status != 200 or not body:
        return None
    data = body if isinstance(body, bytes) else body.encode("utf-8", errors="replace")
    return hashlib.md5(data).hexdigest()


# ---------------------------------------------------------------------------
# module entry point
# ---------------------------------------------------------------------------

def run(target, ctx):
    findings = []

    log = getattr(ctx, "log", None)

    def _log(level, message):
        try:
            if log is not None:
                getattr(log, level)(message)
        except Exception:
            pass

    url = (target or "").strip()
    if not url:
        _log("warning", "tech: empty target")
        return findings
    if "://" not in url:
        url = "https://" + url

    try:
        status, headers, body, final_url = fetch(url, timeout=FETCH_TIMEOUT)
    except Exception as exc:
        _log("warning", "tech: fetch failed for %s: %s" % (url, exc))
        return findings
    if not status:
        _log("info", "tech: no response from %s" % url)
        return findings

    text = _to_text(body)[:BODY_SCAN_LIMIT]
    headers = _headers_lower(headers)

    # 1. headers: X-Powered-By / Via / WAF-CDN
    header_tech, server_value, waf_hits = _detect_from_headers(headers)
    for title, evidence in header_tech:
        findings.append(
            make_finding(
                module=NAME, target=url, severity="info", confidence="strong",
                title=title,
                description="Technology disclosed in an HTTP response header.",
                evidence=evidence, cwe=None, remediation=None,
            )
        )
    for waf_name, marker in waf_hits:
        findings.append(
            make_finding(
                module=NAME, target=url, severity="info", confidence="strong",
                title="WAF/CDN detected: %s" % waf_name,
                description=(
                    "Response carries %s signatures, indicating traffic is "
                    "filtered or cached in front of the origin." % waf_name
                ),
                evidence="header/server marker: %r" % marker,
                cwe=None, remediation=None,
            )
        )

    # 2. Server header version disclosure
    if server_value:
        if VERSION_RE.search(server_value):
            findings.append(
                make_finding(
                    module=NAME, target=url, severity="low", confidence="strong",
                    title="Server version disclosed",
                    description=(
                        "The Server response header reveals the software and "
                        "its version, which helps an attacker pick exploits."
                    ),
                    evidence="Server: %s" % server_value.strip(),
                    cwe="CWE-200",
                    remediation=(
                        "Strip or genericize the Server header at the "
                        "web server or reverse proxy."
                    ),
                )
            )
        else:
            findings.append(
                make_finding(
                    module=NAME, target=url, severity="info", confidence="strong",
                    title="Technology: %s (server banner)" % server_value.strip(),
                    description="Server banner seen in the Server response header.",
                    evidence="Server: %s" % server_value.strip(),
                    cwe=None, remediation=None,
                )
            )

    # 3. body markers: JS libraries, frameworks, CMS
    body_tech, generator = _detect_from_body(text)
    if generator:
        body_tech.append(
            (generator, "CMS/framework",
             "meta generator tag: %s" % generator)
        )
    for tech_name, kind, evidence in body_tech:
        findings.append(
            make_finding(
                module=NAME, target=url, severity="info", confidence="strong",
                title="Technology: %s" % tech_name,
                description="Detected %s from page content markers." % kind,
                evidence=evidence, cwe=None, remediation=None,
            )
        )

    # 4. favicon hash (matchable against known-technology hash databases)
    favicon_hash = _favicon_md5(url)
    if favicon_hash:
        findings.append(
            make_finding(
                module=NAME, target=url, severity="info", confidence="strong",
                title="Favicon fingerprint",
                description=(
                    "MD5 hash of /favicon.ico; match it against public "
                    "favicon-hash databases to identify the underlying "
                    "technology."
                ),
                evidence="md5:%s" % favicon_hash,
                cwe=None, remediation=None,
            )
        )

    _log("info", "tech: %s -> %d findings" % (url, len(findings)))
    return findings
