"""Suspicious URL (phishing indicator) module.

Scores a URL against a set of phishing heuristics and emits one finding
per triggered check. Purely local analysis, no network traffic.

Adapted from pentrix-phish (analyze / heuristic checks).
"""

import re
from urllib.parse import urlparse

from arsenal.findings import make_finding

NAME = "phish"
DESCRIPTION = "Analyze a URL for phishing indicators (one finding per check)."
TARGET_KIND = "url"
INTRUSIVE = False

SUSPICIOUS_KEYWORDS = (
    "login", "verify", "secure", "account", "update",
    "paypal", "bank", "signin", "confirm", "free", "bonus",
)

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "shorturl.at",
    "cutt.ly", "rb.gy", "s.id", "tiny.cc",
}

IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")

# Finding severity per triggered check, per the module spec:
#   high   -> punycode, at_sign, ip_host
#   medium -> url_shortener, hyphen_heavy, suspicious_keywords (many hits)
#   low    -> many_subdomains, suspicious_keywords (few hits), no_https,
#             long_url, nonstandard_port
_SEVERITY = {
    "punycode": "high",
    "at_sign": "high",
    "ip_host": "high",
    "url_shortener": "medium",
    "hyphen_heavy": "medium",
    "many_subdomains": "low",
    "no_https": "low",
    "long_url": "low",
    "nonstandard_port": "low",
}

_CONFIDENCE = {
    "punycode": "high",
    "at_sign": "high",
    "ip_host": "high",
    "url_shortener": "high",
    "hyphen_heavy": "medium",
    "many_subdomains": "medium",
    "suspicious_keywords": "medium",
    "no_https": "high",
    "long_url": "low",
    "nonstandard_port": "medium",
}

_TITLES = {
    "punycode": "Phishing indicator: punycode/IDN homograph risk",
    "at_sign": "Phishing indicator: at-sign host confusion",
    "ip_host": "Phishing indicator: raw IP host",
    "url_shortener": "Phishing indicator: URL shortener hides destination",
    "hyphen_heavy": "Phishing indicator: lookalike hyphen-heavy domain",
    "many_subdomains": "Phishing indicator: stacked subdomains",
    "suspicious_keywords": "Phishing indicator: lure keywords in URL",
    "no_https": "Phishing indicator: no HTTPS",
    "long_url": "Phishing indicator: unusually long URL",
    "nonstandard_port": "Phishing indicator: non-standard port",
}

_REMEDIATIONS = {
    "punycode": "Verify the real domain through an independent channel before visiting or entering credentials.",
    "at_sign": "Treat everything after the last @ as the true host; verify the destination before following the link.",
    "ip_host": "Do not enter credentials on a raw-IP site; confirm the legitimate domain of the service independently.",
    "url_shortener": "Expand the short link (e.g. with a URL expander) to inspect the real destination first.",
    "hyphen_heavy": "Compare the domain character by character against the brand's official domain.",
    "many_subdomains": "Read the URL right-to-left to find the actual registered domain before trusting it.",
    "suspicious_keywords": "Be skeptical of urgency/trust language in links; navigate to the service directly instead of clicking.",
    "no_https": "Avoid submitting credentials or sensitive data over an unencrypted connection.",
    "long_url": "Inspect the full URL, especially the host portion, before clicking.",
    "nonstandard_port": "Treat links on unusual ports with suspicion and verify them out of band.",
}


def parse_url(raw):
    """Parse a raw URL string. Raises ValueError when unusable."""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("empty URL")
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlparse(raw)
    if not parsed.hostname:
        raise ValueError("could not determine a hostname")
    return parsed


def is_ip_literal(host):
    """True when the host is a raw IPv4 (or plausible IPv6) literal."""
    if not host:
        return False
    if IPV4_RE.match(host):
        return all(0 <= int(octet) <= 255 for octet in host.split("."))
    if ":" in host and IPV6_RE.match(host):
        return True
    return False


def check_punycode(raw, parsed, findings):
    if "xn--" in (parsed.hostname or "").lower():
        findings.append({
            "name": "punycode",
            "detail": "Host contains 'xn--' (punycode/IDN). Real brands rarely do this; "
                      "it is a classic homograph trick.",
        })


def check_at_sign(raw, parsed, findings):
    if "@" in raw:
        findings.append({
            "name": "at_sign",
            "detail": "'@' found in the URL. Everything before it is treated as "
                      "credentials, so attackers use it to disguise the real host.",
        })


def check_ip_host(raw, parsed, findings):
    if is_ip_literal(parsed.hostname):
        findings.append({
            "name": "ip_host",
            "detail": "Host is a raw IP address (%s). Legitimate sites almost "
                      "always use a domain name." % parsed.hostname,
        })


def check_nonstandard_port(raw, parsed, findings):
    port = parsed.port
    if port is None:
        return
    default = {"http": 80, "https": 443}.get(parsed.scheme.lower())
    if default is not None and port != default:
        findings.append({
            "name": "nonstandard_port",
            "detail": "Non-standard port %d for %s (normally %d)." % (port, parsed.scheme, default),
        })


def check_many_subdomains(raw, parsed, findings):
    labels = [p for p in (parsed.hostname or "").lower().split(".") if p]
    subdomain_count = max(0, len(labels) - 2)
    if subdomain_count > 3:
        findings.append({
            "name": "many_subdomains",
            "detail": "%d subdomains (over the 3 threshold). Attackers stack "
                      "subdomains so the real domain sits far from the brand name." % subdomain_count,
        })


def check_keywords(raw, parsed, findings):
    haystack = raw.lower()
    hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in haystack]
    if hits:
        findings.append({
            "name": "suspicious_keywords",
            "detail": "Suspicious keywords found: %s. Phishing pages use them to "
                      "look official or create urgency." % ", ".join(hits),
            "hits": len(hits),
        })


def check_long_url(raw, parsed, findings):
    if len(raw) > 100:
        findings.append({
            "name": "long_url",
            "detail": "URL is %d characters (over 100). Long URLs help hide the "
                      "real host from a quick glance." % len(raw),
        })


def check_hyphen_heavy(raw, parsed, findings):
    host = (parsed.hostname or "").lower()
    hyphens = host.count("-")
    if hyphens >= 3:
        findings.append({
            "name": "hyphen_heavy",
            "detail": "%d hyphens in '%s'. Legit brands rarely hyphenate this "
                      "much; phishers glue brand names to lures with dashes." % (hyphens, host),
        })


def check_no_https(raw, parsed, findings):
    if parsed.scheme.lower() != "https":
        findings.append({
            "name": "no_https",
            "detail": "URL uses '%s' instead of HTTPS. Credentials sent over it "
                      "can be read in transit." % (parsed.scheme or "no scheme"),
        })


def check_shortener(raw, parsed, findings):
    host = (parsed.hostname or "").lower()
    if host in URL_SHORTENERS or any(host.endswith("." + s) for s in URL_SHORTENERS):
        findings.append({
            "name": "url_shortener",
            "detail": "Host '%s' is a known URL shortener. The link hides where "
                      "it really goes." % host,
        })


HEURISTICS = (
    check_punycode,
    check_at_sign,
    check_ip_host,
    check_nonstandard_port,
    check_many_subdomains,
    check_keywords,
    check_long_url,
    check_hyphen_heavy,
    check_no_https,
    check_shortener,
)


def analyze(raw):
    """Run every heuristic against one URL.

    Adapted from pentrix-phish. Returns a dict with url, host, score,
    verdict and the list of triggered findings.
    """
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("empty URL")
    parsed = parse_url(raw)
    findings = []
    for heuristic in HEURISTICS:
        heuristic(raw, parsed, findings)
    score = min(100, sum(f.get("points", 10) for f in findings))
    if score >= 60:
        verdict = "HIGH"
    elif score >= 30:
        verdict = "MEDIUM"
    else:
        verdict = "LOW"
    return {
        "url": raw,
        "host": parsed.hostname,
        "score": score,
        "verdict": verdict,
        "findings": findings,
    }


def _severity_for(check):
    name = check["name"]
    if name == "suspicious_keywords":
        return "medium" if check.get("hits", 1) >= 3 else "low"
    return _SEVERITY.get(name, "low")


def run(target, ctx):
    """Analyze target URL; return one finding per triggered heuristic check.

    Returns a single info finding when nothing triggered, or when the URL
    cannot be parsed.
    """
    try:
        analysis = analyze(target)
    except (ValueError, Exception) as exc:
        return [make_finding(
            module=NAME,
            target=target,
            severity="info",
            confidence="low",
            title="URL could not be analyzed",
            description="The URL failed to parse: %s" % exc,
            evidence="url: %s" % target,
            cwe=None,
            remediation="Provide a well-formed URL (a bare host is accepted).",
        )]

    findings = []
    for check in analysis["findings"]:
        name = check["name"]
        findings.append(make_finding(
            module=NAME,
            target=target,
            severity=_severity_for(check),
            confidence=_CONFIDENCE.get(name, "low"),
            title=_TITLES.get(name, "Phishing indicator: %s" % name),
            description="%s Phishing risk score for this URL: %d/100 (%s)."
                        % (check["detail"], analysis["score"], analysis["verdict"]),
            evidence="url: %s | check: %s | host: %s"
                     % (analysis["url"], name, analysis["host"]),
            cwe=None,
            remediation=_REMEDIATIONS.get(name, "Verify the link through an independent channel."),
        ))
    if not findings:
        findings.append(make_finding(
            module=NAME,
            target=target,
            severity="info",
            confidence="high",
            title="No phishing indicators found",
            description="None of the phishing heuristics triggered for this URL "
                        "(score 0/100). This is a hint, not a verdict of safety.",
            evidence="url: %s | host: %s" % (analysis["url"], analysis["host"]),
            cwe=None,
            remediation="None required; stay alert for other attack vectors.",
        ))
    return findings
