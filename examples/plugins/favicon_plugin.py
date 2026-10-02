"""Example PENTRIX ARSENAL plugin: favicon hash for technology ID.

Copy this file to ~/.arsenal/plugins/favicon_plugin.py and it becomes a
first-class module: `arsenal scan <target> --module favicon`.

Fetches /favicon.ico, hashes it (MD5, the Shodan favicon-hash convention),
and reports the hash so the analyst can pivot it against favicon-hash
databases to identify the underlying technology.

Plugin contract:
    NAME         unique module name (used on the CLI)
    DESCRIPTION  one-line help text
    TARGET_KIND  "domain", "url", "ip", "hash", "path", "keyword" or "token"
    INTRUSIVE    True if the plugin performs active intrusive probing
    run(target, ctx) -> list of finding dicts

Finding dict keys: module, target, severity (info/low/medium/high/critical),
confidence (proven/strong/review), title, description, evidence, cwe,
remediation. Never print from run(); use ctx.log. Never let exceptions
escape; catch per-target errors and return what you have.
"""

NAME = "favicon"
DESCRIPTION = "Hash the site favicon (MD5) for technology fingerprint pivoting"
TARGET_KIND = "url"
INTRUSIVE = False
VERSION = "1.0.0"


def run(target, ctx):
    import base64
    import hashlib
    from urllib.parse import urljoin, urlparse
    from arsenal.http import fetch
    from arsenal.findings import make_finding

    findings = []
    log = getattr(ctx, "log", None)

    def _log(level, msg):
        try:
            if log is not None:
                getattr(log, level)(msg)
        except Exception:
            pass

    try:
        parts = urlparse(target)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return findings
        if ctx.scope is not None and not ctx.scope.contains(parts.hostname):
            _log("warning", "favicon: %s out of scope" % parts.hostname)
            return findings
        favicon_url = urljoin(target, "/favicon.ico")
        status, _headers, body, _final = fetch(favicon_url, timeout=10, ctx=ctx)
        if status != 200 or not body:
            return findings
        md5 = hashlib.md5(body).hexdigest()
        # Shodan-style hash: md5 of the base64-encoded icon.
        shodan_hash = hashlib.md5(
            base64.encodebytes(body).decode().encode()).hexdigest()
        findings.append(make_finding(
            module=NAME,
            target=target,
            severity="info",
            confidence="strong",
            title="favicon hash md5:%s" % md5,
            description="The site's favicon hashes to md5 %s (%d bytes). "
                        "Pivot this hash against favicon-hash databases "
                        "(e.g. Shodan's http.favicon.hash) to identify the "
                        "underlying technology or framework." % (md5, len(body)),
            evidence="md5=%s\nshodan_style=%s\nurl=%s" % (
                md5, shodan_hash, favicon_url),
            url=favicon_url,
            remediation="A custom favicon is cosmetic; the value here is "
                        "reconnaissance, no fix needed.",
        ))
    except Exception as exc:
        _log("warning", "favicon plugin failed on %s: %s" % (target, exc))
    return findings
