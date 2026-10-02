"""Example PENTRIX ARSENAL plugin: security.txt contact file check.

Copy this file to ~/.arsenal/plugins/securitytxt_plugin.py and it becomes a
first-class module: `arsenal scan <target> --module securitytxt`.

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

NAME = "securitytxt"
DESCRIPTION = "Check /.well-known/security.txt for a vulnerability disclosure contact"
TARGET_KIND = "url"
INTRUSIVE = False
VERSION = "1.0.0"


def run(target, ctx):
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
            _log("warning", "securitytxt: %s out of scope" % parts.hostname)
            return findings
        for path in ("/.well-known/security.txt", "/security.txt"):
            status, _headers, body, _final = fetch(
                urljoin(target, path), timeout=10, ctx=ctx)
            if status != 200 or not body:
                continue
            text = body.decode("utf-8", errors="replace")
            if "contact:" not in text.lower():
                continue
            contacts = [l.strip() for l in text.splitlines()
                        if l.strip().lower().startswith("contact:")]
            findings.append(make_finding(
                module=NAME,
                target=target,
                severity="info",
                confidence="strong",
                title="security.txt disclosure contact published (%s)" % path,
                description="The site publishes a security.txt file with %d "
                            "contact line(s). Useful for responsible "
                            "disclosure; its absence is not a vulnerability."
                            % len(contacts),
                evidence="\n".join(contacts[:5]) or text[:400],
                url=urljoin(target, path),
                remediation="Keep the contact details current and monitor "
                            "the listed channels.",
            ))
            break
    except Exception as exc:
        _log("warning", "securitytxt plugin failed on %s: %s" % (target, exc))
    return findings
