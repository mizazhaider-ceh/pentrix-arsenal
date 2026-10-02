"""Example PENTRIX ARSENAL plugin: robots.txt analyzer.

Copy this file to ~/.arsenal/plugins/robots_plugin.py and it becomes a
first-class module: `arsenal scan <target> --module robots` and it shows
up in `arsenal plugins` and `arsenal scan --all`.

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

NAME = "robots"
DESCRIPTION = "Fetch robots.txt and flag sensitive disallowed paths"
TARGET_KIND = "url"
INTRUSIVE = False

SENSITIVE_HINTS = (
    "admin", "backup", "config", "db", "debug", "dev", "internal",
    "private", "secret", "staging", "test", ".git", ".env", "wp-admin",
)


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
        base = "%s://%s" % (parts.scheme, parts.netloc)
        if ctx.scope is not None and not ctx.scope.contains(base):
            _log("warning", "robots: %s out of scope" % base)
            return findings
        status, _headers, body, _final = fetch(
            urljoin(base, "/robots.txt"), timeout=10, ctx=ctx)
        if status != 200 or not body:
            return findings
        text = body.decode("utf-8", errors="replace")
        interesting = []
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith(("disallow:", "allow:")):
                path = line.split(":", 1)[1].strip()
                if not path or path == "/":
                    continue
                interesting.append(line)
        if not interesting:
            return findings
        sensitive = [l for l in interesting
                     if any(h in l.lower() for h in SENSITIVE_HINTS)]
        severity = "low" if sensitive else "info"
        findings.append(make_finding(
            module=NAME,
            target=base,
            severity=severity,
            confidence="strong",
            title="robots.txt exposes %d disallowed path(s)" % len(interesting),
            description="robots.txt lists %d disallowed path(s), of which %d "
                        "look sensitive. Disallowed paths often hint at admin "
                        "panels, backups, or staging areas worth reviewing."
                        % (len(interesting), len(sensitive)),
            evidence="\n".join(interesting[:10]),
            remediation="Review whether each disallowed path should be "
                        "reachable at all; do not rely on robots.txt for "
                        "access control.",
        ))
    except Exception as exc:
        _log("warning", "robots plugin failed on %s: %s" % (target, exc))
    return findings
