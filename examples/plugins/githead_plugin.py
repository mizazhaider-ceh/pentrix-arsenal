"""Example PENTRIX ARSENAL plugin: exposed .git/HEAD detector.

Copy this file to ~/.arsenal/plugins/githead_plugin.py and it becomes a
first-class module: `arsenal scan <target> --module githead`.

Fetches /.git/HEAD (a single safe GET). A 200 response with a ref line
means the repository metadata is exposed, which usually allows full
source reconstruction.

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

NAME = "githead"
DESCRIPTION = "Detect exposed /.git/HEAD (source-code disclosure primitive)"
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
            _log("warning", "githead: %s out of scope" % parts.hostname)
            return findings
        git_url = urljoin(target, "/.git/HEAD")
        status, _headers, body, _final = fetch(git_url, timeout=10, ctx=ctx)
        if status != 200 or not body:
            return findings
        text = body.decode("utf-8", errors="replace").strip()
        if not text.startswith("ref:"):
            return findings
        findings.append(make_finding(
            module=NAME,
            target=target,
            severity="high",
            confidence="strong",
            title="Exposed .git/HEAD discloses repository metadata",
            description="/.git/HEAD is publicly reachable and points at %s. "
                        "Exposed git metadata typically allows reconstructing "
                        "the full source tree (objects, config, logs), "
                        "leaking secrets and logic." % text,
            evidence=text[:200],
            url=git_url,
            cwe="CWE-538",
            remediation="Block /.git at the web server (return 404/403), "
                        "deploy from clean build artifacts instead of git "
                        "checkouts, and rotate any secrets present in history.",
        ))
    except Exception as exc:
        _log("warning", "githead plugin failed on %s: %s" % (target, exc))
    return findings
