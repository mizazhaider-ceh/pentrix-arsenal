"""Example PENTRIX ARSENAL plugin: HTTP method enumeration.

Copy this file to ~/.arsenal/plugins/httpmethods_plugin.py and it becomes a
first-class module: `arsenal scan <target> --module httpmethods`.

Sends a single OPTIONS request and reports the methods the server claims
to support, flagging risky ones (TRACE, TRACK, or unexpected PUT/DELETE).

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

NAME = "httpmethods"
DESCRIPTION = "Enumerate allowed HTTP methods via OPTIONS and flag risky ones"
TARGET_KIND = "url"
INTRUSIVE = False
VERSION = "1.0.0"

RISKY = {"TRACE", "TRACK", "PUT", "DELETE", "CONNECT"}


def run(target, ctx):
    from urllib.parse import urlparse
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
            _log("warning", "httpmethods: %s out of scope" % parts.hostname)
            return findings
        status, headers, _body, _final = fetch(
            target, timeout=10, ctx=ctx, method="OPTIONS")
        allow = ""
        for key, value in headers.items():
            if key.lower() == "allow":
                allow = value
                break
        if not allow:
            return findings
        methods = sorted({m.strip().upper() for m in allow.split(",") if m.strip()})
        risky = sorted(set(methods) & RISKY)
        severity = "low" if risky else "info"
        findings.append(make_finding(
            module=NAME,
            target=target,
            severity=severity,
            confidence="strong",
            title="HTTP methods allowed: %s" % ", ".join(methods),
            description="The server advertises these HTTP methods via the "
                        "Allow header: %s.%s" % (
                            ", ".join(methods),
                            " Risky methods enabled: %s." % ", ".join(risky)
                            if risky else ""),
            evidence="Allow: %s" % allow,
            url=target,
            remediation="Disable unneeded methods at the web server / WAF "
                        "layer; TRACE/TRACK are rarely required.",
        ))
    except Exception as exc:
        _log("warning", "httpmethods plugin failed on %s: %s" % (target, exc))
    return findings
