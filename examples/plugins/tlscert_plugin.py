"""Example PENTRIX ARSENAL plugin: TLS certificate inspector.

Copy this file to ~/.arsenal/plugins/tlscert_plugin.py and it becomes a
first-class module: `arsenal scan <target> --module tlscert`.

Opens a TLS handshake (stdlib ssl, no HTTP request to the app) and reports
certificate expiry, weak signature algorithms, and hostname mismatch.

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

NAME = "tlscert"
DESCRIPTION = "Inspect the TLS certificate: expiry, weak signatures, hostname match"
TARGET_KIND = "url"
INTRUSIVE = False
VERSION = "1.0.0"

WEAK_SIGS = ("md5", "sha1")


def run(target, ctx):
    import socket
    import ssl
    from datetime import datetime, timezone
    from urllib.parse import urlparse
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
        if parts.scheme != "https" or not parts.hostname:
            return findings
        host = parts.hostname
        if ctx.scope is not None and not ctx.scope.contains(host):
            _log("warning", "tlscert: %s out of scope" % host)
            return findings
        port = parts.port or 443
        context = ssl.create_default_context()
        # We inspect the presented cert ourselves; verification failures are
        # findings, not fatal errors.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        if not cert:
            return findings
        issues = []
        evidence = []
        not_after = cert.get("notAfter")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expiry = expiry.replace(tzinfo=timezone.utc)
                days = (expiry - datetime.now(timezone.utc)).days
                evidence.append("notAfter=%s (%d days)" % (not_after, days))
                if days < 0:
                    issues.append("certificate EXPIRED %d days ago" % -days)
                elif days < 14:
                    issues.append("certificate expires in %d days" % days)
            except ValueError:
                pass
        sig = ""
        for key in ("signatureAlgorithm",):
            if cert.get(key):
                sig = str(cert[key]).lower()
        if any(w in sig for w in WEAK_SIGS):
            issues.append("weak signature algorithm: %s" % sig)
            evidence.append("signatureAlgorithm=%s" % sig)
        names = set()
        for rdn in cert.get("subject", ()):
            for attr in rdn:
                if attr[0] == "commonName":
                    names.add(attr[1])
        for san_type, san_value in cert.get("subjectAltName", ()):
            if san_type == "DNS":
                names.add(san_value)
        evidence.append("names=%s" % ", ".join(sorted(names)))
        host_ok = any(
            n == host or (n.startswith("*.") and host.endswith(n[1:]))
            for n in names
        )
        if names and not host_ok:
            issues.append("hostname %s not covered by certificate" % host)
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        evidence.append("issuer=%s" % issuer.get("commonName", "?"))
        severity = "medium" if any("EXPIRED" in i or "not covered" in i
                                   for i in issues) else ("low" if issues else "info")
        if issues or True:  # always report the cert baseline once
            findings.append(make_finding(
                module=NAME,
                target=target,
                severity=severity,
                confidence="strong",
                title="TLS certificate: %s" % ("; ".join(issues) if issues
                                               else "no issues found"),
                description="TLS handshake with %s:%d presented a "
                            "certificate issued to %s." % (
                                host, port, ", ".join(sorted(names)) or "?"),
                evidence="\n".join(evidence),
                url=target,
                remediation="Renew before expiry, use SHA-256+ signatures, "
                            "and ensure the SAN list covers every served hostname.",
            ))
    except Exception as exc:
        _log("warning", "tlscert plugin failed on %s: %s" % (target, exc))
    return findings
