"""Report generator for PENTRIX ARSENAL.

generate(target, ctx, fmt="html", out=None) -> filepath
  fmt="html": professional single-file HTML report (inline CSS, dark
      header, no external dependencies). Includes an executive summary
      (counts, top risks, generated narrative), an ATTACK SURFACE GRAPH
      section (vendored graph.js, works offline from file://), findings
      grouped by severity then module with triage verdict and confidence
      badges, cross-target grouping (same title across subdomains merged
      with an affected-hosts list), a methodology footer and an ethical
      disclaimer. Written to <workspace>/report.html by default.
  fmt="yeswehack" | fmt="hackerone": markdown submission templates with
      Title, Description, Impact, Reproduction steps and Remediation per
      finding (top 10 by severity). Written to <workspace>/report-<fmt>.md.

add_parsers(sub) registers `arsenal report <target>
[--format html|yeswehack|hackerone] [--out PATH]`; dispatch(args, ctx)
runs it. Never crashes on missing data.
"""

import html as _html
import json
import os
from collections import Counter
from datetime import datetime

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}


def _ws_dir(ctx, target) -> str:
    ws = getattr(ctx, "workspace", None)
    if ws is not None and hasattr(ws, "path"):
        try:
            return ws.path(target)
        except Exception:
            pass
    return os.path.expanduser(os.path.join("~", ".arsenal", "workspace", str(target)))


def _profile(ctx) -> str:
    cfg = getattr(ctx, "config", None)
    if isinstance(cfg, dict):
        return str(cfg.get("profile", "default"))
    get = getattr(cfg, "get", None)
    if callable(get):
        try:
            return str(get("profile", "default"))
        except Exception:
            pass
    return "default"


def _load_findings(ctx, target) -> list:
    path = os.path.join(_ws_dir(ctx, target), "findings.json")
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _load_scan(ctx, target, name):
    """Best-effort scan artifact loader; returns dict or None."""
    ws = getattr(ctx, "workspace", None)
    if ws is not None and hasattr(ws, "load_scan"):
        try:
            data = ws.load_scan(target, name)
            if data:
                return data
        except Exception:
            pass
    for candidate in (name, os.path.join("scans", name)):
        path = os.path.join(_ws_dir(ctx, target), candidate)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            except Exception:
                return None
    return None


def _sev(finding) -> str:
    try:
        s = str(finding.get("severity", "info")).lower()
    except Exception:
        s = "info"
    return s if s in _SEV_RANK else "info"


def _conf(finding) -> str:
    try:
        return str(finding.get("confidence", "medium")).lower()
    except Exception:
        return "medium"


def _sort_key(finding):
    return (_SEV_RANK.get(_sev(finding), 4), _conf(finding) != "high",
            str(finding.get("title", "")))


# --------------------------------------------------------------------------
# Remediation library (per-finding guidance with code samples)
# --------------------------------------------------------------------------

# module -> (summary, language, code sample)
REMEDIATION = {
    "xss": (
        "Encode all untrusted data for its output context and deploy a strict "
        "Content-Security-Policy. Never build HTML by string concatenation.",
        "html",
        "<!-- context-aware output encoding (example: Python/Jinja2) -->\n"
        "<p>{{ user_input | e }}</p>\n\n"
        "<!-- strict CSP header -->\n"
        "Content-Security-Policy: default-src 'self'; script-src 'self';\n"
        "  object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    ),
    "sqli": (
        "Use parameterized queries or a vetted ORM everywhere. Never "
        "interpolate user input into SQL strings.",
        "python",
        "# parameterized query (psycopg2)\n"
        "cur.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))\n\n"
        "# NEVER do this:\n"
        "# cur.execute(\"SELECT * FROM users WHERE id = '%s'\" % user_id)",
    ),
    "ssti": (
        "Never render templates from user-controlled strings. If templates "
        "must be dynamic, use a logic-less sandbox with autoescaping.",
        "python",
        "# Jinja2 sandboxed environment\n"
        "from jinja2.sandbox import SandboxedEnvironment\n"
        "env = SandboxedEnvironment(autoescape=True)\n"
        "template = env.from_string(TRUSTED_TEMPLATE)  # never user input",
    ),
    "cors": (
        "Reflect only explicitly allowlisted origins, and never combine a "
        "reflected origin with Access-Control-Allow-Credentials: true.",
        "python",
        "ALLOWED = {\"https://app.example.com\"}\n"
        "origin = request.headers.get(\"Origin\")\n"
        "if origin in ALLOWED:\n"
        "    resp.headers[\"Access-Control-Allow-Origin\"] = origin\n"
        "    resp.headers[\"Vary\"] = \"Origin\"",
    ),
    "headers": (
        "Send a complete set of security headers on every response.",
        "http",
        "Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
        "Content-Security-Policy: default-src 'self'; object-src 'none';\n"
        "  base-uri 'self'; frame-ancestors 'none'\n"
        "X-Content-Type-Options: nosniff\n"
        "Referrer-Policy: strict-origin-when-cross-origin\n"
        "Permissions-Policy: camera=(), microphone=(), geolocation=()",
    ),
    "redirect": (
        "Validate redirect targets against an allowlist of relative paths "
        "or known hosts. Never redirect to a raw request parameter.",
        "python",
        "from urllib.parse import urlparse\n"
        "target = request.args.get(\"next\", \"/\")\n"
        "if urlparse(target).netloc:  # absolute URL -> reject\n"
        "    target = \"/\"\n"
        "return redirect(target)",
    ),
    "graphql": (
        "Disable introspection in production, enforce query depth/cost "
        "limits, and require authentication for sensitive fields.",
        "javascript",
        "// graphql-yoga / envelop style depth limiting\n"
        "import { useDepthLimit } from '@envelop/depth-limit'\n"
        "const getEnveloped = envelop({\n"
        "  plugins: [useDepthLimit({ maxDepth: 7 })],\n"
        "})\n"
        "// introspection: false in production builds",
    ),
    "jwt": (
        "Verify signatures server-side with a single trusted algorithm, "
        "reject 'none', and keep token lifetimes short.",
        "python",
        "import jwt\n"
        "payload = jwt.decode(token, PUBLIC_KEY, algorithms=[\"RS256\"],\n"
        "                   options={\"require\": [\"exp\", \"iat\"]})\n"
        "# never accept algorithms=[\"none\"] and never trust the kid header blindly",
    ),
    "oauth": (
        "Use an exact-match allowlist for redirect_uris, always send and "
        "verify a state (and PKCE) parameter, and never leak codes via the "
        "fragment to third parties.",
        "python",
        "ALLOWED_REDIRECTS = {\"https://app.example.com/callback\"}\n"
        "if redirect_uri not in ALLOWED_REDIRECTS:\n"
        "    abort(400)\n"
        "state = secrets.token_urlsafe(32)  # bind to the user session",
    ),
    "hostheader": (
        "Never build absolute URLs from the Host header. Configure the "
        "web server with an explicit server name and reject unknown hosts.",
        "nginx",
        "server {\n"
        "    listen 443 ssl;\n"
        "    server_name app.example.com;  # explicit, no wildcards\n"
        "    # password-reset links use a configured base URL, not $host\n"
        "}",
    ),
    "secrets": (
        "Revoke every exposed secret, move secrets to a vault or env-based "
        "config, and add pre-commit secret scanning.",
        "bash",
        "# rotate immediately, then stop committing secrets\n"
        "git rm --cached .env && echo '.env' >> .gitignore\n"
        "# store at runtime instead:\n"
        "export STRIPE_KEY=\"sk_live_...\"  # via your secret manager",
    ),
    "jssecrets": (
        "Same as exposed secrets: revoke, rotate, and never ship API keys "
        "in client-side bundles. Use backend proxies for keyed calls.",
        "javascript",
        "// bad:  const key = \"sk_live_...\";\n"
        "// good: call your own backend, which holds the key server-side\n"
        "const data = await fetch(\"/api/internal/resource\").then(r => r.json());",
    ),
    "cachepoison": (
        "Do not cache responses keyed on untrusted input. Mark dynamic "
        "content Cache-Control: no-store and strip unkeyed headers at the "
        "cache layer.",
        "http",
        "Cache-Control: no-store, must-revalidate\n"
        "# CDN rule: only cache when the response has no Set-Cookie and the\n"
        "# request carries no unkeyed headers",
    ),
    "ppollution": (
        "Use null-prototype objects or Maps for merging user input, and "
        "freeze Object.prototype-adjacent paths in recursive merge code.",
        "javascript",
        "const store = Object.create(null);  // no prototype to pollute\n"
        "// or harden merges:\n"
        "if ([\"__proto__\", \"constructor\", \"prototype\"].includes(key)) continue;",
    ),
    "tech": (
        "Keep components patched and hide version banners where possible. "
        "Track CVEs for every versioned component in the stack.",
        "bash",
        "# example: hide nginx version\n"
        "# nginx.conf: server_tokens off;\n"
        "# then subscribe to vendor security lists for each component",
    ),
    "cve": (
        "Patch to the fixed version (or apply the vendor workaround), then "
        "re-test. Prioritize CVEs with public exploits affecting reachable "
        "services.",
        "bash",
        "# upgrade the affected package and verify\n"
        "apt-get update && apt-get install --only-upgrade <package>\n"
        "dpkg -l | grep <package>  # confirm the fixed version",
    ),
    "phish": (
        "If this is your own domain: deploy SPF, DKIM and DMARC with a "
        "reject policy, and monitor lookalike registrations.",
        "dns",
        "_dmarc.example.com.  TXT  \"v=DMARC1; p=reject; rua=mailto:dmarc@example.com\"",
    ),
    "wordlist": (
        "Remove or protect the discovered path: authentication, IP "
        "allowlisting, or removal if it is not needed.",
        "nginx",
        "location /internal/ {\n"
        "    allow 10.0.0.0/8;\n"
        "    deny all;\n"
        "    auth_basic \"restricted\";\n"
        "    auth_basic_user_file /etc/nginx/.htpasswd;\n"
        "}",
    ),
    "redirect_mod": (
        "See 'redirect': allowlist redirect targets and reject absolute URLs.",
        "python",
        "if urlparse(target).netloc:\n    target = \"/\"",
    ),
}


def _remediation_for(finding):
    """Return (summary, language, code) for a finding.

    Prefers the finding's own remediation text, then the per-module
    library, then a generic fallback.
    """
    own = str(finding.get("remediation") or "").strip()
    module = str(finding.get("module") or "").lower()
    lib = REMEDIATION.get(module)
    if lib and not own:
        return lib
    if lib and own:
        return (own, lib[1], lib[2])
    if own:
        return (own, "", "")
    return (
        "Investigate the finding, confirm it manually, and apply the "
        "vendor or framework recommended fix for the affected component.",
        "", "",
    )


def esc(value) -> str:
    return _html.escape("" if value is None else str(value), quote=True)


# --------------------------------------------------------------------------
# Attack surface graph
# --------------------------------------------------------------------------

def _build_graph(target, ctx, findings) -> dict:
    """Nodes: domain -> subdomains -> ips -> ports -> tech -> findings."""
    nodes = [{"id": str(target), "label": str(target), "kind": "domain",
              "meta": {"role": "assessment target"}}]
    links = []
    seen = {str(target)}

    def add(node_id, label, kind, parent, meta=None):
        node_id = str(node_id)
        if node_id not in seen:
            nodes.append({"id": node_id, "label": str(label), "kind": kind,
                          "meta": meta or {}})
            seen.add(node_id)
        if parent:
            links.append({"a": str(parent), "b": node_id})

    # Recon: subdomains and resolved IPs
    for scan_name in ("recon.json", "subdomains.json"):
        recon = _load_scan(ctx, target, scan_name)
        if isinstance(recon, dict):
            subs = recon.get("subdomains") or recon.get("hosts") or []
            for sub in subs if isinstance(subs, list) else []:
                name = sub.get("host") if isinstance(sub, dict) else sub
                if not name:
                    continue
                add("sub:%s" % name, name, "subdomain", target,
                    {"source": "recon"})
                ips = sub.get("ips", []) if isinstance(sub, dict) else []
                for ip in ips:
                    add("ip:%s" % ip, ip, "ip", "sub:%s" % name,
                        {"resolved_from": name})
            break

    # Port scan results
    for scan_name in ("ports.json", "portscan.json"):
        ports = _load_scan(ctx, target, scan_name)
        if isinstance(ports, dict):
            for host, plist in ports.items():
                host_id = "sub:%s" % host if ("sub:%s" % host) in seen else str(host)
                if host_id not in seen:
                    add(host_id, host, "subdomain", target, {"source": "ports"})
                for p in plist if isinstance(plist, list) else []:
                    port = p.get("port") if isinstance(p, dict) else p
                    if port is None:
                        continue
                    add("port:%s:%s" % (host, port), "port %s" % port, "port",
                        host_id, {"service": (p.get("service") if isinstance(p, dict) else "") or ""})
            break

    # Technology fingerprints
    for scan_name in ("tech.json", "technologies.json"):
        tech = _load_scan(ctx, target, scan_name)
        if isinstance(tech, dict):
            for host, tlist in tech.items():
                host_id = "sub:%s" % host if ("sub:%s" % host) in seen else str(host)
                if host_id not in seen:
                    add(host_id, host, "subdomain", target, {"source": "tech"})
                items = tlist if isinstance(tlist, list) else [tlist]
                for t in items:
                    name = t.get("name") if isinstance(t, dict) else t
                    if not name:
                        continue
                    version = t.get("version", "") if isinstance(t, dict) else ""
                    add("tech:%s:%s" % (host, name), "%s %s" % (name, version), "tech",
                        host_id, {"version": version})
            break

    # Findings attach to their host (or to the target root)
    for f in findings:
        host = str(f.get("target") or target)
        parent = "sub:%s" % host if ("sub:%s" % host) in seen else str(target)
        fid = "finding:%s:%s" % (host, f.get("id") or f.get("title"))
        add(fid, str(f.get("title", "finding"))[:48], "finding", parent,
            {"severity": _sev(f), "module": str(f.get("module", "")),
             "confidence": _conf(f),
             "verdict": str(f.get("verdict", "unreviewed"))})
    return {"nodes": nodes, "links": links}


def _graph_js() -> str:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "report_assets", "graph.js")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except Exception:
        return ""


# --------------------------------------------------------------------------
# HTML report
# --------------------------------------------------------------------------

_CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
       background: #0d1117; color: #dbe2f0; margin: 0; line-height: 1.55; }
header.top { background: linear-gradient(135deg, #0b1e3a, #12294d); padding: 34px 40px;
              border-bottom: 3px solid #2f81f7; }
header.top h1 { margin: 0 0 6px; font-size: 30px; letter-spacing: 1px; }
header.top .sub { color: #9fb3d1; font-size: 14px; }
main { max-width: 1100px; margin: 0 auto; padding: 28px 24px 60px; }
section { margin-bottom: 40px; }
h2 { font-size: 20px; border-bottom: 2px solid #2f81f7; padding-bottom: 8px;
     text-transform: uppercase; letter-spacing: 1px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
.card { background: #161b26; border: 1px solid #2a3348; border-radius: 8px; padding: 14px; }
.card .num { font-size: 30px; font-weight: 700; }
.card .lbl { color: #9fb3d1; font-size: 12px; text-transform: uppercase; }
.sev-critical { color: #ff5d5d; } .sev-high { color: #ff8a5c; }
.sev-medium { color: #ffb020; } .sev-low { color: #4cc38a; } .sev-info { color: #58a6ff; }
.narrative { background: #161b26; border-left: 4px solid #2f81f7; padding: 14px 18px;
              border-radius: 0 8px 8px 0; }
.finding { background: #161b26; border: 1px solid #2a3348; border-radius: 8px;
            padding: 18px 20px; margin-bottom: 16px; }
.finding h3 { margin: 0 0 8px; font-size: 17px; }
.badges { margin: 6px 0 10px; }
.badge { display: inline-block; font-size: 11px; font-weight: 700; text-transform: uppercase;
         letter-spacing: .5px; padding: 3px 10px; border-radius: 20px; margin-right: 6px; }
.badge.severity-critical { background: #5a1d1d; color: #ff8f8f; }
.badge.severity-high { background: #5a2f1d; color: #ffb08a; }
.badge.severity-medium { background: #5a4a1d; color: #ffd98a; }
.badge.severity-low { background: #1d5a38; color: #8affc1; }
.badge.severity-info { background: #1d3a5a; color: #8ac6ff; }
.badge.conf { background: #232b3d; color: #b8c4dc; border: 1px solid #3a4358; }
.badge.verdict { background: #2b2140; color: #c9a8ff; border: 1px solid #4a3a78; }
.meta { color: #9fb3d1; font-size: 13px; margin: 4px 0 10px; }
pre.evidence { background: #0a0e14; border: 1px solid #2a3348; border-radius: 6px;
               padding: 12px; overflow-x: auto; font-size: 12.5px; color: #c8d3e8; }
.hosts { color: #9fb3d1; font-size: 13px; margin: 6px 0; }
#attack-graph { width: 100%; height: 520px; background: #0a0e14;
                border: 1px solid #2a3348; border-radius: 8px; cursor: grab; }
#graph-detail { background: #161b26; border: 1px solid #2a3348; border-radius: 8px;
                padding: 12px 16px; margin-top: 10px; min-height: 60px; }
#graph-detail h3 { margin: 0 0 4px; font-size: 15px; }
#graph-detail dl { display: grid; grid-template-columns: 130px 1fr; gap: 4px 10px;
                   font-size: 13px; margin: 8px 0 0; }
#graph-detail dt { color: #9fb3d1; } #graph-detail dd { margin: 0; }
.g-kind { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #9fb3d1; }
.g-legend-item { margin-right: 14px; font-size: 13px; color: #9fb3d1; }
.g-dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 6px; }
.g-hint { color: #9fb3d1; font-size: 13px; margin: 0; }
#graph-legend { margin: 10px 0; }
footer { border-top: 1px solid #2a3348; margin-top: 30px; padding-top: 18px;
         color: #8a93a6; font-size: 12.5px; }
.disclaimer { background: #2a1d1d; border: 1px solid #5a2f2f; border-radius: 8px;
              padding: 12px 16px; font-size: 13px; color: #e8b8b8; margin-top: 16px; }
"""

_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pentrix Arsenal Report - {target}</title>
<style>{css}</style></head>
<body>
<header class="top">
  <h1>PENTRIX ARSENAL</h1>
  <div class="sub">Security assessment report &nbsp;|&nbsp; Target: <strong>{target}</strong>
  &nbsp;|&nbsp; {date} &nbsp;|&nbsp; Profile: {profile}</div>
</header>
<main>
<section><h2>Executive Summary</h2>
<div class="cards">{cards}</div>
<div class="narrative" style="margin-top:16px">{narrative}</div>
<h3 style="margin-top:18px">Top risks</h3>
{top_risks}
</section>
<section><h2>Attack Surface Graph</h2>
<div id="graph-legend"></div>
<svg id="attack-graph" viewBox="0 0 1400 700" preserveAspectRatio="xMidYMid meet"></svg>
<div id="graph-detail"></div>
<script>window.__ARSENAL_GRAPH__ = {graph_json};</script>
<script>{graph_js}</script>
</section>
<section><h2>Findings</h2>
{findings_html}
</section>
<section><h2>Methodology</h2>
<div class="narrative">{methodology}</div>
</section>
<footer>
<div>Generated by Pentrix Arsenal on {date}. Scope was limited to the authorized
target(s); results reflect point-in-time observations and should be revalidated
before remediation sign-off.</div>
<div class="disclaimer"><strong>Ethical disclaimer:</strong> this assessment was
performed under explicit authorization for the stated target only. Do not use
these techniques against systems you do not own or have written permission to
test. Findings are provided for defensive remediation purposes.</div>
</footer>
</main></body></html>
"""


def _narrative(target, findings, counts) -> str:
    total = len(findings)
    if not total:
        return ("<p>No findings were recorded for <strong>%s</strong> in this "
                "assessment run. This does not certify the target as secure; "
                "it only reflects the coverage and depth of the modules that "
                "were executed.</p>" % esc(target))
    mods = Counter(str(f.get("module", "general")) for f in findings)
    top_mod, top_mod_n = mods.most_common(1)[0]
    ordered = sorted(findings, key=_sort_key)
    top = ordered[0]
    s1 = ("Arsenal assessed <strong>%s</strong> and recorded <strong>%d</strong> "
          "finding(s): %d Critical, %d High, %d Medium, %d Low." % (
              esc(target), total, counts["critical"], counts["high"],
              counts["medium"], counts["low"]))
    s2 = ("The <strong>%s</strong> module was the most active with %d finding(s); "
          "the highest-ranked issue is <strong>%s</strong> (%s severity, %s "
          "confidence)." % (esc(top_mod), top_mod_n, esc(top.get("title")),
                             _sev(top).capitalize(), _conf(top).capitalize()))
    top3 = "; ".join(esc(f.get("title", "")) for f in ordered[:3])
    s3 = ("Immediate attention should go to: %s. Remediation guidance for each "
          "finding is listed below with its triage verdict." % top3)
    return "<p>%s</p><p>%s</p><p>%s</p>" % (s1, s2, s3)


def _finding_card(f, hosts=None) -> str:
    sev = _sev(f)
    verdict = str(f.get("verdict", "unreviewed") or "unreviewed")
    body = f.get("report_section") or f.get("description") or ""
    evidence = f.get("evidence") or ""
    remediation = f.get("remediation") or ""
    next_steps = f.get("next_steps") or ""
    rem_summary, rem_lang, rem_code = _remediation_for(f)
    parts = ['<div class="finding">']
    parts.append("<h3>%s</h3>" % esc(f.get("title", "(untitled)")))
    parts.append('<div class="badges">'
                 '<span class="badge severity-%s">%s</span>'
                 '<span class="badge conf">confidence: %s</span>'
                 '<span class="badge verdict">verdict: %s</span></div>' % (
                     sev, sev.upper(), esc(_conf(f)), esc(verdict)))
    parts.append('<div class="meta">Module: %s &nbsp;|&nbsp; CWE: %s &nbsp;|&nbsp; CRM: %s (%s)</div>' % (
        esc(f.get("module", "-")), esc(f.get("cwe", "-")),
        esc(f.get("id", "-")), esc(f.get("status", "found"))))
    if hosts:
        parts.append('<div class="hosts"><strong>Affected hosts (%d):</strong> %s</div>' % (
            len(hosts), esc(", ".join(hosts))))
    if body:
        parts.append("<p>%s</p>" % esc(body))
    if evidence:
        parts.append('<h4>Evidence</h4><pre class="evidence">%s</pre>' % esc(evidence))
    parts.append("<h4>Remediation</h4><p>%s</p>" % esc(remediation or rem_summary))
    if rem_code:
        parts.append('<pre class="evidence">%s</pre>' % esc(rem_code))
    if next_steps:
        parts.append("<h4>Next steps</h4><p>%s</p>" % esc(next_steps))
    parts.append("</div>")
    return "\n".join(parts)


def _grouped_findings_html(findings) -> str:
    """Group by severity, then module; merge identical titles across hosts."""
    if not findings:
        return "<p>No findings.</p>"
    # cross-target grouping: same normalized title -> one card, host list
    merged = {}
    order = []
    for f in findings:
        key = str(f.get("title", "")).strip().lower()
        host = str(f.get("target", "") or "")
        if key not in merged:
            merged[key] = {"finding": f, "hosts": []}
            order.append(key)
        if host and host not in merged[key]["hosts"]:
            merged[key]["hosts"].append(host)
    groups = {}
    for key in order:
        item = merged[key]
        f = item["finding"]
        groups.setdefault((_sev(f), str(f.get("module", "general"))), []).append(item)
    out = []
    for (sev, module) in sorted(groups, key=lambda k: (_SEV_RANK[k[0]], k[1])):
        out.append("<h3 class=\"sev-%s\">%s &mdash; %s</h3>" % (sev, sev.upper(), esc(module)))
        for item in sorted(groups[(sev, module)], key=lambda it: _sort_key(it["finding"])):
            hosts = item["hosts"] if len(item["hosts"]) > 1 else None
            out.append(_finding_card(item["finding"], hosts=hosts))
    return "\n".join(out)


def _generate_html(target, ctx, findings, out=None) -> str:
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        counts[_sev(f)] += 1
    cards = "".join(
        '<div class="card"><div class="num sev-%s">%d</div><div class="lbl">%s</div></div>'
        % (s, counts[s], s.capitalize()) for s in SEV_ORDER
    )
    ordered = sorted(findings, key=_sort_key)
    top_risks = "".join(
        "<li><strong class=\"sev-%s\">[%s]</strong> %s <span class=\"meta\">(%s)</span></li>"
        % (_sev(f), _sev(f).upper(), esc(f.get("title")), esc(f.get("module", "")))
        for f in ordered[:5]
    ) or "<li>None recorded.</li>"
    top_risks = "<ol>%s</ol>" % top_risks
    graph = _build_graph(target, ctx, findings)
    methodology = (
        "<p>This assessment combined automated reconnaissance (subdomain and "
        "port enumeration, technology fingerprinting), targeted vulnerability "
        "checks, secret scanning, and visual reconnaissance. Each finding was "
        "triaged with a verdict and confidence rating; only findings relevant "
        "to the authorized scope are reported. Re-test after remediation to "
        "confirm fixes.</p>"
    )
    page = _HTML.format(
        target=esc(target),
        date=esc(datetime.now().strftime("%Y-%m-%d %H:%M")),
        profile=esc(_profile(ctx)),
        css=_CSS,
        cards=cards,
        narrative=_narrative(target, findings, counts),
        top_risks=top_risks,
        graph_json=json.dumps(graph),
        graph_js=_graph_js(),
        findings_html=_grouped_findings_html(findings),
        methodology=methodology,
    )
    out = out or os.path.join(_ws_dir(ctx, target), "report.html")
    directory = os.path.dirname(out)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(page)
    return out


# --------------------------------------------------------------------------
# Platform markdown templates
# --------------------------------------------------------------------------

_MD = """# {platform} Submission Report
**Target:** {target}  |  **Date:** {date}  |  **Profile:** {profile}

## Executive summary

{exec_summary}

---
{notice}
{entries}
---

*Submitted via Pentrix Arsenal. Testing was limited to the authorized scope.*
"""

_ENTRY = """## {idx}. {title}

**Severity:** {severity}  |  **Confidence:** {confidence}  |  **CWE:** {cwe}  |  **Module:** {module}

### Description
{description}

### Impact
{impact}

### Reproduction steps
{repro}

### Remediation
{remediation}
{remediation_code}
"""


def _md_exec_summary(target, findings) -> str:
    counts = {s: sum(1 for f in findings if _sev(f) == s) for s in SEV_ORDER}
    total = len(findings)
    if not total:
        return "No findings were recorded for %s in this assessment run." % target
    ordered = sorted(findings, key=_sort_key)
    top = ordered[0]
    lines = [
        "Arsenal recorded **%d** finding(s) for **%s**: %s." % (
            total, target,
            ", ".join("%d %s" % (counts[s], s.capitalize())
                      for s in SEV_ORDER if counts[s])),
        "Highest-ranked issue: **%s** (%s severity, %s confidence, %s module)." % (
            top.get("title", ""), _sev(top).capitalize(),
            _conf(top).capitalize(), top.get("module", "")),
    ]
    return "\n\n".join(lines)


def _md_field(f, *keys, default="-"):
    for k in keys:
        v = f.get(k)
        if v:
            return str(v)
    return default


def _generate_md(target, ctx, findings, fmt, out=None) -> str:
    platform = "YesWeHack" if fmt == "yeswehack" else "HackerOne"
    ordered = sorted(findings, key=_sort_key)  # all findings; never silently truncated
    notice = ("*This report includes all %d recorded finding(s), ordered by "
              "severity.*\n" % len(ordered)) if ordered else ""
    entries = []
    for i, f in enumerate(ordered, 1):
        repro = f.get("reproduction") or f.get("repro_steps") or f.get("evidence") or "-"
        impact = f.get("impact") or (
            "A %s severity issue (%s confidence). See description for exploitability "
            "context." % (_sev(f), _conf(f)))
        rem_summary, rem_lang, rem_code = _remediation_for(f)
        remediation_code = ""
        if rem_code:
            remediation_code = "\n```%s\n%s\n```\n" % (rem_lang or "text", rem_code)
        remediation_text = f.get("remediation") or rem_summary
        if isinstance(remediation_text, list):
            remediation_text = "\n".join(str(x) for x in remediation_text)
        entries.append(_ENTRY.format(
            idx=i,
            title=_md_field(f, "title"),
            severity=_sev(f).upper(),
            confidence=_conf(f).capitalize(),
            cwe=_md_field(f, "cwe"),
            module=_md_field(f, "module"),
            description=_md_field(f, "report_section", "description"),
            impact=impact,
            repro=repro,
            remediation=remediation_text,
            remediation_code=remediation_code,
        ))
    if not entries:
        entries.append("_No findings to report._\n")
    doc = _MD.format(
        platform=platform,
        target=target,
        date=datetime.now().strftime("%Y-%m-%d"),
        profile=_profile(ctx),
        exec_summary=_md_exec_summary(target, ordered),
        notice=notice,
        entries="\n".join(entries),
    )
    out = out or os.path.join(_ws_dir(ctx, target), "report-%s.md" % fmt)
    directory = os.path.dirname(out)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return out


# --------------------------------------------------------------------------
# Trend graphs across hunts (no new dependencies: ASCII + inline SVG)
# --------------------------------------------------------------------------

def _trend_roots(ctx):
    roots = []
    ws = getattr(ctx, "workspace", None)
    if ws is not None:
        for attr in ("root", "base", "dir", "basedir"):
            val = getattr(ws, attr, None)
            if isinstance(val, str) and os.path.isdir(os.path.expanduser(val)):
                roots.append(os.path.expanduser(val))
    home = os.path.expanduser("~/.arsenal")
    for name in ("workspaces", "workspace"):
        d = os.path.join(home, name)
        if os.path.isdir(d) and d not in roots:
            roots.append(d)
    return roots


def _trend_data(ctx, weeks=12):
    """Bucket finding severities per ISO week across all hunt workspaces.

    Returns (week_labels, {severity: [counts]}). A finding counts in the
    week of its "ts" field, falling back to the findings.json mtime.
    """
    buckets = {}
    for root in _trend_roots(ctx):
        try:
            targets = sorted(d for d in os.listdir(root)
                             if os.path.isdir(os.path.join(root, d)))
        except OSError:
            continue
        for target in targets:
            path = os.path.join(root, target, "findings.json")
            if not os.path.isfile(path):
                continue
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                mtime = None
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except (OSError, ValueError):
                continue
            if isinstance(data, dict):
                data = data.get("findings", [])
            if not isinstance(data, list):
                continue
            for f in data:
                if not isinstance(f, dict):
                    continue
                ts = str(f.get("ts") or "")
                when = None
                if ts:
                    try:
                        when = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    except ValueError:
                        when = None
                if when is None and mtime:
                    when = datetime.fromtimestamp(mtime)
                if when is None:
                    continue
                iso_year, iso_week, _ = when.isocalendar()
                label = "%d-W%02d" % (iso_year, iso_week)
                sev = _sev(f)
                buckets.setdefault(label, {s: 0 for s in SEV_ORDER})
                buckets[label][sev] += 1
    labels = sorted(buckets)[-weeks:]
    series = {s: [buckets[label][s] for label in labels] for s in SEV_ORDER}
    return labels, series


def _trends_ascii(labels, series) -> str:
    """ASCII bar chart of total findings per week, split by severity."""
    if not labels:
        return "No trend data yet (no findings with timestamps in any workspace)."
    totals = [sum(series[s][i] for s in SEV_ORDER) for i in range(len(labels))]
    peak = max(totals) or 1
    width = 40
    glyph = {"critical": "#", "high": "H", "medium": "M", "low": "L", "info": "i"}
    lines = ["Findings per week (across all hunts):", ""]
    for i, label in enumerate(labels):
        bar = ""
        for s in SEV_ORDER:
            n = series[s][i]
            seg = int(round(n / peak * width)) if n else 0
            bar += glyph[s] * seg
        bar = (bar + " " * width)[:width]
        lines.append("%s |%s| %d" % (label, bar, totals[i]))
    lines.append("")
    lines.append("Legend: # critical  H high  M medium  L low  i info")
    return "\n".join(lines)


def _trends_svg(labels, series) -> str:
    """Inline SVG grouped bar chart (no JS, no external deps)."""
    if not labels:
        return "<p>No trend data yet.</p>"
    colors = {"critical": "#ff5d5d", "high": "#ff8a5c", "medium": "#ffb020",
              "low": "#4cc38a", "info": "#58a6ff"}
    n = len(labels)
    bw, gap, left, top, height = 34, 14, 70, 20, 220
    width = left + n * (bw + gap) + 20
    peak = max((sum(series[s][i] for s in SEV_ORDER) for i in range(n)), default=0) or 1
    parts = ['<svg viewBox="0 0 %d %d" width="100%%" role="img" '
             'aria-label="Findings trend across hunts">' % (width, height + top + 40)]
    # gridlines
    for frac in (0.25, 0.5, 0.75, 1.0):
        y = top + height - frac * height
        val = int(round(frac * peak))
        parts.append('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#2a3348"/>'
                     % (left, y, width - 20, y))
        parts.append('<text x="%d" y="%d" fill="#8a93a6" font-size="10" '
                     'text-anchor="end">%d</text>' % (left - 6, y + 3, val))
    for i, label in enumerate(labels):
        x = left + i * (bw + gap)
        y0 = top + height
        for s in SEV_ORDER:
            v = series[s][i]
            h = v / peak * height
            if h > 0:
                parts.append('<rect x="%d" y="%.1f" width="%d" height="%.1f" fill="%s">'
                             '<title>%s %s: %d</title></rect>'
                             % (x, y0 - h, bw, h, colors[s], label, s, v))
                y0 -= h
        parts.append('<text x="%d" y="%d" fill="#8a93a6" font-size="10" '
                     'text-anchor="middle" transform="rotate(-30 %d %d)">%s</text>'
                     % (x + bw / 2, height + top + 28, x + bw / 2,
                        height + top + 28, label))
    # legend
    lx = left
    for s in SEV_ORDER:
        parts.append('<rect x="%d" y="%d" width="10" height="10" fill="%s"/>'
                     % (lx, height + top + 34, colors[s]))
        parts.append('<text x="%d" y="%d" fill="#9fb3d1" font-size="11">%s</text>'
                     % (lx + 14, height + top + 43, s))
        lx += 78
    parts.append("</svg>")
    return "".join(parts)


def generate_trends(ctx, fmt="html", out=None) -> str:
    """Write a cross-hunt trend report. Returns the filepath."""
    fmt = str(fmt or "html").lower()
    labels, series = _trend_data(ctx)
    if fmt == "md":
        doc = ("# Hunt Trends (all targets)\n\n"
               "*Generated %s*\n\n```\n%s\n```\n"
               % (datetime.now().strftime("%Y-%m-%d %H:%M"),
                  _trends_ascii(labels, series)))
        out = out or os.path.join(
            os.path.expanduser("~/.arsenal"), "trends.md")
    elif fmt == "html":
        doc = ("<!DOCTYPE html><html><head><meta charset='utf-8'>"
               "<title>Hunt trends</title><style>"
               "body{background:#0d1117;color:#dbe2f0;font-family:sans-serif;"
               "max-width:1100px;margin:0 auto;padding:24px}</style></head>"
               "<body><h1>Hunt trends (all targets)</h1>"
               "<p>Generated %s</p>%s<pre>%s</pre></body></html>"
               % (datetime.now().strftime("%Y-%m-%d %H:%M"),
                  _trends_svg(labels, series),
                  esc(_trends_ascii(labels, series))))
        out = out or os.path.join(
            os.path.expanduser("~/.arsenal"), "trends.html")
    else:
        raise ValueError("Unknown trends format %r (html|md)" % fmt)
    directory = os.path.dirname(out)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return out


def cmd_trends(args, ctx):
    path = generate_trends(ctx, fmt=getattr(args, "format", "html"),
                           out=getattr(args, "out", None))
    print("Trend report written to %s" % path)
    return 0


def generate(target, ctx, fmt="html", out=None) -> str:
    """Generate a report for *target*. Returns the written filepath."""
    fmt = str(fmt or "html").lower()
    findings = _load_findings(ctx, target)
    if fmt == "html":
        return _generate_html(target, ctx, findings, out=out)
    if fmt in ("yeswehack", "hackerone"):
        return _generate_md(target, ctx, findings, fmt, out=out)
    raise ValueError("Unknown report format %r (html|yeswehack|hackerone)" % fmt)


def add_parsers(sub):
    """Register `arsenal report <target> [--format ...] [--out PATH]`."""
    p = sub.add_parser("report", help="Generate assessment reports")
    p.add_argument("target", help="Target name")
    p.add_argument("--format", default="html",
                   choices=["html", "yeswehack", "hackerone"],
                   help="Report format (default: html)")
    p.add_argument("--out", default=None, help="Output path override")
    p.set_defaults(func=dispatch)
    t = sub.add_parser("trends", help="Trend graphs across hunts (ASCII/SVG)")
    t.add_argument("--format", default="html", choices=["html", "md"],
                   help="Trend report format (default: html)")
    t.add_argument("--out", default=None, help="Output path override")
    t.set_defaults(func=cmd_trends)
    return sub


def dispatch(args, ctx):
    """CLI dispatch for `arsenal report`."""
    path = generate(args.target, ctx, fmt=getattr(args, "format", "html"),
                    out=getattr(args, "out", None))
    print("Report written to %s" % path)
    return 0
