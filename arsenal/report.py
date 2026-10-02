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
    if remediation:
        parts.append("<h4>Remediation</h4><p>%s</p>" % esc(remediation))
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

---
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

"""


def _md_field(f, *keys, default="-"):
    for k in keys:
        v = f.get(k)
        if v:
            return str(v)
    return default


def _generate_md(target, ctx, findings, fmt, out=None) -> str:
    platform = "YesWeHack" if fmt == "yeswehack" else "HackerOne"
    ordered = sorted(findings, key=_sort_key)[:10]
    entries = []
    for i, f in enumerate(ordered, 1):
        repro = f.get("reproduction") or f.get("repro_steps") or f.get("evidence") or "-"
        impact = f.get("impact") or (
            "A %s severity issue (%s confidence). See description for exploitability "
            "context." % (_sev(f), _conf(f)))
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
            remediation=_md_field(f, "remediation"),
        ))
    if not entries:
        entries.append("_No findings to report._\n")
    doc = _MD.format(
        platform=platform,
        target=target,
        date=datetime.now().strftime("%Y-%m-%d"),
        profile=_profile(ctx),
        entries="\n".join(entries),
    )
    out = out or os.path.join(_ws_dir(ctx, target), "report-%s.md" % fmt)
    directory = os.path.dirname(out)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return out


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
    return sub


def dispatch(args, ctx):
    """CLI dispatch for `arsenal report`."""
    path = generate(args.target, ctx, fmt=getattr(args, "format", "html"),
                    out=getattr(args, "out", None))
    print("Report written to %s" % path)
    return 0
