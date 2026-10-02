"""EXPORT FINDINGS TO TOOL FORMATS.

    arsenal export <target> --format nuclei|burp-xml [--out PATH]

nuclei:  emits RUNNABLE Nuclei YAML templates built from confirmed
         (high/critical, strong/proven confidence) findings. The raw
         request is reconstructed from the finding's url/payload and the
         matcher is derived from its evidence; findings without enough
         data to build a runnable check are skipped with a notice (no
         TODO skeletons are emitted).
burp-xml: emits a well-formed Burp site-map XML where every finding
         becomes an <item> carrying the finding details in <comment>,
         followed by plain discovered-URL items.

Findings are read from the target workspace's findings.json
(~/.arsenal/workspace/<target>/findings.json).
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlsplit

from rich.console import Console

console = Console()

_STRONG_SEV = {"high", "critical"}
_STRONG_CONF = {"high", "proven", "strong"}


def _workspace_dirs(target, ctx):
    dirs = []
    ws = getattr(ctx, "workspace", None)
    if ws is not None:
        try:
            if hasattr(ws, "path"):
                dirs.append(Path(ws.path(target)))
            else:
                dirs.append(Path(ws) / str(target))
        except Exception:
            pass
    dirs.append(Path.home() / ".arsenal" / "workspace" / str(target))
    return dirs


def _load_findings(target, ctx):
    """Return (findings, source_path)."""
    for d in _workspace_dirs(target, ctx):
        p = d / "findings.json"
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            data = data.get("findings", data.get(str(target), []))
        if isinstance(data, list):
            return [f for f in data if isinstance(f, dict)], p
    return [], None


def _is_strong(finding) -> bool:
    sev = str(finding.get("severity") or "").lower()
    conf = str(finding.get("confidence") or "").lower()
    return sev in _STRONG_SEV and conf in _STRONG_CONF


def _yaml_str(value) -> str:
    """Render a plain string as valid double-quoted YAML."""
    return json.dumps(str(value), ensure_ascii=False)


def _slug(text: str) -> str:
    text = re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-")
    return text[:48] or "finding"


def _nuclei_request(finding):
    """Reconstruct a runnable raw HTTP request from a finding.

    Returns (raw_request_text, matcher_dsl) or (None, None) when the
    finding lacks the url/payload/evidence needed for a real check.
    """
    url = str(finding.get("url") or finding.get("location") or "").strip()
    payload = str(finding.get("payload") or "").strip()
    evidence = str(finding.get("evidence") or "").strip()
    if not url:
        target = str(finding.get("target") or "")
        if target.startswith(("http://", "https://")):
            url = target
    if not url:
        return None, None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None, None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None, None
    path = parts.path or "/"
    query = parts.query or ""
    marker = ""
    if payload:
        # Inject the recorded payload into the first query parameter so the
        # template replays the exact probe that produced the finding.
        from urllib.parse import parse_qsl, urlencode
        try:
            pairs = parse_qsl(query, keep_blank_values=True)
        except Exception:
            pairs = []
        if pairs:
            pairs[0] = (pairs[0][0], payload)
            query = urlencode(pairs)
        elif query:
            query = payload
        else:
            query = "arsenal_probe=" + payload
        marker = payload[:80]
    elif evidence:
        marker = evidence[:80]
    if not marker:
        return None, None
    request_line = "GET %s HTTP/1.1" % (path + ("?" + query if query else ""))
    host_hdr = parts.hostname
    if parts.port and parts.port not in (80, 443):
        host_hdr += ":%d" % parts.port
    raw = "%s\nHost: %s\nUser-Agent: Mozilla/5.0 (compatible; pentrix-arsenal)\nAccept: */*\nConnection: close\n\n" % (
        request_line, host_hdr)
    # Escape for a double-quoted DSL string.
    dsl_marker = marker.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
    dsl = 'contains(body, "%s")' % dsl_marker
    return raw, dsl


def _nuclei_template(finding, target, index: int):
    module = str(finding.get("module") or "unknown")
    title = str(finding.get("title") or "Untitled finding")
    severity = str(finding.get("severity") or "high").lower()
    if severity not in ("critical", "high", "medium", "low", "info", "unknown"):
        severity = "high"
    description = str(finding.get("description") or finding.get("triage_reason") or "").strip()
    remediation = str(finding.get("remediation") or "").strip()
    raw, dsl = _nuclei_request(finding)
    lines = [
        "id: arsenal-%s-%d" % (_slug(module), index),
        "info:",
        "  name: %s" % _yaml_str(title),
        "  author: pentrix-arsenal",
        "  severity: %s" % severity,
        "  description: |",
    ]
    for dline in (description or "Finding reported by PENTRIX ARSENAL.").splitlines():
        lines.append("    " + dline)
    if remediation:
        lines.append("  remediation: |")
        for rline in remediation.splitlines():
            lines.append("    " + rline)
    lines.append("  tags: arsenal,verified")
    cwe = finding.get("cwe")
    lines.append("  metadata:")
    lines.append("    target: %s" % _yaml_str(target))
    if cwe:
        lines.append("    cwe: %s" % _yaml_str(cwe))
    lines.append("http:")
    lines.append("  - raw:")
    lines.append("      - |")
    for rline in raw.rstrip("\n").splitlines():
        lines.append("        " + rline)
    lines.append("    matchers:")
    lines.append("      - type: dsl")
    lines.append("        dsl:")
    lines.append("          - '%s'" % dsl.replace("'", "''"))
    lines.append("        condition: and")
    return "\n".join(lines) + "\n"


def _export_nuclei(target, ctx, out_path: Path) -> int:
    findings, src = _load_findings(target, ctx)
    strong = [f for f in findings if _is_strong(f)]
    if not strong:
        console.print("[yellow]No high/critical strong-confidence findings for '%s'. Nothing to export.[/]" % target)
        return 1
    docs, skipped = [], 0
    for i, f in enumerate(strong, 1):
        raw, _dsl = _nuclei_request(f)
        if raw is None:
            skipped += 1
            continue
        docs.append(_nuclei_template(f, target, i))
    if not docs:
        console.print("[yellow]None of the %d strong finding(s) had enough data "
                      "(url + payload/evidence) for a runnable template. Nothing to export.[/]" % len(strong))
        return 1
    out_path.write_text("\n---\n".join(docs), encoding="utf-8")
    console.print("[green]Wrote %d runnable nuclei template(s) to %s[/]" % (len(docs), out_path))
    if skipped:
        console.print("[dim]Skipped %d finding(s) lacking replay data.[/]" % skipped)
    return 0


def _collect_urls(target, ctx):
    urls = set()

    def _add(obj):
        if isinstance(obj, str) and obj.lower().startswith(("http://", "https://")):
            urls.add(obj.strip())
        elif isinstance(obj, dict):
            for v in obj.values():
                _add(v)
        elif isinstance(obj, (list, tuple)):
            for v in obj:
                _add(v)

    for d in _workspace_dirs(target, ctx):
        for name in ("urls.txt", "urls.json", "scope.json"):
            p = d / name
            if not p.exists():
                continue
            try:
                if name.endswith(".txt"):
                    for line in p.read_text(encoding="utf-8").splitlines():
                        _add(line.strip())
                else:
                    _add(json.loads(p.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                continue
    findings, _ = _load_findings(target, ctx)
    for f in findings:
        _add(f.get("url"))
        _add(f.get("evidence"))

    # Keep only well-formed http(s) URLs, de-duplicate, sort.
    clean = set()
    for u in urls:
        try:
            parts = urlsplit(u)
        except ValueError:
            continue
        if parts.scheme in ("http", "https") and parts.netloc:
            clean.add(u)
    return sorted(clean)


def _finding_url(finding):
    """Best-effort http(s) URL for a finding, or None."""
    for key in ("url", "location"):
        val = str(finding.get(key) or "").strip()
        if val.lower().startswith(("http://", "https://")):
            return val
    target = str(finding.get("target") or "").strip()
    if target.lower().startswith(("http://", "https://")):
        return target
    return None


def _finding_comment(finding) -> str:
    sev = str(finding.get("severity") or "info").upper()
    title = str(finding.get("title") or "untitled")
    module = str(finding.get("module") or "?")
    conf = str(finding.get("confidence") or "?")
    evidence = str(finding.get("evidence") or "").strip().replace("\n", " | ")
    comment = "[%s/%s] %s (%s)" % (sev, conf, title, module)
    if evidence:
        comment += " -- %s" % (evidence[:300] + ("..." if len(evidence) > 300 else ""))
    verdict = finding.get("verdict")
    if verdict:
        comment += " [triage: %s]" % verdict
    return comment


def _add_burp_item(root, url, comment=""):
    parts = urlsplit(url)
    item = ET.SubElement(root, "item")
    ET.SubElement(item, "url").text = url
    host = ET.SubElement(item, "host")
    host.set("ip", "")
    host.text = parts.hostname or ""
    ET.SubElement(item, "path").text = parts.path or "/"
    ET.SubElement(item, "protocol").text = parts.scheme
    default_port = 443 if parts.scheme == "https" else 80
    ET.SubElement(item, "port").text = str(parts.port or default_port)
    ET.SubElement(item, "query").text = parts.query or ""
    ET.SubElement(item, "status").text = ""
    ET.SubElement(item, "responselength").text = ""
    ET.SubElement(item, "mimetype").text = ""
    ET.SubElement(item, "comment").text = comment


def _export_burp_xml(target, ctx, out_path: Path) -> int:
    findings, _src = _load_findings(target, ctx)
    root = ET.Element("items")
    root.set("burpVersion", "2026.2")
    count = 0
    covered = set()
    # Findings first: each becomes an item carrying its details in <comment>.
    for f in findings:
        url = _finding_url(f)
        if not url:
            continue
        try:
            parts = urlsplit(url)
        except ValueError:
            continue
        if parts.scheme not in ("http", "https") or not parts.netloc:
            continue
        _add_burp_item(root, url, _finding_comment(f))
        covered.add(url)
        count += 1
    # Then the plain discovered-URL site map for context.
    for url in _collect_urls(target, ctx):
        if url in covered:
            continue
        _add_burp_item(root, url)
        count += 1
    if not count:
        console.print("[yellow]No findings or discovered URLs for '%s'. Nothing to export.[/]" % target)
        return 1
    tree = ET.ElementTree(root)
    try:
        ET.indent(tree, space="  ")
    except AttributeError:
        pass
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tree.write(str(out_path), encoding="utf-8", xml_declaration=True)
    n_findings = sum(1 for _ in findings if _finding_url(_))
    console.print("[green]Wrote %d item(s) (%d with finding details) as Burp site-map XML to %s[/]"
                  % (count, min(n_findings, count), out_path))
    return 0


def cmd_export(args, ctx) -> int:
    fmt = args.format
    out = Path(args.out) if args.out else Path(f"{args.target}.{fmt.replace('-xml', '.xml').replace('nuclei', '.nuclei.yaml')}")
    if fmt == "nuclei":
        return _export_nuclei(args.target, ctx, out)
    if fmt == "burp-xml":
        return _export_burp_xml(args.target, ctx, out)
    console.print(f"[red]Unknown format '{fmt}'.[/]")
    return 1


def add_parsers(sub):
    p = sub.add_parser(
        "export",
        help="Export findings/URLs to tool formats (nuclei, burp-xml)",
        description=(
            "nuclei: runnable YAML templates for high/critical "
            "strong-confidence findings (skips findings without replay "
            "data; never emits TODO skeletons). burp-xml: Burp site-map XML "
            "with one commented item per finding plus discovered URLs."
        ),
    )
    p.add_argument("target", help="Target identifier (as stored in the workspace)")
    p.add_argument("--format", required=True, choices=["nuclei", "burp-xml"],
                   help="Export format")
    p.add_argument("--out", metavar="PATH", help="Output file (default: <target>.<ext>)")
    p.set_defaults(func=cmd_export)
    return p


def dispatch(args, ctx):
    func = getattr(args, "func", None)
    if callable(func):
        return func(args, ctx)
    raise ValueError("no command dispatch configured for export")
