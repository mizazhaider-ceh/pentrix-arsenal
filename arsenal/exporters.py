"""EXPORT FINDINGS TO TOOL FORMATS.

    arsenal export <target> --format nuclei|burp-xml [--out PATH]

nuclei:  emits skeletal Nuclei YAML templates (with TODO markers) for
         high/critical findings with strong (high/proven/strong)
         confidence. Each document is valid YAML.
burp-xml: emits a well-formed Burp site-map XML
         (<items><item><url>...</url>...) of discovered in-scope URLs.

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


def _nuclei_template(finding, target, index: int) -> str:
    module = str(finding.get("module") or "unknown")
    title = str(finding.get("title") or "Untitled finding")
    severity = str(finding.get("severity") or "high").lower()
    cwe = finding.get("cwe") or "TODO"
    return (
        f"id: arsenal-{_slug(module)}-{index}\n"
        "info:\n"
        f"  name: {_yaml_str(title)}\n"
        "  author: pentrix-arsenal\n"
        f"  severity: {severity}\n"
        "  description: |\n"
        "    TODO: describe the vulnerability and its impact in your own words.\n"
        "  remediation: |\n"
        "    TODO: describe the recommended fix.\n"
        "  reference:\n"
        "    - TODO: add reference URLs\n"
        "  tags: arsenal,todo\n"
        "  metadata:\n"
        f"    target: {_yaml_str(target)}\n"
        f"    cwe: {_yaml_str(cwe)}\n"
        "http:\n"
        "  - raw:\n"
        "      - |\n"
        "        TODO: paste the raw HTTP request that reproduces the finding\n"
        "    matchers:\n"
        "      - type: dsl\n"
        "        dsl:\n"
        "          - 'TODO: write a matcher, e.g. status_code == 200 && contains(body, \"marker\")'\n"
        "        condition: and\n"
    )


def _export_nuclei(target, ctx, out_path: Path) -> int:
    findings, src = _load_findings(target, ctx)
    strong = [f for f in findings if _is_strong(f)]
    if not strong:
        console.print(f"[yellow]No high/critical strong-confidence findings for '{target}'. Nothing to export.[/]")
        return 1
    docs = "\n---\n".join(_nuclei_template(f, target, i) for i, f in enumerate(strong, 1))
    out_path.write_text(docs + "\n", encoding="utf-8")
    console.print(f"[green]Wrote {len(strong)} skeletal nuclei template(s) to {out_path}[/]")
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


def _export_burp_xml(target, ctx, out_path: Path) -> int:
    urls = _collect_urls(target, ctx)
    if not urls:
        console.print(f"[yellow]No discovered URLs for '{target}'. Nothing to export.[/]")
        return 1
    root = ET.Element("items")
    root.set("burpVersion", "2026.2")
    for u in urls:
        parts = urlsplit(u)
        item = ET.SubElement(root, "item")
        ET.SubElement(item, "url").text = u
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
        ET.SubElement(item, "comment").text = ""
    tree = ET.ElementTree(root)
    try:
        ET.indent(tree, space="  ")
    except AttributeError:
        pass
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tree.write(str(out_path), encoding="utf-8", xml_declaration=True)
    console.print(f"[green]Wrote {len(urls)} URL(s) as Burp site-map XML to {out_path}[/]")
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
            "nuclei: skeletal YAML templates (with TODO markers) for "
            "high/critical strong-confidence findings. burp-xml: a "
            "well-formed Burp site-map XML of discovered in-scope URLs."
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
