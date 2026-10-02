"""DUPLICATE FINDING CHECK.

    arsenal dupcheck <target>

Scans ~/.arsenal/workspaces/*/findings.json (and the legacy singular
~/.arsenal/workspace/) for records with status == "duplicate" that share
the same module and >= 3 significant title words with a finding for the
target. Helps avoid re-reporting already-known duplicates.

Library API:
    check(finding, ctx) -> [warning strings]
    warn_duplicates(findings, ctx) -> [warning strings]
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from rich.console import Console

console = Console()

_STOPWORDS = {
    "the", "and", "for", "with", "from", "via", "into", "that", "this",
    "these", "those", "are", "was", "were", "has", "have", "had", "its",
    "our", "your", "their", "not", "but", "all", "any", "can", "may",
    "one", "two", "new", "old", "via", "using", "used", "use", "allow",
    "allows", "allows", "potential", "possible", "found", "page",
}


def _significant_words(title) -> set:
    words = re.findall(r"[a-z0-9]+", str(title or "").lower())
    return {w for w in words if len(w) >= 3 and w not in _STOPWORDS}


def _workspaces_roots(ctx):
    roots = []
    home = Path.home()
    for name in ("workspaces", "workspace"):
        d = home / ".arsenal" / name
        if d.is_dir():
            roots.append(d)
    extra = getattr(ctx, "workspaces_root", None)
    if extra:
        p = Path(extra)
        if p.is_dir() and p not in roots:
            roots.append(p)
    ws = getattr(ctx, "workspace", None)
    wroot = getattr(ws, "root", None)
    if wroot:
        p = Path(os.path.expanduser(str(wroot)))
        if p.is_dir() and p not in roots:
            roots.append(p)
    return roots


def _known_duplicates(ctx):
    """Yield (finding_dict, source_workspace_name) for status == duplicate."""
    for root in _workspaces_roots(ctx):
        for child in sorted(root.iterdir()):
            if not child.is_dir():
                continue
            path = child / "findings.json"
            if not path.exists():
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(data, dict):
                data = data.get("findings", [])
            if not isinstance(data, list):
                continue
            for rec in data:
                if not isinstance(rec, dict):
                    continue
                if str(rec.get("status") or "").lower() == "duplicate":
                    yield rec, child.name


def _target_findings(target, ctx):
    """Load findings for a target (workspace files, or ctx.workspace)."""
    candidates = []
    ws = getattr(ctx, "workspace", None)
    if ws is not None:
        try:
            if hasattr(ws, "path"):
                candidates.append(Path(ws.path(target)) / "findings.json")
            else:
                candidates.append(Path(ws) / str(target) / "findings.json")
        except Exception:
            pass
    home = Path.home()
    for name in ("workspace", "workspaces"):
        candidates.append(home / ".arsenal" / name / str(target) / "findings.json")
    for p in candidates:
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            data = data.get("findings", [])
        if isinstance(data, list):
            return [f for f in data if isinstance(f, dict)]
    return []


def check(finding, ctx):
    """Return warning strings if finding resembles a known duplicate."""
    warnings = []
    if not isinstance(finding, dict):
        return warnings
    module = str(finding.get("module") or "").lower()
    sig = _significant_words(finding.get("title"))
    if not module or len(sig) < 3:
        return warnings
    title = str(finding.get("title") or "untitled")
    for dup, ws_name in _known_duplicates(ctx):
        if str(dup.get("module") or "").lower() != module:
            continue
        shared = sig & _significant_words(dup.get("title"))
        if len(shared) >= 3:
            warnings.append(
                f"Possible duplicate: [{module}] '{title}' shares "
                f"{len(shared)} significant title word(s) "
                f"({', '.join(sorted(shared))}) with a known duplicate "
                f"in workspace '{ws_name}': '{dup.get('title')}'."
            )
    return warnings


def warn_duplicates(findings, ctx):
    """Run check() over every finding; return the combined warnings."""
    warnings = []
    for finding in findings or []:
        warnings.extend(check(finding, ctx))
    return warnings


def cmd_dupcheck(args, ctx) -> int:
    findings = _target_findings(args.target, ctx)
    if not findings:
        console.print(f"[yellow]No findings stored for target '{args.target}'.[/]")
        return 0
    warnings = warn_duplicates(findings, ctx)
    if not warnings:
        console.print(f"[green]No likely duplicates found for '{args.target}' "
                      f"({len(findings)} finding(s) checked).[/]")
        return 0
    console.print(f"[bold yellow]{len(warnings)} duplicate warning(s)[/] "
                  f"for '{args.target}':")
    for w in warnings:
        console.print(f"  [!] {w}")
    return 0


def add_parsers(sub):
    p = sub.add_parser(
        "dupcheck",
        help="Warn about findings that resemble known duplicates",
        description=(
            "Scans ~/.arsenal/workspaces/*/findings.json for records with "
            "status == 'duplicate' sharing the same module and at least 3 "
            "significant title words with this target's findings."
        ),
    )
    p.add_argument("target", help="Target identifier (as stored in the workspace)")
    p.set_defaults(func=cmd_dupcheck)
    return p


def dispatch(args, ctx):
    func = getattr(args, "func", None)
    if callable(func):
        return func(args, ctx)
    raise ValueError("no command dispatch configured for dupcheck")
