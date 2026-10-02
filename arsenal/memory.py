"""PERSISTENT HUNT MEMORY for PENTRIX ARSENAL.

`arsenal memory <target> [--add "note"] [--search QUERY]`

Stores autopilot decisions and analyst notes in hunt_memory.jsonl inside the
target's workspace directory. Library functions never print; the CLI below may.
"""

from __future__ import annotations

import datetime as _dt
import json
import os


def _workspace_dir(ctx, target):
    ws = getattr(ctx, "workspace", None)
    fn = getattr(ws, "path", None)
    if not callable(fn):
        return None
    try:
        p = fn(target)
    except Exception:
        return None
    if not p:
        return None
    try:
        os.makedirs(p, exist_ok=True)
    except Exception:
        pass
    return p


def memory_path(ctx, target):
    d = _workspace_dir(ctx, target)
    return os.path.join(d, "hunt_memory.jsonl") if d else None


def read_memory(ctx, target):
    """Return all memory records (dicts) for a target. Never raises."""
    p = memory_path(ctx, target)
    if not p or not os.path.exists(p):
        return []
    records = []
    try:
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        return []
    return [r for r in records if isinstance(r, dict)]


def add_note(ctx, target, text):
    """Append an analyst note to hunt memory. Returns True on success."""
    p = memory_path(ctx, target)
    if not p:
        return False
    record = {
        "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "kind": "note",
        "text": str(text),
    }
    try:
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
        return True
    except Exception:
        return False


def _get_findings(ctx, target):
    ws = getattr(ctx, "workspace", None)
    for method in ("get_findings", "all_findings"):
        fn = getattr(ws, method, None)
        if callable(fn):
            try:
                f = fn(target)
                break
            except Exception:
                f = None
        else:
            f = None
    else:
        f = None
    if f is None:
        f = getattr(ws, "findings", None)
    if isinstance(f, dict):
        f = f.get(target, [])
    return [x for x in (f or []) if isinstance(x, dict)]


def _get_tech(ctx, target):
    ws = getattr(ctx, "workspace", None)
    fn = getattr(ws, "get_tech", None)
    t = None
    if callable(fn):
        try:
            t = fn(target)
        except Exception:
            t = None
    if t is None:
        t = getattr(ws, "tech", None)
    if isinstance(t, dict):
        t = t.get(target, [])
    return list(t or [])


def search_memory(ctx, target, query):
    """Grep memory records, findings and tech for a query. Returns matches."""
    q = str(query or "").lower()
    matches = []
    for r in read_memory(ctx, target):
        blob = json.dumps(r).lower()
        if q in blob:
            matches.append(("memory", r.get("ts", "?"),
                            r.get("text") or r.get("decision") or r.get("reason") or ""))
    for f in _get_findings(ctx, target):
        blob = json.dumps(f).lower()
        if q in blob:
            matches.append(("finding", f.get("severity", "?"),
                            f.get("title") or ""))
    for t in _get_tech(ctx, target):
        blob = json.dumps(t).lower()
        if q in blob:
            matches.append(("tech", "", t.get("name") or t.get("tech") or str(t)))
    return matches


def hunt_summary(ctx, target):
    """Build a hunt summary dict. Never raises."""
    records = read_memory(ctx, target)
    findings = _get_findings(ctx, target)
    by_sev = {}
    open_questions = []
    for f in findings:
        sev = str(f.get("severity", "unknown")).lower()
        by_sev[sev] = by_sev.get(sev, 0) + 1
        if sev in ("high", "critical") and not (f.get("triaged") or f.get("verdict")):
            open_questions.append(f.get("title") or "untitled finding")
    timeline = []
    for r in records:
        if r.get("kind") == "note":
            timeline.append("%s  note: %s" % (r.get("ts", "?")[:19], r.get("text", "")))
        else:
            timeline.append("%s  cycle %s: %s (%s)" % (
                r.get("ts", "?")[:19], r.get("cycle", "?"),
                r.get("decision", "?"), r.get("reason", "")))
    return {
        "target": target,
        "timeline": timeline,
        "finding_counts": by_sev,
        "total_findings": len(findings),
        "open_questions": open_questions,
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def cmd_memory(args, ctx):
    if args.add:
        ok = add_note(ctx, args.target, args.add)
        print("Note saved to hunt memory." if ok else
              "Could not save note (workspace path unavailable).")
        return 0 if ok else 1
    if args.search:
        matches = search_memory(ctx, args.target, args.search)
        if not matches:
            print("No matches for %r." % args.search)
            return 0
        for kind, meta, text in matches:
            print("[%s] %s %s" % (kind, meta, text))
        return 0
    s = hunt_summary(ctx, args.target)
    try:
        from rich.console import Console
        from rich.table import Table
        console = Console()
        console.print("[bold]Hunt summary for %s[/bold]" % s["target"])
        if s["timeline"]:
            console.print("\n[bold]Timeline[/bold]")
            for line in s["timeline"][-20:]:
                console.print("  " + line)
        else:
            console.print("\n[dim]No decisions or notes recorded yet.[/dim]")
        table = Table(title="Findings by severity")
        table.add_column("Severity")
        table.add_column("Count", justify="right")
        for sev, count in sorted(s["finding_counts"].items()):
            table.add_row(sev, str(count))
        console.print(table)
        console.print("Total findings: %d" % s["total_findings"])
        if s["open_questions"]:
            console.print("\n[bold yellow]Open questions (untriaged high/critical)[/bold yellow]")
            for q in s["open_questions"]:
                console.print("  - %s" % q)
        else:
            console.print("\n[green]No open questions.[/green]")
    except Exception:
        print("Hunt summary for %s" % s["target"])
        for line in s["timeline"][-20:]:
            print("  " + line)
        print("Findings: %s (total %d)" % (s["finding_counts"], s["total_findings"]))
        if s["open_questions"]:
            print("Open questions:")
            for q in s["open_questions"]:
                print("  - %s" % q)
    return 0


def add_parsers(sub):
    p = sub.add_parser("memory", help="Inspect or annotate the hunt memory for a target")
    p.add_argument("target", help="Target identifier (as stored in the workspace)")
    p.add_argument("--add", metavar="NOTE", default=None,
                   help="Append an analyst note to hunt memory")
    p.add_argument("--search", metavar="QUERY", default=None,
                   help="Search memory, findings and tech for a query")
    p.set_defaults(func=cmd_memory)
    return p


def dispatch(args, ctx):
    func = getattr(args, "func", None)
    if callable(func):
        return func(args, ctx)
    raise ValueError("no command dispatch configured for memory")
