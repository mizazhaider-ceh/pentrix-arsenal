"""BOUNTY CRM for PENTRIX ARSENAL.

Finding lifecycle persisted per target in the workspace findings.json.
Every finding gets a stable id (F-001, F-002, ...) and a status in:
found | triaged | reported | accepted | duplicate | informative | paid.

Public API:
    ensure_ids(target, ctx) -> dict of {index: id} for newly assigned ids
    set_status(target, fid, status, program=None, payout=None) -> entry dict
    add_parsers(sub)  -> registers `arsenal findings` and `arsenal stats`
    dispatch_findings(args, ctx), dispatch_stats(args, ctx)
"""

import json
import os

STATUSES = ("found", "triaged", "reported", "accepted", "duplicate", "informative", "paid")


def _ws_dir(ctx, target) -> str:
    ws = getattr(ctx, "workspace", None)
    if ws is not None and hasattr(ws, "path"):
        try:
            return ws.path(target)
        except Exception:
            pass
    return os.path.expanduser(os.path.join("~", ".arsenal", "workspace", str(target)))


def _workspace_root(ctx) -> str:
    ws = getattr(ctx, "workspace", None)
    if ws is not None:
        for attr in ("root", "base", "dir", "basedir"):
            if hasattr(ws, attr):
                try:
                    return str(getattr(ws, attr))
                except Exception:
                    pass
        if hasattr(ws, "path"):
            try:
                probe = ws.path("__probe__")
                return os.path.dirname(probe.rstrip(os.sep))
            except Exception:
                pass
    return os.path.expanduser(os.path.join("~", ".arsenal", "workspace"))


def _findings_path(ctx, target) -> str:
    return os.path.join(_ws_dir(ctx, target), "findings.json")


def _load(ctx, target) -> list:
    path = _findings_path(ctx, target)
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save(ctx, target, findings: list) -> str:
    path = _findings_path(ctx, target)
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2, ensure_ascii=False)
    return path


def append_finding(ctx, target, finding: dict) -> dict:
    """Append a raw finding dict to the target's findings.json."""
    findings = _load(ctx, target)
    entry = dict(finding or {})
    entry.setdefault("status", "found")
    findings.append(entry)
    _save(ctx, target, findings)
    ensure_ids(target, ctx)
    return entry


def ensure_ids(target, ctx) -> dict:
    """Assign F-001 style ids to findings missing one. Returns {idx: id}."""
    findings = _load(ctx, target)
    if not findings:
        return {}
    used = set()
    for entry in findings:
        fid = entry.get("id")
        if isinstance(fid, str) and fid.startswith("F-"):
            used.add(fid)
    counter = 1
    assigned = {}
    changed = False
    for idx, entry in enumerate(findings):
        if not entry.get("id"):
            while "F-%03d" % counter in used:
                counter += 1
            fid = "F-%03d" % counter
            entry["id"] = fid
            used.add(fid)
            counter += 1
            assigned[idx] = fid
            changed = True
        entry.setdefault("status", "found")
    if changed:
        _save(ctx, target, findings)
    return assigned


def set_status(target, fid, status, program=None, payout=None, ctx=None) -> dict:
    """Set lifecycle status (and optional program/payout) for a finding id.

    Raises ValueError for an unknown status and LookupError when the id
    is not present.
    """
    status = str(status or "").lower()
    if status not in STATUSES:
        raise ValueError("Unknown status %r; expected one of: %s" % (status, ", ".join(STATUSES)))
    findings = _load(ctx, target)
    wanted = str(fid or "").upper()
    for entry in findings:
        if str(entry.get("id", "")).upper() == wanted:
            entry["status"] = status
            if program is not None:
                entry["program"] = program
            if payout is not None:
                try:
                    entry["payout"] = float(payout)
                except (TypeError, ValueError):
                    entry["payout"] = payout
            _save(ctx, target, findings)
            return entry
    raise LookupError("Finding %s not found for target %s" % (fid, target))


def list_findings(target, ctx, status=None) -> list:
    """All findings for a target, optionally filtered by status."""
    findings = _load(ctx, target)
    if status:
        wanted = str(status).lower()
        findings = [f for f in findings if str(f.get("status", "")).lower() == wanted]
    return findings


def _iter_all_findings(ctx):
    root = _workspace_root(ctx)
    if not os.path.isdir(root):
        return
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name, "findings.json")
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, list):
                    for entry in data:
                        yield name, entry
            except Exception:
                continue


def stats(ctx, program=None) -> dict:
    """Aggregate totals: by status, by severity, by program, paid, hours."""
    by_status = {s: 0 for s in STATUSES}
    by_severity = {}
    by_program = {}
    total_paid = 0.0
    total = 0
    for _target, entry in _iter_all_findings(ctx):
        prog = entry.get("program")
        if program and str(prog or "").lower() != str(program).lower():
            continue
        total += 1
        st = str(entry.get("status", "found")).lower()
        by_status[st] = by_status.get(st, 0) + 1
        sev = str(entry.get("severity", "info")).lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        key = str(prog) if prog else "unassigned"
        by_program[key] = by_program.get(key, 0) + 1
        if st == "paid":
            try:
                total_paid += float(entry.get("payout") or 0)
            except (TypeError, ValueError):
                pass
    hours = 0.0
    time_path = os.path.expanduser(os.path.join("~", ".arsenal", "time.json"))
    try:
        if os.path.exists(time_path):
            with open(time_path, "r", encoding="utf-8") as fh:
                tdata = json.load(fh)
            if isinstance(tdata, dict):
                hours = float(tdata.get("hours", 0) or 0)
            elif isinstance(tdata, list):
                hours = float(sum(float(x) for x in tdata))
    except Exception:
        hours = 0.0
    return {
        "total": total,
        "by_status": by_status,
        "by_severity": by_severity,
        "by_program": by_program,
        "total_paid": total_paid,
        "hours_hunted": hours,
    }


def add_parsers(sub):
    """Register `arsenal findings` and `arsenal stats` on a subparsers object."""
    pf = sub.add_parser("findings", help="List and manage bounty findings (CRM)")
    pf.add_argument("target", help="Target name")
    pf.add_argument("--status", default=None, help="Filter by status")
    pf.add_argument("--set", default=None, metavar="FID", help="Finding id to update, e.g. F-003")
    pf.add_argument("--to", default=None, help="New status for --set")
    pf.add_argument("--program", default=None, help="Program name (stored with --set)")
    pf.add_argument("--payout", default=None, help="Payout amount (stored with --set)")
    pf.set_defaults(func=dispatch_findings)

    ps = sub.add_parser("stats", help="Bounty totals across all targets")
    ps.add_argument("--program", default=None, help="Filter by program name")
    ps.set_defaults(func=dispatch_stats)
    return sub


def dispatch_findings(args, ctx):
    """CLI dispatch for `arsenal findings`. Prints a table; applies --set."""
    from rich.console import Console
    from rich.table import Table

    console = Console()
    if getattr(args, "set", None):
        if not getattr(args, "to", None):
            console.print("[red]--set requires --to <status>[/red]")
            return 1
        try:
            entry = set_status(
                args.target, args.set, args.to,
                program=getattr(args, "program", None),
                payout=getattr(args, "payout", None),
                ctx=ctx,
            )
            console.print("[green]Updated %s -> %s[/green]" % (entry.get("id"), entry.get("status")))
        except (ValueError, LookupError) as exc:
            console.print("[red]%s[/red]" % exc)
            return 1
        return 0

    ensure_ids(args.target, ctx)
    findings = list_findings(args.target, ctx, status=getattr(args, "status", None))
    table = Table(title="Findings: %s" % args.target)
    for col in ("ID", "Severity", "Status", "Program", "Payout", "Title"):
        table.add_column(col)
    for f in findings:
        payout = f.get("payout")
        table.add_row(
            str(f.get("id", "-")),
            str(f.get("severity", "-")),
            str(f.get("status", "-")),
            str(f.get("program", "-")),
            str(payout) if payout not in (None, "") else "-",
            str(f.get("title", "-"))[:60],
        )
    console.print(table)
    console.print("[dim]%d finding(s)[/dim]" % len(findings))
    return 0


def dispatch_stats(args, ctx):
    """CLI dispatch for `arsenal stats`."""
    from rich.console import Console
    from rich.table import Table

    console = Console()
    data = stats(ctx, program=getattr(args, "program", None))
    console.print("[bold]Bounty stats[/bold]%s" % (" (program: %s)" % args.program if getattr(args, "program", None) else ""))

    t1 = Table(title="By status")
    t1.add_column("Status")
    t1.add_column("Count", justify="right")
    for s, n in data["by_status"].items():
        t1.add_row(s, str(n))
    t1.add_row("[bold]total[/bold]", "[bold]%d[/bold]" % data["total"])
    console.print(t1)

    t2 = Table(title="By severity")
    t2.add_column("Severity")
    t2.add_column("Count", justify="right")
    for sev, n in sorted(data["by_severity"].items()):
        t2.add_row(sev, str(n))
    console.print(t2)

    t3 = Table(title="By program")
    t3.add_column("Program")
    t3.add_column("Count", justify="right")
    for prog, n in sorted(data["by_program"].items()):
        t3.add_row(prog, str(n))
    console.print(t3)

    console.print("Total paid: [bold green]%s[/bold green]" % data["total_paid"])
    console.print("Hours hunted: [bold]%s[/bold]" % data["hours_hunted"])
    return 0
