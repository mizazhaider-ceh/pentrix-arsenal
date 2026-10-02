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

# Submission status flow: allowed transitions. Terminal states
# (duplicate/informative/paid) accept no further moves.
STATUS_FLOW = {
    "found": ("triaged", "duplicate", "informative"),
    "triaged": ("reported", "duplicate", "informative", "found"),
    "reported": ("accepted", "duplicate", "informative", "triaged"),
    "accepted": ("paid", "duplicate"),
    "duplicate": (),
    "informative": (),
    "paid": (),
}

PROGRAMS_FILE = os.path.expanduser(os.path.join("~", ".arsenal", "programs.json"))
TEMPLATES_DIR = os.path.expanduser(os.path.join("~", ".arsenal", "report-templates"))


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


def set_status(target, fid, status, program=None, payout=None, ctx=None,
               force=False) -> dict:
    """Set lifecycle status (and optional program/payout) for a finding id.

    Raises ValueError for an unknown status or a transition outside
    STATUS_FLOW (unless force=True), and LookupError when the id is not
    present.
    """
    status = str(status or "").lower()
    if status not in STATUSES:
        raise ValueError("Unknown status %r; expected one of: %s" % (status, ", ".join(STATUSES)))
    findings = _load(ctx, target)
    wanted = str(fid or "").upper()
    for entry in findings:
        if str(entry.get("id", "")).upper() == wanted:
            current = str(entry.get("status", "found")).lower()
            allowed = STATUS_FLOW.get(current, ())
            if status != current and status not in allowed and not force:
                raise ValueError(
                    "Invalid transition %s -> %s for %s; allowed: %s "
                    "(use --force to override)" % (
                        current, status, wanted,
                        ", ".join(allowed) or "none (terminal state)"))
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


# --------------------------------------------------------------------------
# Program tracking
# --------------------------------------------------------------------------

def _load_programs() -> list:
    try:
        with open(PROGRAMS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _save_programs(programs: list) -> None:
    directory = os.path.dirname(PROGRAMS_FILE)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = PROGRAMS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(programs, fh, indent=2)
    os.replace(tmp, PROGRAMS_FILE)


def add_program(name, url="", scope="", notes="") -> dict:
    """Register a bounty program. Returns the program dict."""
    programs = _load_programs()
    entry = {
        "name": str(name),
        "url": str(url or ""),
        "scope": str(scope or ""),
        "notes": str(notes or ""),
    }
    for i, existing in enumerate(programs):
        if str(existing.get("name", "")).lower() == entry["name"].lower():
            programs[i] = entry
            _save_programs(programs)
            return entry
    programs.append(entry)
    _save_programs(programs)
    return entry


def list_programs() -> list:
    """All tracked bounty programs."""
    return _load_programs()


def get_program(name):
    """Return the program dict matching name (case-insensitive), or None."""
    wanted = str(name or "").lower()
    for entry in _load_programs():
        if str(entry.get("name", "")).lower() == wanted:
            return entry
    return None


def program_stats(ctx, program) -> dict:
    """CRM stats scoped to one program name."""
    return stats(ctx, program=program)


# --------------------------------------------------------------------------
# Report template library (crowdsourced convention)
# --------------------------------------------------------------------------

_STARTER_TEMPLATES = {
    "yeswehack.md": """# {{title}}

**Severity:** {{severity}} | **Target:** {{target}} | **Module:** {{module}}

## Description
{{description}}

## Impact
{{impact}}

## Reproduction steps
{{reproduction}}

## Remediation
{{remediation}}
""",
    "hackerone.md": """## Summary
{{title}} on {{target}} ({{severity}} severity, found by {{module}}).

## Description
{{description}}

## Impact
{{impact}}

## Steps to reproduce
{{reproduction}}

## Suggested fix
{{remediation}}
""",
}


def list_report_templates() -> list:
    """Names of *.md templates in the report-templates dir."""
    if not os.path.isdir(TEMPLATES_DIR):
        return []
    return sorted(f[:-3] for f in os.listdir(TEMPLATES_DIR)
                  if f.endswith(".md") and os.path.isfile(
                      os.path.join(TEMPLATES_DIR, f)))


def get_report_template(name: str):
    """Return template text, or None when missing."""
    for candidate in (name, name + ".md"):
        path = os.path.join(TEMPLATES_DIR, candidate)
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    return fh.read()
            except OSError:
                return None
    return None


def init_report_templates() -> list:
    """Write the starter templates; returns paths written."""
    os.makedirs(TEMPLATES_DIR, exist_ok=True)
    written = []
    for fname, text in _STARTER_TEMPLATES.items():
        path = os.path.join(TEMPLATES_DIR, fname)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            written.append(path)
    return written


def render_report_template(name: str, finding: dict, target="") -> str:
    """Render a template with {{field}} placeholders from a finding dict.

    Unknown placeholders are left as-is. Lists (reproduction steps) are
    joined with newlines.
    """
    template = get_report_template(name)
    if template is None:
        raise LookupError("Report template %r not found in %s" % (name, TEMPLATES_DIR))
    import re as _re

    def value_for(key):
        if key == "target":
            return str(target or finding.get("target") or "")
        val = finding.get(key)
        if isinstance(val, list):
            return "\n".join(str(x) for x in val)
        if isinstance(val, dict):
            return "\n".join("%s: %s" % (k, v) for k, v in val.items())
        return "" if val is None else str(val)

    def repl(match):
        key = match.group(1).strip()
        if key in finding or key == "target":
            return value_for(key)
        return match.group(0)

    return _re.sub(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}", repl, template)


def add_parsers(sub):
    """Register `arsenal findings` and `arsenal stats` on a subparsers object."""
    pf = sub.add_parser("findings", help="List and manage bounty findings (CRM)")
    pf.add_argument("target", help="Target name")
    pf.add_argument("--status", default=None, help="Filter by status")
    pf.add_argument("--set", default=None, metavar="FID", help="Finding id to update, e.g. F-003")
    pf.add_argument("--to", default=None, help="New status for --set")
    pf.add_argument("--program", default=None, help="Program name (stored with --set)")
    pf.add_argument("--payout", default=None, help="Payout amount (stored with --set)")
    pf.add_argument("--force", action="store_true",
                    help="Allow a status transition outside the normal flow")
    pf.set_defaults(func=dispatch_findings)

    ps = sub.add_parser("stats", help="Bounty totals across all targets")
    ps.add_argument("--program", default=None, help="Filter by program name")
    ps.set_defaults(func=dispatch_stats)

    pp = sub.add_parser("program", help="Track bounty programs (targets, scope)")
    psub = pp.add_subparsers(dest="program_cmd", metavar="COMMAND")
    pa = psub.add_parser("add", help="Register or update a bounty program")
    pa.add_argument("name", help="Program name")
    pa.add_argument("--url", default="", help="Program URL")
    pa.add_argument("--scope", default="", help="In-scope assets summary")
    pa.add_argument("--notes", default="", help="Policy notes")
    pa.set_defaults(func=dispatch_program_add)
    pl = psub.add_parser("list", help="List tracked bounty programs")
    pl.set_defaults(func=dispatch_program_list)

    pt = sub.add_parser("templates", help="Report template library")
    tsub = pt.add_subparsers(dest="templates_cmd", metavar="COMMAND")
    tl = tsub.add_parser("list", help="List report templates")
    tl.set_defaults(func=dispatch_templates_list)
    ts = tsub.add_parser("show", help="Print a report template")
    ts.add_argument("name", help="Template name")
    ts.set_defaults(func=dispatch_templates_show)
    ti = tsub.add_parser("init", help="Write starter templates")
    ti.set_defaults(func=dispatch_templates_init)
    return sub


def dispatch_program_add(args, ctx):
    entry = add_program(args.name, url=args.url, scope=args.scope,
                        notes=args.notes)
    print("Program '%s' saved." % entry["name"])
    return 0


def dispatch_program_list(args, ctx):
    from rich.console import Console
    from rich.table import Table

    programs = list_programs()
    if not programs:
        print("No programs tracked yet. Add one with: arsenal program add <name>")
        return 0
    try:
        console = Console()
        table = Table(title="Bounty programs")
        for col in ("Name", "URL", "Scope", "Notes"):
            table.add_column(col)
        for p in programs:
            table.add_row(p.get("name", ""), p.get("url", "")[:40],
                          p.get("scope", "")[:40], p.get("notes", "")[:40])
        console.print(table)
    except Exception:
        for p in programs:
            print("- %s (%s)" % (p.get("name"), p.get("url")))
    return 0


def dispatch_templates_list(args, ctx):
    names = list_report_templates()
    if not names:
        print("No templates in %s. Run: arsenal templates init" % TEMPLATES_DIR)
        return 0
    print("Report templates in %s:" % TEMPLATES_DIR)
    for name in names:
        print("  - %s" % name)
    return 0


def dispatch_templates_show(args, ctx):
    text = get_report_template(args.name)
    if text is None:
        print("Template %r not found." % args.name)
        return 1
    print(text)
    return 0


def dispatch_templates_init(args, ctx):
    written = init_report_templates()
    if written:
        for path in written:
            print("Wrote %s" % path)
    else:
        print("Starter templates already present in %s" % TEMPLATES_DIR)
    return 0


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
                force=getattr(args, "force", False),
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
