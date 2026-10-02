"""PENTRIX ARSENAL goal tracker and time tracking.

Goals: monthly bounty target from config, with progress computed from paid
findings (status "paid") dated in the current month across all workspaces.

Time: hours logged per target in ~/.arsenal/time.json.

Library code in this module never prints; only ``dispatch`` prints.
"""

import argparse
import json
import os
from datetime import datetime
from pathlib import Path

DEFAULT_CURRENCY = "EUR"


# ---------------------------------------------------------------------------
# Goals
# ---------------------------------------------------------------------------

def get_goal(ctx):
    """Return {"monthly_target": float, "currency": str} from ctx.config."""
    cfg = getattr(ctx, "config", None) or {}
    try:
        target = float(cfg.get("monthly_target", 0.0) or 0.0)
    except (TypeError, ValueError):
        target = 0.0
    currency = cfg.get("currency", DEFAULT_CURRENCY) or DEFAULT_CURRENCY
    return {"monthly_target": target, "currency": str(currency)}


def set_goal(ctx, amount):
    """Set the monthly target in ctx.config and persist if possible."""
    cfg = getattr(ctx, "config", None)
    if cfg is None:
        raise ValueError("ctx has no config to store the goal in")
    cfg["monthly_target"] = float(amount)
    save = getattr(ctx, "save_config", None)
    if callable(save):
        save()
    return get_goal(ctx)


def _findings_files(ctx):
    """Yield findings.json paths: current workspace plus sibling workspaces."""
    seen = set()
    candidates = []
    workspace = getattr(ctx, "workspace", None)
    root = getattr(ctx, "workspaces_root", None)
    if workspace is not None:
        wroot = getattr(workspace, "root", None)
        if wroot:
            root = root or os.path.expanduser(str(wroot))
    if root:
        try:
            for child in sorted(Path(root).iterdir()):
                if child.is_dir():
                    candidates.append(child)
        except OSError:
            pass
    for base in candidates:
        path = (base / "findings.json").resolve()
        if path not in seen:
            seen.add(path)
            if path.exists():
                yield path


def _iter_findings(ctx):
    for path in _findings_files(ctx):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            data = data.get("findings", [])
        if not isinstance(data, list):
            continue
        for item in data:
            if isinstance(item, dict):
                yield item


def progress(ctx):
    """Return {"target", "currency", "paid_this_month", "pct"}.

    Sums payout of findings with status "paid" dated in the current month
    across every workspace's findings.json.
    """
    goal = get_goal(ctx)
    target = goal["monthly_target"]
    month = datetime.now().strftime("%Y-%m")
    paid = 0.0
    for item in _iter_findings(ctx):
        if str(item.get("status", "")).lower() != "paid":
            continue
        if not str(item.get("date", "")).startswith(month):
            continue
        try:
            paid += float(item.get("payout", 0) or 0)
        except (TypeError, ValueError):
            continue
    pct = (paid / target * 100.0) if target > 0 else 0.0
    return {
        "target": target,
        "currency": goal["currency"],
        "paid_this_month": round(paid, 2),
        "pct": round(pct, 1),
    }


# ---------------------------------------------------------------------------
# Time tracking: ~/.arsenal/time.json -> {"target": hours}
# ---------------------------------------------------------------------------

def _time_path():
    return Path.home() / ".arsenal" / "time.json"


def _load_time():
    path = _time_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_time(data):
    path = _time_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def log_time(target, hours):
    """Add hours for a target. Returns the new total for that target."""
    data = _load_time()
    try:
        current = float(data.get(target, 0.0) or 0.0)
    except (TypeError, ValueError):
        current = 0.0
    total = round(current + float(hours), 2)
    data[target] = total
    _save_time(data)
    return total


def time_report():
    """Return {target: hours} sorted by hours descending."""
    data = _load_time()
    cleaned = {}
    for target, hours in data.items():
        try:
            cleaned[str(target)] = float(hours)
        except (TypeError, ValueError):
            continue
    return dict(sorted(cleaned.items(), key=lambda kv: kv[1], reverse=True))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def add_parsers(sub):
    g = sub.add_parser("goal", help="Monthly bounty goal tracker")
    g.add_argument("action", nargs="?", default="show",
                   choices=["show", "set", "progress"],
                   help="show the goal, set a new amount, or show progress")
    g.add_argument("amount", nargs="?", type=float, default=None,
                   help="New monthly target amount (for 'set')")
    g.set_defaults(cmd="goal", func=dispatch)

    t = sub.add_parser("time", help="Time tracking per target")
    t.add_argument("action", nargs="?", default="report",
                   choices=["log", "report"],
                   help="log hours for a target or show the report")
    t.add_argument("target", nargs="?", default=None, help="Target name")
    t.add_argument("hours", nargs="?", type=float, default=None,
                   help="Hours to log (for 'log')")
    t.set_defaults(cmd="time", func=dispatch)
    return g


def _print_goal_table(goal):
    try:
        from rich.console import Console
        from rich.table import Table
        table = Table(title="Monthly goal")
        table.add_column("Target")
        table.add_column("Currency")
        table.add_row("%.2f" % goal["monthly_target"], goal["currency"])
        Console().print(table)
    except Exception:
        print("Monthly target: %.2f %s"
              % (goal["monthly_target"], goal["currency"]))


def _print_progress_table(result):
    try:
        from rich.console import Console
        from rich.table import Table
        table = Table(title="Goal progress (this month)")
        table.add_column("Target")
        table.add_column("Paid this month")
        table.add_column("Progress")
        table.add_row("%.2f %s" % (result["target"], result["currency"]),
                      "%.2f %s" % (result["paid_this_month"],
                                   result["currency"]),
                      "%.1f%%" % result["pct"])
        Console().print(table)
    except Exception:
        print("Target: %.2f %s | Paid this month: %.2f %s | Progress: %.1f%%"
              % (result["target"], result["currency"],
                 result["paid_this_month"], result["currency"], result["pct"]))


def _print_time_table(report):
    try:
        from rich.console import Console
        from rich.table import Table
        table = Table(title="Time tracked per target")
        table.add_column("Target")
        table.add_column("Hours")
        for target, hours in report.items():
            table.add_row(target, "%.2f" % hours)
        Console().print(table)
    except Exception:
        print("Target | Hours")
        for target, hours in report.items():
            print("%s | %.2f" % (target, hours))


def dispatch(args, ctx):
    cmd = getattr(args, "cmd", "goal")
    if cmd == "goal":
        if args.action == "set":
            if args.amount is None:
                print("Usage: arsenal goal set <amount>")
                return
            goal = set_goal(ctx, args.amount)
            print("Monthly goal set to %.2f %s."
                  % (goal["monthly_target"], goal["currency"]))
        elif args.action == "progress":
            _print_progress_table(progress(ctx))
        else:
            _print_goal_table(get_goal(ctx))
    elif cmd == "time":
        if args.action == "log":
            if args.target is None or args.hours is None:
                print("Usage: arsenal time log <target> <hours>")
                return
            total = log_time(args.target, args.hours)
            print("Logged %.2f h for %s (total %.2f h)."
                  % (args.hours, args.target, total))
        else:
            report = time_report()
            if not report:
                print("No time logged yet.")
            else:
                _print_time_table(report)
    else:
        raise ValueError("unknown command: %r" % (cmd,))
