"""Command history and per-target time tracking.

History: ~/.arsenal/sessions.jsonl, one {"ts": ..., "argv": [...]} per line.
Time:    ~/.arsenal/time.json, {"target": total_seconds}.
"""

import json
import os
from datetime import datetime, timezone

SESSIONS_FILE = os.path.expanduser("~/.arsenal/sessions.jsonl")
TIME_FILE = os.path.expanduser("~/.arsenal/time.json")


def _ensure_parent(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def log_command(argv):
    """Append {"ts": ..., "argv": [...]} to the session history."""
    _ensure_parent(SESSIONS_FILE)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "argv": [str(a) for a in argv],
    }
    with open(SESSIONS_FILE, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


def _load_commands():
    commands = []
    try:
        with open(SESSIONS_FILE, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    commands.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    return commands


def record_time(target, seconds):
    """Accumulate seconds spent against a target."""
    data = {}
    try:
        with open(TIME_FILE, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
            if isinstance(loaded, dict):
                data = loaded
    except (OSError, ValueError):
        data = {}
    key = str(target)
    data[key] = float(data.get(key, 0.0)) + float(seconds)
    _ensure_parent(TIME_FILE)
    tmp = TIME_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, TIME_FILE)


def get_time(target):
    """Return total seconds recorded for a target (0.0 when unknown)."""
    try:
        with open(TIME_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return float(data.get(str(target), 0.0))
    except (OSError, ValueError, TypeError):
        return 0.0


def add_parsers(subparsers):
    """Register `arsenal replay [--list | --last N]`."""
    p = subparsers.add_parser("replay", help="Show previously run arsenal commands")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--list", action="store_true",
                       help="List recorded commands")
    group.add_argument("--last", type=int, metavar="N",
                       help="Show only the last N commands")
    p.set_defaults(func=dispatch)


def dispatch(args, ctx):
    """Print recorded commands; returns exit code int."""
    commands = _load_commands()
    if getattr(args, "last", None):
        commands = commands[-args.last:]
    else:
        commands = commands[-200:]
    if not commands:
        print("no recorded commands yet")
        return 0
    for i, entry in enumerate(commands, 1):
        ts = entry.get("ts", "?")
        argv = entry.get("argv", [])
        print("%4d  %s  %s" % (i, ts, " ".join(argv)))
    return 0
