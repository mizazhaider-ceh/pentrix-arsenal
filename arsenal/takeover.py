"""CONTINUOUS TAKEOVER MONITORING.

Differentiator #10. subzy/subjack are one-shot; Osmedeus scans
continuously but never diffs. This module re-checks dangling DNS
records on a schedule and alerts only on what is NEWLY claimable
since the last run.

It builds on recon_mod's triage (_takeover_candidate via DNS-over-HTTPS
plus the dead-service suffix list) and adds:

* persistent state per target in the workspace (takeover_state.json),
* diffing: newly dangling, newly claimable, resolved-since-last-run,
* alert findings only for newly claimable records,
* importable functions so the scheduler (cron/arsenal monitor) can call
  check_targets(targets, workspace) on whatever cadence the hunter wants.

Provider API::

    from arsenal import takeover
    report = takeover.check_targets(["a.example.com"], workspace)
    # report["alerts"] -> finding dicts for newly claimable records
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from arsenal.modules.recon_mod import (
    _takeover_candidate,
    _doh_cname,
    _resolves,
    DEAD_SERVICE_SUFFIXES,
)

STATE_NAME = "takeover_state.json"


def _state_path(workspace) -> str:
    base = workspace.path("monitor") if hasattr(workspace, "path") else None
    if base is None:
        from pathlib import Path
        base = Path.home() / ".arsenal" / "monitor"
    os.makedirs(str(base), exist_ok=True)
    return os.path.join(str(base), STATE_NAME)


def load_state(workspace) -> dict:
    path = _state_path(workspace)
    if not os.path.exists(path):
        return {"hosts": {}}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {"hosts": {}}
    except (OSError, ValueError):
        return {"hosts": {}}


def save_state(workspace, state: dict) -> str:
    path = _state_path(workspace)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
    os.replace(tmp, path)
    return path


def check_host(host: str) -> dict:
    """Check one host now. Returns a status dict (never raises)."""
    now = datetime.now(timezone.utc).isoformat()
    try:
        cname = _doh_cname(host)
    except Exception as exc:  # noqa: BLE001 - per-host probe
        return {"host": host, "status": "error", "error": str(exc), "ts": now}
    if not cname:
        return {"host": host, "status": "no_cname", "cname": None, "ts": now}
    dead = any(cname == s or cname.endswith("." + s)
               for s in DEAD_SERVICE_SUFFIXES)
    if not dead:
        return {"host": host, "status": "cname_alive_service",
                "cname": cname, "ts": now}
    try:
        dangling = not _resolves(cname)
    except Exception as exc:  # noqa: BLE001
        return {"host": host, "status": "error", "error": str(exc), "ts": now}
    return {"host": host,
            "status": "claimable" if dangling else "dangling_resolves",
            "cname": cname, "ts": now}


def check_targets(hosts, workspace) -> dict:
    """Re-check hosts, diff against stored state, alert on newly claimable.

    Returns {"checked": [...], "alerts": [finding, ...], "changes": [...]}.
    """
    from arsenal.findings import make_finding
    state = load_state(workspace)
    old_hosts = state.get("hosts", {})
    alerts, changes, checked = [], [], []
    for host in hosts:
        cur = check_host(host)
        checked.append(cur)
        prev = old_hosts.get(host, {})
        prev_status = prev.get("status")
        cur_status = cur["status"]
        state["hosts"][host] = cur
        if cur_status != prev_status:
            changes.append({"host": host, "from": prev_status,
                            "to": cur_status, "cname": cur.get("cname")})
        if cur_status == "claimable" and prev_status != "claimable":
            alerts.append(make_finding(
                "takeover", host, "high",
                "NEWLY claimable subdomain: %s -> %s" % (host, cur["cname"]),
                "Continuous monitoring detected that %s now points at the "
                "dangling record %s (previously: %s). The CNAME target does "
                "not resolve and matches a historically claimable service "
                "suffix. Verify by attempting to claim the service resource, "
                "then report immediately." % (
                    host, cur["cname"], prev_status or "unknown"),
                evidence="cname=%s previous=%s" % (cur["cname"], prev_status),
                confidence="strong",
                remediation="Remove the dangling DNS record or reclaim the "
                            "service resource. Audit all CNAMEs on a "
                            "schedule; this monitor does that for you."))
        elif cur_status == "claimable" and prev_status == "claimable":
            changes.append({"host": host, "from": "claimable",
                            "to": "claimable (still open)",
                            "cname": cur.get("cname")})
    state["last_run"] = datetime.now(timezone.utc).isoformat()
    save_state(workspace, state)
    return {"checked": checked, "alerts": alerts, "changes": changes,
            "state_path": _state_path(workspace)}


ARGPARSE_SNIPPET = '''
# --- integrator: add to arsenal/cli.py subparsers ---
p = sub.add_parser("takeover", help="Continuous takeover monitoring")
t = p.add_argument("--hosts", nargs="+", required=True,
                   help="Hostnames to re-check")
p.add_argument("--json", action="store_true")
p.set_defaults(func=arsenal.takeover.cmd_takeover)
'''


def cmd_takeover(args, ctx) -> int:
    report = check_targets(args.hosts, ctx.workspace)
    if args.json:
        print(json.dumps(report, indent=2, default=str))
        return 0
    print("checked %d host(s), %d change(s), %d NEW claimable" % (
        len(report["checked"]), len(report["changes"]), len(report["alerts"])))
    for c in report["changes"]:
        print("  %s: %s -> %s (%s)" % (
            c["host"], c["from"], c["to"], c.get("cname") or "-"))
    for a in report["alerts"]:
        print("[HIGH] %s" % a["title"])
    print("state: %s" % report["state_path"])
    print("Schedule this (cron/arsenal monitor) to keep the diff alerts coming.")
    return 0
