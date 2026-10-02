"""AGENTIC AUTOPILOT for PENTRIX ARSENAL.

Runs a bounded sense-plan-act loop over a target's workspace:

  (a) ensure baseline recon state exists (pipeline.run_pipeline in event mode),
  (b) PLANNER (rule-based): score candidate actions and pick the best,
  (c) execute the chosen modules via the module REGISTRY,
  (d) triage new findings via arsenal.triage.triage_all,
  (e) persist the decision to hunt_memory.jsonl.

Library functions never print; the CLI entry points below may.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import types

try:
    from arsenal.modules import REGISTRY  # owned by another builder
except Exception:  # modules package not populated yet
    REGISTRY = None


# --------------------------------------------------------------------------
# defensive helpers (local copies; other builders' helpers are optional)
# --------------------------------------------------------------------------

def _log(ctx, level: str, msg: str) -> None:
    log = getattr(ctx, "log", None)
    fn = getattr(log, level, None) if log is not None else None
    if callable(fn):
        try:
            fn(msg)
        except Exception:
            pass


def _ws_call(ws, method: str, default=None, *args):
    if ws is None:
        return default
    fn = getattr(ws, method, None)
    if not callable(fn):
        return default
    try:
        return fn(*args)
    except Exception:
        return default


def _get_registry():
    reg = globals().get("REGISTRY")
    if reg is not None:
        return reg
    try:
        import arsenal.modules as mods
        return getattr(mods, "REGISTRY", None) or {}
    except Exception:
        return {}


def _workspace_dir(ctx, target):
    ws = getattr(ctx, "workspace", None)
    p = _ws_call(ws, "path", None, target)
    if not p:
        return None
    try:
        os.makedirs(p, exist_ok=True)
    except Exception:
        pass
    return p


def _get_findings(ctx, target):
    ws = getattr(ctx, "workspace", None)
    f = _ws_call(ws, "get_findings", None, target)
    if f is None:
        f = _ws_call(ws, "all_findings", None, target)
    if f is None:
        f = getattr(ws, "findings", None)
    if isinstance(f, dict):
        f = f.get(target, [])
    return [x for x in (f or []) if isinstance(x, dict)]


def _get_tech(ctx, target):
    ws = getattr(ctx, "workspace", None)
    t = _ws_call(ws, "get_tech", None, target)
    if t is None:
        t = getattr(ws, "tech", None)
    if isinstance(t, dict):
        t = t.get(target, [])
    return list(t or [])


def _get_hosts(ctx, target):
    ws = getattr(ctx, "workspace", None)
    h = _ws_call(ws, "get_hosts", None, target)
    if h is None:
        h = getattr(ws, "hosts", None)
    if isinstance(h, dict):
        h = h.get(target, [])
    hosts = [str(x) for x in (h or []) if x]
    if hosts:
        return hosts
    seen = []
    for f in _get_findings(ctx, target):
        host = f.get("host")
        if host and str(host) not in seen:
            seen.append(str(host))
    return seen


def _get_coverage(ctx, target):
    ws = getattr(ctx, "workspace", None)
    c = _ws_call(ws, "get_coverage", None, target)
    if c is None:
        c = getattr(ws, "coverage", None)
    if isinstance(c, dict):
        return c.get(target, c) if target in c else c
    return {}


def _store_findings(ctx, target, findings):
    """Persist findings back to the workspace using whatever API exists."""
    ws = getattr(ctx, "workspace", None)
    if ws is None or not findings:
        return False
    appender = getattr(ws, "append_findings", None)
    if callable(appender):
        try:
            appender(target, findings)
            return True
        except TypeError:
            try:
                appender(findings)
                return True
            except Exception:
                pass
        except Exception:
            pass
    saver = getattr(ws, "save_findings", None)
    if callable(saver):
        try:
            saver(target, findings)
            return True
        except Exception:
            return False
    return False


def _memory_path(ctx, target):
    d = _workspace_dir(ctx, target)
    if not d:
        return None
    return os.path.join(d, "hunt_memory.jsonl")


def _append_memory(ctx, target, record: dict) -> bool:
    p = _memory_path(ctx, target)
    if not p:
        return False
    try:
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
        return True
    except Exception as e:
        _log(ctx, "error", "Could not append hunt memory: %s" % e)
        return False


# --------------------------------------------------------------------------
# (a) baseline recon state
# --------------------------------------------------------------------------

def _baseline_exists(ctx, target) -> bool:
    if _get_findings(ctx, target) or _get_tech(ctx, target):
        return True
    d = _workspace_dir(ctx, target)
    if d and os.path.exists(os.path.join(d, "state.json")):
        return True
    cov = _get_coverage(ctx, target)
    return bool(cov)


def _ensure_baseline(ctx, target) -> bool:
    """Run the pipeline in event mode when no recon state exists yet."""
    if _baseline_exists(ctx, target):
        return True
    try:
        from arsenal import pipeline  # owned by another builder
    except Exception as e:
        _log(ctx, "warning", "pipeline module unavailable, skipping baseline: %s" % e)
        return False
    fn = getattr(pipeline, "run_pipeline", None)
    if not callable(fn):
        _log(ctx, "warning", "pipeline.run_pipeline not available, skipping baseline")
        return False
    try:
        try:
            fn(target, ctx, event_mode=True)
        except TypeError:
            fn(target, ctx)
        _log(ctx, "info", "Baseline pipeline run finished for %s" % target)
        return True
    except Exception as e:
        _log(ctx, "error", "Baseline pipeline failed: %s" % e)
        return False


# --------------------------------------------------------------------------
# (b) rule-based planner
# --------------------------------------------------------------------------

_SCORES = {
    "login_page": 90,
    "api_endpoint": 80,
    "untriaged_high": 70,
    "unscanned_host": 50,
    "new_tech": 40,
}

_REPEAT_PENALTY = 60

_WEB_MODULES = {
    "web", "webscan", "nikto", "dirscan", "direnum", "crawl", "whatweb",
    "jsintel", "fuzz",
}

# Registry module names to try per action kind (first existing wins).
_MODULE_HINTS = {
    "login_page": ["webauth", "auth", "login", "brute"],
    "api_endpoint": ["apiscan", "api", "jsintel"],
    "untriaged_high": ["verify", "retest", "confirm"],
    "unscanned_host": ["webscan", "web", "nikto", "direnum"],
    "new_tech": ["tech", "fingerprint"],
}


def _triaged(f: dict) -> bool:
    return bool(f.get("triaged")) or bool(f.get("verdict"))


def plan_actions(target, ctx):
    """Build scored candidate actions from workspace state.

    Returns a list of dicts with keys: kind, detail, score, reason, modules.
    Library function; never prints.
    """
    findings = _get_findings(ctx, target)
    tech = _get_tech(ctx, target)
    hosts = _get_hosts(ctx, target)
    coverage = _get_coverage(ctx, target) or {}
    registry = _get_registry()

    actions = []

    for f in findings:
        text = ("%s %s" % (f.get("title", ""), f.get("url", ""))).lower()
        if "login" in text or "sign in" in text or "auth page" in text:
            mods = [m for m in _MODULE_HINTS["login_page"] if m in registry]
            actions.append({
                "kind": "login_page",
                "detail": f.get("url") or f.get("title") or "login page",
                "score": _SCORES["login_page"],
                "reason": "Login page discovered and never tested: %s" % (f.get("title") or "?"),
                "modules": mods,
                "finding": f,
            })
        if str(f.get("module", "")).lower() == "jsintel" and "api" in text:
            mods = [m for m in _MODULE_HINTS["api_endpoint"] if m in registry]
            actions.append({
                "kind": "api_endpoint",
                "detail": f.get("url") or f.get("title") or "api endpoint",
                "score": _SCORES["api_endpoint"],
                "reason": "API endpoint surfaced by jsintel: %s" % (f.get("title") or "?"),
                "modules": mods,
                "finding": f,
            })
        sev = str(f.get("severity", "")).lower()
        if sev in ("high", "critical") and not _triaged(f):
            mods = [m for m in _MODULE_HINTS["untriaged_high"] if m in registry]
            actions.append({
                "kind": "untriaged_high",
                "detail": f.get("title") or "high finding",
                "score": _SCORES["untriaged_high"],
                "reason": "Untriaged %s finding: %s" % (sev, f.get("title") or "?"),
                "modules": mods,
                "finding": f,
            })

    covered_web = set()
    if isinstance(coverage, dict):
        for host, cov in coverage.items():
            if isinstance(cov, dict) and cov.get("web"):
                covered_web.add(str(host))
    for f in findings:
        if str(f.get("module", "")).lower() in _WEB_MODULES and f.get("host"):
            covered_web.add(str(f.get("host")))
    for host in hosts:
        if host not in covered_web:
            mods = [m for m in _MODULE_HINTS["unscanned_host"] if m in registry]
            actions.append({
                "kind": "unscanned_host",
                "detail": host,
                "score": _SCORES["unscanned_host"],
                "reason": "Host %s has no web scan coverage yet" % host,
                "modules": mods,
            })

    for t in tech:
        name = t.get("name") or t.get("tech") or str(t)
        if isinstance(t, dict) and t.get("new"):
            mods = [m for m in _MODULE_HINTS["new_tech"] if m in registry]
            actions.append({
                "kind": "new_tech",
                "detail": name,
                "score": _SCORES["new_tech"],
                "reason": "New technology detected: %s" % name,
                "modules": mods,
            })

    # Drop actions that have no executable module; triage-only action is fine.
    kept = []
    for a in actions:
        if a["kind"] == "untriaged_high" or a["modules"]:
            kept.append(a)
    kept.sort(key=lambda a: a["score"], reverse=True)
    return kept


def _penalize_repeats(actions, done):
    """Lower the score of actions already taken this run so the loop advances."""
    for a in actions:
        if (a["kind"], str(a["detail"])) in done:
            a = dict(a)
            a["score"] = max(0, a["score"] - _REPEAT_PENALTY)
        yield a


# --------------------------------------------------------------------------
# (c) execution
# --------------------------------------------------------------------------

def _scoped_ctx(ctx, intrusive: bool, passive: bool):
    """Return a shallow ctx copy with adjusted safety flags for this run."""
    data = {k: getattr(ctx, k) for k in dir(ctx) if not k.startswith("__")}
    data["safe_mode"] = bool(passive) or (not intrusive and getattr(ctx, "safe_mode", True))
    data["allow_intrusive"] = bool(intrusive) or getattr(ctx, "allow_intrusive", False)
    return types.SimpleNamespace(**data)


def _run_module(name, target, ctx):
    """Run one registry module defensively. Returns list of new findings."""
    registry = _get_registry()
    mod = registry.get(name)
    if mod is None:
        return []
    run = getattr(mod, "run", None)
    if not callable(run):
        return []
    before = _get_findings(ctx, target)
    before_keys = {(f.get("title"), f.get("module"), f.get("host")) for f in before}
    returned = []
    try:
        res = run(target, ctx)
    except Exception as e:
        _log(ctx, "error", "Module %s failed: %s" % (name, e))
        return []
    if isinstance(res, list):
        returned = [f for f in res if isinstance(f, dict)]
    after = _get_findings(ctx, target)
    new = [f for f in returned
           if (f.get("title"), f.get("module"), f.get("host")) not in before_keys]
    for f in after:
        key = (f.get("title"), f.get("module"), f.get("host"))
        if key not in before_keys and all(
                (g.get("title"), g.get("module"), g.get("host")) != key for g in new):
            new.append(f)
    return new


def execute_action(action, target, ctx):
    """Execute an action. Returns (modules_run, new_findings). Never raises."""
    modules_run = []
    new_findings = []
    if action["kind"] == "untriaged_high":
        # The action itself is triage: verify first if a verifier exists,
        # then triage the finding in place.
        f = action.get("finding") or {}
        for name in action["modules"]:
            new_findings.extend(_run_module(name, target, ctx))
            modules_run.append(name)
        try:
            from arsenal import triage  # owned by another builder
            triaged = triage.triage_all([f], ctx)
        except Exception as e:
            _log(ctx, "warning", "triage.triage_all unavailable: %s" % e)
            triaged = [dict(f, triaged=True, verdict="needs_manual_review")]
        _store_findings(ctx, target, triaged)
        new_findings.extend(triaged)
        return modules_run, new_findings
    for name in action["modules"]:
        new_findings.extend(_run_module(name, target, ctx))
        modules_run.append(name)
    return modules_run, new_findings


def _triage_new(findings, ctx):
    try:
        from arsenal import triage  # owned by another builder
    except Exception as e:
        _log(ctx, "warning", "triage module unavailable: %s" % e)
        return findings
    try:
        return triage.triage_all(findings, ctx)
    except Exception as e:
        _log(ctx, "error", "triage_all failed: %s" % e)
        return findings


# --------------------------------------------------------------------------
# autopilot loop
# --------------------------------------------------------------------------

def run_autopilot(target, ctx, max_cycles=5, intrusive=False, passive=False):
    """Run the sense-plan-act loop. Returns a summary dict. Never prints."""
    run_ctx = _scoped_ctx(ctx, intrusive, passive)
    _ensure_baseline(run_ctx, target)
    done = set()
    cycles = []
    for cycle in range(1, max_cycles + 1):
        actions = list(_penalize_repeats(plan_actions(target, run_ctx), done))
        actions.sort(key=lambda a: a["score"], reverse=True)
        best = actions[0] if actions else None
        if best is None or best["score"] <= 20:
            cycles.append({"cycle": cycle, "decision": "stop",
                           "reason": "No actions scored above 20; hunt is quiet."})
            break
        modules_run, new_findings = execute_action(best, target, run_ctx)
        triaged = _triage_new(new_findings, run_ctx) if best["kind"] != "untriaged_high" else new_findings
        if best["kind"] != "untriaged_high" and triaged:
            _store_findings(run_ctx, target, triaged)
        record = {
            "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "cycle": cycle,
            "decision": best["kind"],
            "reason": best["reason"],
            "modules": modules_run,
            "new_findings": len(triaged),
            "kind": "decision",
        }
        _append_memory(run_ctx, target, record)
        done.add((best["kind"], str(best["detail"])))
        cycles.append({
            "cycle": cycle,
            "decision": best["kind"],
            "reason": best["reason"],
            "modules": modules_run,
            "new_findings": len(triaged),
            "plan": [(a["kind"], a["detail"], a["score"]) for a in actions[:5]],
        })
    return {"target": target, "cycles": cycles}


# --------------------------------------------------------------------------
# CLI: arsenal autopilot <target> [--max-cycles N] [--intrusive] [--passive]
# --------------------------------------------------------------------------

def _print_cycle(console, target, info):
    plan = info.get("plan") or []
    if not plan:
        return
    try:
        from rich.table import Table
        table = Table(title="Autopilot cycle %d for %s" % (info["cycle"], target))
        table.add_column("Score", justify="right")
        table.add_column("Action")
        table.add_column("Detail")
        for kind, detail, score in plan:
            mark = " <-- chosen" if kind == info["decision"] else ""
            table.add_row(str(score), kind + mark, str(detail))
        console.print(table)
        console.print("Reason: %s" % info.get("reason", ""))
        console.print("Modules: %s | New findings: %d"
                      % (", ".join(info.get("modules") or []) or "none",
                         info.get("new_findings", 0)))
    except Exception:
        print("Cycle %d plan for %s:" % (info["cycle"], target))
        for kind, detail, score in plan:
            print("  [%d] %s: %s" % (score, kind, detail))
        print("  Chosen: %s (%s)" % (info["decision"], info.get("reason", "")))


def cmd_autopilot(args, ctx):
    try:
        from rich.console import Console
        console = Console()
    except Exception:
        console = None

    summary = run_autopilot(
        args.target, ctx,
        max_cycles=args.max_cycles,
        intrusive=args.intrusive,
        passive=args.passive,
    )
    for info in summary["cycles"]:
        if info["decision"] == "stop":
            msg = "Autopilot finished: %s" % info["reason"]
            if console:
                console.print("[green]%s[/green]" % msg)
            else:
                print(msg)
            break
        if console:
            _print_cycle(console, args.target, info)
        else:
            _print_cycle(None, args.target, info)
    path = _memory_path(ctx, args.target)
    tail = "Decisions logged to %s" % path if path else "Hunt memory not persisted (no workspace path)."
    if console:
        console.print("[dim]%s[/dim]" % tail)
    else:
        print(tail)
    return 0


def add_parsers(sub):
    p = sub.add_parser("autopilot", help="Run the agentic recon loop against a target")
    p.add_argument("target", help="Target identifier (as stored in the workspace)")
    p.add_argument("--max-cycles", type=int, default=5,
                   help="Maximum sense-plan-act cycles (default 5)")
    p.add_argument("--intrusive", action="store_true",
                   help="Allow intrusive modules (respects ctx.allow_intrusive otherwise)")
    p.add_argument("--passive", action="store_true",
                   help="Passive-only mode: recon without touching the target")
    p.set_defaults(func=cmd_autopilot)
    return p


def dispatch(args, ctx):
    func = getattr(args, "func", None)
    if callable(func):
        return func(args, ctx)
    raise ValueError("no command dispatch configured for autopilot")
