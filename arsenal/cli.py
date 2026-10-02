"""Command line interface for PENTRIX ARSENAL.

Feature-file contract: any arsenal/<name>.py feature module may expose
add_parsers(subparsers) which registers its subcommand(s), and each
subcommand must set_defaults(func=<dispatch>) where
dispatch(args, ctx) -> int is the exit code.

Global flags: --verbose, --workspace-root.

Safety behaviour:
* Scope firewall: before ANY recon/scan, when a scope is loaded
  (--scope-file or the workspace scope.json), a target outside the
  scope refuses with exit code 2.
* Safe-mode guardrail: intrusive modules need --intrusive, otherwise
  the run refuses (single module) or skips (scan --all) with a message.
* Passive mode (--passive): zero packets to the target; only recon,
  cve and wayback data are used.
* Every invocation is logged via session.log_command and timed via
  session.record_time(target, seconds).
"""

import argparse
import importlib
import ipaddress
import json
import os
import sys
import time
from urllib.parse import urlsplit

from arsenal import __version__
from arsenal import config as config_mod
from arsenal import logging_setup
from arsenal import session as session_mod
from arsenal import workspace as workspace_mod
from arsenal.context import make_ctx


# -- scope ---------------------------------------------------------------

class SimpleScope:
    """Minimal scope object exposing .contains(host) -> bool."""

    def __init__(self, entries):
        self.entries = [str(e).strip() for e in entries if str(e).strip()]

    def contains(self, host):
        text = str(host).strip()
        if "://" in text:
            text = urlsplit(text).hostname or text
        text = text.split("/")[0].lower()
        for entry in self.entries:
            ent = entry.lower()
            if "/" in ent:
                try:
                    if ipaddress.ip_address(text) in ipaddress.ip_network(ent, strict=False):
                        return True
                except ValueError:
                    pass
                continue
            if text == ent or text.endswith("." + ent):
                return True
        return False


def load_scope(scope_file=None, workspace_root="~/.arsenal/workspaces",
               target=None):
    """Load a scope for the firewall.

    Accepts .txt / .csv / .json via arsenal.scope.Scope. Checks, in order:
    --scope-file, the target's workspace scope.json, ~/.arsenal/scope.json.
    Returns a Scope-like object with .contains(host) or None.
    """
    candidates = []
    if scope_file:
        candidates.append(os.path.expanduser(scope_file))
    if target:
        try:
            safe = workspace_mod.Workspace.safe_name(target)
            candidates.append(os.path.join(
                os.path.expanduser(workspace_root), safe, "scope.json"))
        except Exception:
            pass
    candidates.append(os.path.join(
        os.path.dirname(os.path.expanduser(workspace_root)), "scope.json"))
    try:
        from arsenal.scope import Scope
    except ImportError:
        return None
    for path in candidates:
        if not path or not os.path.isfile(path):
            continue
        try:
            scope = Scope.load(path)
        except Exception:
            continue
        if scope and scope.domains():
            return scope
    return None


# -- subcommand builders ---------------------------------------------------

def _add_recon(sub):
    p = sub.add_parser("recon", help="Run the event-driven recon pipeline")
    p.add_argument("target", help="Domain, IP or URL to recon")
    p.add_argument("--scope-file", default=None, help="Path to a scope JSON file")
    p.add_argument("--intrusive", action="store_true",
                   help="Allow intrusive modules")
    p.add_argument("--passive", action="store_true",
                   help="Passive-only mode: no packets sent to the target")
    p.add_argument("--resume", action="store_true",
                   help="Resume a previous interrupted run from saved state")
    p.set_defaults(func=_cmd_recon)


def _add_scan(sub):
    p = sub.add_parser("scan", help="Run one or all scan modules")
    p.add_argument("target", help="Domain, IP or URL to scan")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--module", metavar="NAME",
                       help="Run a single module from the registry")
    group.add_argument("--all", action="store_true",
                       help="Run every applicable module")
    p.add_argument("--scope-file", default=None, help="Path to a scope JSON file")
    p.add_argument("--intrusive", action="store_true",
                   help="Allow intrusive modules")
    p.add_argument("--passive", action="store_true",
                   help="Passive-only mode: recon and cve modules only")
    p.set_defaults(func=_cmd_scan)


def _add_triage(sub):
    p = sub.add_parser("triage", help="Re-triage stored findings for a target")
    p.add_argument("target", help="Target whose stored findings get re-triaged")
    p.set_defaults(func=_cmd_triage)


def _add_config_cmd(sub):
    p = sub.add_parser("config", help="Show or update configuration")
    p.add_argument("--show", action="store_true",
                   help="Print the effective configuration")
    p.add_argument("--set", action="append", metavar="k=v", default=[],
                   help="Set a config value (dotted keys allowed); repeatable")
    p.set_defaults(func=_cmd_config)


def _guarded_add(modname, subparsers):
    """Import arsenal.<modname> and call its add_parsers(); never raises."""
    try:
        mod = importlib.import_module("arsenal." + modname)
    except ImportError:
        return False
    add = getattr(mod, "add_parsers", None)
    if callable(add):
        try:
            add(subparsers)
        except Exception:
            return False
        return True
    return False


def build_parser():
    parser = argparse.ArgumentParser(
        prog="arsenal",
        description="PENTRIX ARSENAL %s: bug bounty / pentest automation" % __version__)
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose logging")
    parser.add_argument("--workspace-root", default="~/.arsenal/workspaces",
                        help="Workspace root directory")
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    _add_recon(sub)
    _add_scan(sub)
    _add_triage(sub)
    _add_config_cmd(sub)
    # Core feature files owned by this builder.
    _guarded_add("plugins", sub)
    _guarded_add("session", sub)   # registers `replay`
    # Other builders' feature files (report/monitor/crm own findings+stats).
    for name in ("report", "monitor", "crm", "ask", "scope", "lab",
                 "checklists", "goals", "autopilot", "memory", "workflows",
                 "serve", "pipeviz", "inbox", "payloads", "revshell",
                 "notify", "exporters", "dupcheck"):
        _guarded_add(name, sub)
    return parser


# -- helpers -----------------------------------------------------------------

def _make_progress():
    """Progress callback for the pipeline; rich only imported here."""
    try:
        from rich.console import Console
        console = Console()

        def _rich(stage, detail, done=False):
            mark = " [green]done[/green]" if done else ""
            console.print("[cyan]%s[/cyan] %s%s" % (stage, detail, mark))

        return _rich
    except ImportError:
        def _plain(stage, detail, done=False):
            suffix = " [done]" if done else ""
            print("[%s] %s%s" % (stage, detail, suffix))

        return _plain


def _print_summary(summary):
    print("-" * 64)
    print("target:   %s" % summary.get("target"))
    print("hosts:    %d" % len(summary.get("hosts", [])))
    findings = summary.get("findings", [])
    counts = {}
    for item in findings:
        sev = str(item.get("severity", "info")).lower()
        counts[sev] = counts.get(sev, 0) + 1
    print("findings: %d %s" % (len(findings), counts if counts else ""))
    print("chains:   %d" % len(summary.get("chains", [])))
    if summary.get("interrupted"):
        print("status:   interrupted (resume with --resume)")
    print("-" * 64)


def _passive_banner():
    print("=" * 64)
    print("PASSIVE MODE: no packets sent to target")
    print("=" * 64)


def _passive_allowed(name):
    from arsenal.pipeline import PASSIVE_MODULES
    return name in PASSIVE_MODULES or name.replace("_mod", "") in PASSIVE_MODULES


def _coerce(value):
    low = value.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low in ("none", "null"):
        return None
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def _set_dotted(cfg, dotted, value):
    parts = dotted.split(".")
    node = cfg
    for part in parts[:-1]:
        child = node.get(part)
        if not isinstance(child, dict):
            child = {}
            node[part] = child
        node = child
    node[parts[-1]] = value


# -- command handlers ------------------------------------------------------------

def _cmd_recon(args, ctx):
    from arsenal import pipeline
    if args.passive:
        _passive_banner()
    ctx.passive = bool(args.passive)
    ctx.resume = bool(args.resume)
    ctx.allow_intrusive = bool(args.intrusive) and not bool(args.passive)
    if args.intrusive and args.passive:
        print("note: --intrusive is ignored in passive mode")
    # Rich live dashboard on a real terminal, plain progress otherwise.
    use_dashboard = sys.stdout.isatty()
    if use_dashboard:
        try:
            from arsenal import dashboard as dash_mod
            result = dash_mod.run_dashboard(args.target, ctx,
                                            pipeline.run_pipeline)
            summary = result.get("pipeline_summary") or {}
            if result.get("error") and not summary:
                summary = {"target": args.target,
                           "error": result.get("error")}
        except Exception as exc:
            ctx.log.warning("dashboard failed, falling back: %s", exc)
            summary = pipeline.run_pipeline(args.target, ctx,
                                            progress=_make_progress())
    else:
        summary = pipeline.run_pipeline(args.target, ctx,
                                        progress=_make_progress())
    _print_summary(summary)
    return 1 if summary.get("error") else 0


def _cmd_scan(args, ctx):
    from arsenal import modules as modules_pkg
    from arsenal.pipeline import run_module
    registry = dict(modules_pkg.REGISTRY)
    # Plugin system: user plugins join the registry automatically.
    try:
        from arsenal import plugins as plugins_mod
        for pname, pmod in plugins_mod.load_plugins().items():
            registry.setdefault(pname, pmod)
    except Exception as exc:
        ctx.log.warning("plugin load failed: %s", exc)
    if args.all:
        names = sorted(registry.keys())
    else:
        names = [args.module]
    if args.passive:
        _passive_banner()
    ctx.passive = bool(args.passive)
    ctx.allow_intrusive = bool(args.intrusive) and not bool(args.passive)
    if args.intrusive and args.passive:
        print("note: --intrusive is ignored in passive mode")
    if not names:
        print("no modules registered")
        return 0
    ran = 0
    for name in names:
        mod = registry.get(name)
        if mod is None:
            msg = "unknown module '%s'" % name
            if registry:
                msg += "; available: %s" % ", ".join(sorted(registry))
            print("error: %s" % msg, file=sys.stderr)
            if not args.all:
                return 2
            continue
        if args.passive and not _passive_allowed(name):
            print("skipping '%s': not permitted in passive mode" % name)
            continue
        intrusive = bool(getattr(mod, "INTRUSIVE", False))
        if intrusive and ctx.safe_mode and not ctx.allow_intrusive:
            if args.all:
                print("skipping intrusive module '%s' (re-run with --intrusive)" % name)
                continue
            print("error: module '%s' is intrusive; re-run with --intrusive"
                  % name, file=sys.stderr)
            return 2
        res = run_module(mod, args.target, ctx)
        findings = res["findings"]
        try:
            ctx.workspace.save_scan(args.target, name, findings)
            ctx.workspace.append_findings(args.target, findings)
        except Exception as exc:
            ctx.log.warning("workspace save failed for %s: %s", name, exc)
        print("%s: %d findings" % (name, len(findings)))
        ran += 1
    if ran == 0:
        print("nothing ran")
    return 0


def _cmd_triage(args, ctx):
    from arsenal.pipeline import call_optional
    findings = ctx.workspace.all_findings(args.target)
    if not findings:
        print("no stored findings for target '%s'" % args.target)
        return 1
    result = call_optional("arsenal.triage", "triage_all", findings, ctx)
    triaged = result if isinstance(result, list) else findings
    try:
        ctx.workspace.write_findings(args.target, triaged)
    except Exception as exc:
        print("error: could not write findings: %s" % exc, file=sys.stderr)
        return 1
    print("re-triaged %d findings for %s" % (len(triaged), args.target))
    return 0


def _cmd_config(args, ctx):
    cfg = config_mod.load()
    if args.set:
        for item in args.set:
            if "=" not in item:
                print("error: --set expects k=v, got '%s'" % item, file=sys.stderr)
                return 2
            key, value = item.split("=", 1)
            _set_dotted(cfg, key.strip(), _coerce(value.strip()))
        try:
            config_mod.save(cfg)
        except OSError as exc:
            print("error: could not save config: %s" % exc, file=sys.stderr)
            return 1
        print("config updated")
    if args.show or not args.set:
        print(json.dumps(cfg, indent=2))
    return 0


# -- main --------------------------------------------------------------------------

def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    logger = logging_setup.setup(getattr(args, "verbose", False))
    cfg = config_mod.load()
    ws = workspace_mod.Workspace(root=getattr(args, "workspace_root",
                                              "~/.arsenal/workspaces"))

    scope = None
    command = getattr(args, "command", None)
    if command in ("recon", "scan"):
        scope = load_scope(getattr(args, "scope_file", None),
                           getattr(args, "workspace_root",
                                   "~/.arsenal/workspaces"),
                           target=getattr(args, "target", None))

    ctx = make_ctx(config=cfg, log=logger, workspace=ws, scope=scope,
                   safe_mode=cfg.get("safe_mode", True))

    logged_argv = list(sys.argv) if argv is None else ["arsenal"] + list(argv)
    if logged_argv:
        logged_argv[0] = "arsenal"
    try:
        session_mod.log_command(logged_argv)
    except Exception:
        pass

    # Scope firewall: enforced before any recon/scan work.
    if command in ("recon", "scan"):
        target = getattr(args, "target", None)
        if target and scope is not None and not scope.contains(target):
            print("error: target '%s' is outside the authorized scope; "
                  "refusing to scan" % target, file=sys.stderr)
            return 2

    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 2

    start = time.monotonic()
    try:
        rc = func(args, ctx)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        rc = 130
    elapsed = time.monotonic() - start

    target = getattr(args, "target", None)
    if target:
        try:
            session_mod.record_time(target, elapsed)
        except Exception:
            pass
    return rc if isinstance(rc, int) else 0


if __name__ == "__main__":
    sys.exit(main())
