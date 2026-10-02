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
import re
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
    group.add_argument("--modules", metavar="A,B,C",
                       help="Run a comma-separated list of modules from the registry")
    group.add_argument("--all", action="store_true",
                       help="Run every applicable module")
    p.add_argument("--scope-file", default=None, help="Path to a scope JSON file")
    p.add_argument("--proxy", default=None, metavar="URL",
                   help="HTTP(S) proxy URL, e.g. http://127.0.0.1:8080 "
                        "(overrides the config proxy block)")
    p.add_argument("--intrusive", action="store_true",
                   help="Allow intrusive modules")
    p.add_argument("--passive", action="store_true",
                   help="Passive-only mode: recon and cve modules only")
    p.set_defaults(func=_cmd_scan)


def _add_triage(sub):
    p = sub.add_parser("triage", help="Re-triage stored findings for a target")
    p.add_argument("target", help="Target whose stored findings get re-triaged")
    # CREW D: FP-feedback flags (triage.py owns the feature; triage.py's own
    # add_parsers is shadowed by this core registration, so flags live here).
    p.add_argument("--mark-fp", metavar="FID", default=None,
                   help="Record finding FID as a false positive (teaches future triage)")
    p.add_argument("--fp-note", default="",
                   help="Analyst note stored with the false-positive verdict")
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
    # ---- CREW D appended section (CLI UX): new subcommands only. The
    # scan/recon dispatch above is owned by another crew; do not touch it.
    _guarded_add("doctor", sub)
    _add_completions(sub)
    # ---- end CREW D appended section ----
    # ---- CREW C appended section: differentiator CLIs ----
    _add_diff_cmd(sub)
    _add_oob_cmd(sub)
    _add_auth_cmd(sub)
    _add_xsleak_cmd(sub)
    _add_takeover_cmd(sub)
    _add_scopex_cmd(sub)
    _add_recondiff_cmd(sub)
    # ---- end CREW C appended section ----
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


def _target_shape(target):
    """Classify a raw scan target into a shape word.

    Returns one of: url, domain, ip, token, hash, keyword, path, unknown.
    """
    text = (target or "").strip()
    if not text:
        return "unknown"
    if os.path.exists(os.path.expanduser(text)):
        return "path"
    if "://" in text:
        scheme = text.split("://", 1)[0].lower()
        return "url" if scheme in ("http", "https") else "unknown"
    try:
        ipaddress.ip_address(text)
        return "ip"
    except ValueError:
        pass
    if re.match(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$", text):
        # A bare domain like sub.example.com also has three segments;
        # real JWTs start with eyJ (or are very long).
        first = text.split(".", 1)[0]
        if first.startswith("eyJ") or len(text) > 60:
            return "token"
    if re.match(r"^[a-fA-F0-9]{16,}$", text):
        return "hash"
    if "." in text and " " not in text and "/" not in text:
        return "domain"
    if re.match(r"^[A-Za-z0-9_.-]+$", text):
        return "keyword"
    return "unknown"


def _host_of_target(target):
    try:
        return urlsplit(target).hostname or ""
    except Exception:
        return ""


def _route_module(mod, target, shape):
    """Map (module, target shape) to a concrete target string, or None.

    Used by `scan --all` so modules only run against targets they can
    actually handle: jwt/secrets/hashid/cve/wordlist/phish no longer run
    against mistyped targets. URL modules get a full URL built from bare
    domains; domain modules get the bare host extracted from URLs.
    """
    kind = getattr(mod, "TARGET_KIND", "url")
    if kind == "url":
        if shape == "url":
            return target
        if shape == "domain":
            return "https://" + target
        if shape == "ip":
            return "http://" + target
        return None
    if kind == "domain":
        if shape == "domain":
            return target
        if shape == "url":
            return _host_of_target(target) or None
        return None
    if kind == "ip":
        # portscan resolves hostnames itself.
        if shape in ("ip", "domain"):
            return target
        if shape == "url":
            return _host_of_target(target) or None
        return None
    if kind == "token":
        # jwt also scrapes tokens off a URL page when pointed at one.
        return target if shape in ("token", "url") else None
    if kind == "hash":
        return target if shape == "hash" else None
    if kind == "path":
        return target if shape == "path" else None
    if kind == "keyword":
        return target if shape == "keyword" else None
    return None


def _scope_allows(scope, target):
    """Scope-firewall check with URL targets normalized before matching.

    Scope.contains() strips scheme, userinfo, path, query, fragment and
    port, so "https://example.com/page" matches a scope entry for
    example.com instead of refusing every URL target.
    """
    try:
        return bool(scope.contains(target))
    except Exception:
        return False


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


def _apply_proxy_override(args, ctx):
    """Apply an explicit --proxy flag onto ctx.config.

    Overrides the config proxy block entirely and clears no_proxy: an
    explicit proxy is the strongest user intent, everything goes through it.
    """
    if getattr(args, "proxy", None):
        cfg = dict(ctx.config or {})
        cfg["proxy"] = {"enabled": True, "url": args.proxy, "no_proxy": ""}
        ctx.config = cfg


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
    elif getattr(args, "modules", None):
        names = [n.strip() for n in args.modules.split(",") if n.strip()]
        if not names:
            print("error: --modules needs at least one module name",
                  file=sys.stderr)
            return 2
    else:
        names = [args.module]
    shape = _target_shape(args.target) if args.all else None
    _apply_proxy_override(args, ctx)
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
        target = args.target
        if args.all:
            routed = _route_module(mod, args.target, shape)
            if routed is None:
                print("skipping '%s': target is %s, module needs %s"
                      % (name, shape,
                         getattr(mod, "TARGET_KIND", "url")))
                continue
            target = routed
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
        res = run_module(mod, target, ctx)
        findings = res["findings"]
        try:
            ctx.workspace.save_scan(target, name, findings)
            ctx.workspace.append_findings(target, findings)
        except Exception as exc:
            ctx.log.warning("workspace save failed for %s: %s", name, exc)
        print("%s: %d findings" % (name, len(findings)))
        ran += 1
    if ran == 0:
        print("nothing ran")
    return 0


def _cmd_triage(args, ctx):
    # CREW D: FP-feedback short-circuit (feature owned by triage.py).
    if getattr(args, "mark_fp", None):
        from arsenal import triage as triage_mod
        findings = ctx.workspace.all_findings(args.target)
        wanted = str(args.mark_fp).upper()
        match = next((f for f in findings
                      if str(f.get("id", "")).upper() == wanted), None)
        if match is None:
            print("no finding %s stored for '%s'" % (args.mark_fp, args.target))
            return 1
        if triage_mod.record_fp_verdict(match, ctx,
                                        analyst_note=getattr(args, "fp_note", "")):
            print("recorded false-positive feedback for %s; future matching "
                  "findings will be auto-suppressed." % wanted)
            return 0
        print("error: could not store FP feedback", file=sys.stderr)
        return 1
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

    # Scope firewall: enforced before any recon/scan work. URL targets are
    # normalized inside Scope.contains (scheme/path/query/port stripped).
    if command in ("recon", "scan"):
        target = getattr(args, "target", None)
        if target and scope is not None and not _scope_allows(scope, target):
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


# ---- CREW D appended section (CLI UX): `arsenal completions`. Kept here so
# build_parser() above stays untouched apart from its own marked block.
import os as _os


def _add_completions(sub):
    p = sub.add_parser("completions", help="Print shell completion scripts")
    p.add_argument("--shell", default="bash", choices=["bash", "zsh", "fish"],
                   help="Shell flavor to print (default: bash)")
    p.set_defaults(func=_cmd_completions)
    return p


def _cmd_completions(args, ctx):
    path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                         "completions", "arsenal.%s" % args.shell)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            sys.stdout.write(fh.read())
        return 0
    except OSError as exc:
        print("error: could not read %s: %s" % (path, exc), file=sys.stderr)
        return 1
# ---- end CREW D appended section ----


# ---- CREW C appended section: differentiator subcommands ----
def _add_diff_cmd(sub):
    from arsenal import diff as _m
    p = sub.add_parser("diff", help="JS bundle / GraphQL schema snapshot diffing")
    dsub = p.add_subparsers(dest="diff_cmd", required=True)
    sn = dsub.add_parser("snapshot", help="Snapshot JS bundles / GraphQL schema")
    sn.add_argument("--target", required=True)
    sn.add_argument("--kind", default="js,graphql")
    sn.add_argument("--js-url", action="append", default=[])
    sn.add_argument("--graphql-url")
    sn.set_defaults(func=_m.cmd_snapshot)
    cp = dsub.add_parser("compare", help="Diff runs")
    cp.add_argument("--target", required=True)
    cp.set_defaults(func=_m.cmd_compare)


def _add_oob_cmd(sub):
    from arsenal import oob as _m
    p = sub.add_parser("oob", help="OOB callback correlation engine")
    osub = p.add_subparsers(dest="oob_cmd", required=True)
    m = osub.add_parser("mint", help="Mint a token + callback URL for a payload")
    m.add_argument("--class", dest="vuln_class", required=True)
    m.add_argument("--target", required=True)
    m.add_argument("--param", default="")
    m.add_argument("--method", default="GET")
    m.add_argument("--base-url", required=True)
    m.set_defaults(func=_m.cmd_mint)
    pl = osub.add_parser("poll", help="Poll inbox and link callbacks to requests")
    pl.add_argument("--base-url", default="")
    pl.add_argument("--wait", type=float, default=0.0)
    pl.set_defaults(func=_m.cmd_poll)


def _add_auth_cmd(sub):
    from arsenal import auth as _m
    p = sub.add_parser("auth", help="Shared auth session manager")
    asub = p.add_subparsers(dest="auth_cmd", required=True)
    lg = asub.add_parser("login", help="Store a login session in a profile")
    lg.add_argument("--profile", required=True)
    lg.add_argument("--url")
    lg.add_argument("--username"); lg.add_argument("--password")
    lg.add_argument("--bearer")
    lg.add_argument("--basic", action="store_true")
    lg.set_defaults(func=_m.cmd_login)
    st = asub.add_parser("status", help="List profiles / show session state")
    st.set_defaults(func=_m.cmd_status)


def _add_xsleak_cmd(sub):
    from arsenal import xsleak as _m
    p = sub.add_parser("xsleak", help="XS-Leak PoC generator")
    xsub = p.add_subparsers(dest="xsleak_cmd", required=True)
    xsub.add_parser("list", help="List XS-Leak classes").set_defaults(func=_m.cmd_list)
    g = xsub.add_parser("gen", help="Generate a test page for a class")
    g.add_argument("--class", dest="cls", required=True)
    g.add_argument("--target", required=True)
    g.set_defaults(func=_m.cmd_gen)


def _add_takeover_cmd(sub):
    from arsenal import takeover as _m
    p = sub.add_parser("takeover", help="Continuous takeover monitoring")
    p.add_argument("--hosts", nargs="+", required=True)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=_m.cmd_takeover)


def _add_scopex_cmd(sub):
    from arsenal import scopex as _m
    p = sub.add_parser("scopex", help="Smart scope expansion")
    p.add_argument("--domain", required=True)
    p.add_argument("--org", default="")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=_m.cmd_scopex)


def _add_recondiff_cmd(sub):
    from arsenal import recon_diff as _m
    p = sub.add_parser("recondiff", help="Recon diff reports")
    p.add_argument("--target", required=True)
    p.add_argument("--subdomains", nargs="*", default=None)
    p.add_argument("--endpoints", nargs="*", default=None)
    p.add_argument("--format", choices=["md", "json"], default="md")
    p.set_defaults(func=_m.cmd_recondiff)
# ---- end CREW C appended section ----
