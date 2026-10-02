"""DOCTOR: self-check for PENTRIX ARSENAL.

    arsenal doctor [--json]

Checks the environment, dependencies, configuration, inbox port and LLM
key presence. Secrets are never printed: key presence is reported as a
boolean only.

Exit code 0 when every check passes, 1 otherwise. Library functions never
print; the CLI entry point below may.
"""

from __future__ import annotations

import json
import os
import platform
import socket
import sys


def _check_env():
    return {
        "name": "python",
        "ok": sys.version_info >= (3, 10),
        "detail": "%s (%s)" % (platform.python_version(), platform.system()),
    }


def _check_deps():
    results = []
    for modname, label in (("rich", "rich"), ("yaml", "pyyaml"),
                           ("PIL", "pillow")):
        try:
            mod = __import__(modname)
            version = getattr(mod, "__version__", "?")
            results.append({"name": "dep:%s" % label, "ok": True,
                            "detail": "version %s" % version})
        except Exception:
            results.append({"name": "dep:%s" % label, "ok": False,
                            "detail": "not installed"})
    return results


def _check_config(ctx):
    try:
        from arsenal import config as config_mod
        cfg = config_mod.load()
    except Exception as e:
        return {"name": "config", "ok": False,
                "detail": "could not load config: %s" % e}
    if not isinstance(cfg, dict):
        return {"name": "config", "ok": False, "detail": "config is not a mapping"}
    return {
        "name": "config",
        "ok": True,
        "detail": "profile=%s safe_mode=%s" % (
            cfg.get("profile", "default"), cfg.get("safe_mode", True)),
    }


def _check_workspace(ctx):
    ws = getattr(ctx, "workspace", None)
    root = None
    if ws is not None:
        for attr in ("root", "base", "dir", "basedir"):
            val = getattr(ws, attr, None)
            if isinstance(val, str) and val:
                root = os.path.expanduser(val)
                break
    if not root:
        root = os.path.expanduser("~/.arsenal/workspaces")
    try:
        os.makedirs(root, exist_ok=True)
        probe = os.path.join(root, ".doctor-write-test")
        with open(probe, "w") as fh:
            fh.write("ok")
        os.remove(probe)
        return {"name": "workspace", "ok": True, "detail": root}
    except Exception as e:
        return {"name": "workspace", "ok": False,
                "detail": "%s: %s" % (root, e)}


def _check_inbox(ctx):
    port = 8000
    try:
        cfg = getattr(ctx, "config", None) or {}
        if isinstance(cfg, dict):
            port = int((cfg.get("inbox") or {}).get("port", 8000))
    except Exception:
        pass
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        listening = sock.connect_ex(("127.0.0.1", port)) == 0
    except Exception:
        listening = False
    finally:
        sock.close()
    return {
        "name": "inbox",
        "ok": True,  # the inbox is opt-in; absence is not a failure
        "detail": ("listening on 127.0.0.1:%d" % port if listening
                   else "not listening on 127.0.0.1:%d (start with `arsenal inbox`)" % port),
    }


def _check_llm():
    try:
        from arsenal import llm as llm_mod
        info = llm_mod.provider_info()
        return {
            "name": "llm",
            "ok": True,  # AI triage is optional; absence is not a failure
            "detail": "provider=%s model=%s key_present=%s (source: %s)" % (
                info["provider"], info["model"],
                info["key_present"], info["key_source"]),
        }
    except Exception as e:
        return {"name": "llm", "ok": True,
                "detail": "provider check unavailable: %s" % e}


def _check_modules():
    try:
        from arsenal.modules import REGISTRY
        names = sorted(REGISTRY)
        return {"name": "modules", "ok": bool(names),
                "detail": "%d registered: %s" % (len(names), ", ".join(names))}
    except Exception as e:
        return {"name": "modules", "ok": False,
                "detail": "registry unavailable: %s" % e}


def _check_plugins():
    try:
        from arsenal import plugins as plugins_mod
        loaded = plugins_mod.load_plugins()
        return {"name": "plugins", "ok": True,
                "detail": "%d loaded from %s" % (len(loaded),
                                                 plugins_mod.PLUGIN_DIR)}
    except Exception as e:
        return {"name": "plugins", "ok": False, "detail": str(e)}


def run_checks(ctx) -> list:
    """Run every self-check. Returns a list of {name, ok, detail} dicts."""
    checks = [_check_env(), *_check_deps(), _check_config(ctx),
              _check_workspace(ctx), _check_inbox(ctx), _check_llm(),
              _check_modules(), _check_plugins()]
    return checks


def cmd_doctor(args, ctx):
    checks = run_checks(ctx)
    failed = [c for c in checks if not c["ok"]]
    if getattr(args, "json", False):
        print(json.dumps({"checks": checks,
                          "ok": not failed}, indent=2))
        return 1 if failed else 0
    try:
        from rich.console import Console
        from rich.table import Table
        console = Console()
        table = Table(title="arsenal doctor")
        table.add_column("Check")
        table.add_column("Status")
        table.add_column("Detail", overflow="fold")
        for c in checks:
            table.add_row(c["name"],
                          "[green]ok[/green]" if c["ok"] else "[red]FAIL[/red]",
                          str(c["detail"])[:90])
        console.print(table)
    except Exception:
        print("arsenal doctor")
        for c in checks:
            print("  [%s] %s: %s" % ("ok" if c["ok"] else "FAIL",
                                     c["name"], c["detail"]))
    if failed:
        print("%d check(s) failed." % len(failed))
        return 1
    print("All checks passed.")
    return 0


def add_parsers(sub):
    p = sub.add_parser("doctor",
                       help="Self-check: env, deps, config, inbox port, LLM key presence")
    p.add_argument("--json", action="store_true",
                   help="Machine-readable JSON output")
    p.set_defaults(func=cmd_doctor)
    return p


def dispatch(args, ctx):
    func = getattr(args, "func", None)
    if callable(func):
        return func(args, ctx)
    raise ValueError("no command dispatch configured for doctor")
