"""DECLARATIVE YAML WORKFLOWS for PENTRIX ARSENAL.

`arsenal workflow run flow.yaml [--target T]`
`arsenal workflow init [--out flow.yaml]`

Schema:
    name:        flow name
    description: what the flow does
    vars:
      target:    default target (overridable with --target)
    steps:
      - module: <REGISTRY module name>
        target: "$target" | literal target   (variable refs expand from vars)
        args:   {}                            (passed through to the module ctx)

Steps execute in order via the module REGISTRY and findings are collected
into the workspace. Library functions never print; the CLI below may.
"""

from __future__ import annotations

import os
import re
import types

try:
    import yaml
except Exception:  # pyyaml is a declared dependency; degrade gracefully
    yaml = None

try:
    from arsenal.modules import REGISTRY  # owned by another builder
except Exception:
    REGISTRY = None

_VAR_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")


def _get_registry():
    reg = globals().get("REGISTRY")
    if reg is not None:
        return reg
    try:
        import arsenal.modules as mods
        return getattr(mods, "REGISTRY", None) or {}
    except Exception:
        return {}


def expand_vars(value, variables):
    """Expand $var references in strings, lists and dicts. Never raises."""
    variables = variables or {}
    if isinstance(value, str):
        def repl(m):
            return str(variables.get(m.group(1), m.group(0)))
        return _VAR_RE.sub(repl, value)
    if isinstance(value, list):
        return [expand_vars(v, variables) for v in value]
    if isinstance(value, dict):
        return {k: expand_vars(v, variables) for k, v in value.items()}
    return value


def load_flow(path):
    """Load and validate a workflow YAML file. Returns (flow, error)."""
    if yaml is None:
        return None, "pyyaml is not installed; cannot parse workflow files"
    if not os.path.exists(path):
        return None, "workflow file not found: %s" % path
    try:
        with open(path, encoding="utf-8") as fh:
            flow = yaml.safe_load(fh)
    except Exception as e:
        return None, "invalid YAML in %s: %s" % (path, e)
    if not isinstance(flow, dict):
        return None, "workflow must be a YAML mapping"
    steps = flow.get("steps")
    if not isinstance(steps, list) or not steps:
        return None, "workflow must define a non-empty 'steps' list"
    for i, step in enumerate(steps):
        if not isinstance(step, dict) or not step.get("module"):
            return None, "step %d must be a mapping with a 'module' key" % i
    return flow, None


def _scoped_ctx(ctx, step_args):
    data = {k: getattr(ctx, k) for k in dir(ctx) if not k.startswith("__")}
    data["workflow_args"] = step_args or {}
    return types.SimpleNamespace(**data)


def _store_findings(ctx, target, findings):
    ws = getattr(ctx, "workspace", None)
    if ws is None or not findings:
        return
    appender = getattr(ws, "append_findings", None)
    if callable(appender):
        try:
            appender(target, findings)
            return
        except TypeError:
            try:
                appender(findings)
                return
            except Exception:
                pass
        except Exception:
            pass


def run_flow(flow, variables, ctx):
    """Execute flow steps in order. Returns a result dict. Never prints."""
    registry = _get_registry()
    variables = dict(variables or {})
    results = []
    collected = []
    for idx, step in enumerate(flow.get("steps", [])):
        name = expand_vars(step.get("module"), variables)
        step_target = expand_vars(step.get("target", "$target"), variables)
        step_args = expand_vars(step.get("args", {}), variables)
        mod = registry.get(name)
        if mod is None:
            results.append({"step": idx, "module": name, "status": "skipped",
                            "error": "module %r not in REGISTRY" % name})
            continue
        run = getattr(mod, "run", None)
        if not callable(run):
            results.append({"step": idx, "module": name, "status": "skipped",
                            "error": "module %r has no run()" % name})
            continue
        try:
            res = run(step_target, _scoped_ctx(ctx, step_args))
            status = "ok"
            err = None
        except Exception as e:
            res, status, err = None, "failed", str(e)
        findings = [f for f in (res or []) if isinstance(f, dict)] if isinstance(res, list) else []
        if findings and step_target:
            _store_findings(ctx, step_target, findings)
        collected.extend(findings)
        results.append({"step": idx, "module": name, "status": status,
                        "error": err, "findings": len(findings)})
    return {"name": flow.get("name", "?"), "steps": results, "findings": collected}


EXAMPLE_FLOW = """\
name: example
description: Example PENTRIX ARSENAL workflow. Copy and adapt.
vars:
  target: example.com
steps:
  - module: alive
    target: $target
    args: {}
  - module: portscan
    target: $target
    args: {}
  - module: tech
    target: $target
    args: {}
  - module: jsintel
    target: $target
    args: {}
"""

WEB_BASIC_FLOW = """\
name: web-basic
description: Baseline web recon for a target.
vars:
  target: ""
steps:
  - module: alive
    target: $target
    args: {}
  - module: portscan
    target: $target
    args: {}
  - module: tech
    target: $target
    args: {}
  - module: jsintel
    target: $target
    args: {}
  - module: webscan
    target: $target
    args: {}
"""

PASSIVE_FLOW = """\
name: passive
description: Passive-only recon. No packets are aimed at the target.
vars:
  target: ""
steps:
  - module: subdomain
    target: $target
    args: {}
  - module: cert
    target: $target
    args: {}
  - module: tech
    target: $target
    args: {}
"""


def _print_result(console, result):
    rows = result["steps"]
    try:
        from rich.table import Table
        table = Table(title="Workflow: %s" % result["name"])
        table.add_column("#", justify="right")
        table.add_column("Module")
        table.add_column("Status")
        table.add_column("Findings", justify="right")
        for r in rows:
            table.add_row(str(r["step"]), str(r["module"]),
                          r["status"] + (": " + r["error"] if r.get("error") else ""),
                          str(r.get("findings", 0)))
        console.print(table)
        console.print("Total findings collected: %d" % len(result["findings"]))
    except Exception:
        print("Workflow: %s" % result["name"])
        for r in rows:
            print("  [%d] %s: %s (%d findings)" % (
                r["step"], r["module"], r["status"], r.get("findings", 0)))
            if r.get("error"):
                print("       error: %s" % r["error"])


def cmd_workflow_run(args, ctx):
    flow, err = load_flow(args.flow)
    if err:
        print("Error: %s" % err)
        return 1
    variables = dict(flow.get("vars") or {})
    if args.target:
        variables["target"] = args.target
    if not variables.get("target"):
        print("Error: no target set (use vars.target in the YAML or --target).")
        return 1
    result = run_flow(flow, variables, ctx)
    try:
        from rich.console import Console
        _print_result(Console(), result)
    except Exception:
        _print_result(None, result)
    failed = sum(1 for r in result["steps"] if r["status"] == "failed")
    return 1 if failed else 0


def cmd_workflow_init(args, ctx):
    out = args.out or "flow.yaml"
    try:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(EXAMPLE_FLOW)
    except Exception as e:
        print("Error: could not write %s: %s" % (out, e))
        return 1
    print("Example workflow written to %s" % out)
    return 0


def add_parsers(sub):
    p = sub.add_parser("workflow", help="Run declarative YAML module workflows")
    wsub = p.add_subparsers(dest="workflow_cmd", metavar="COMMAND")
    pr = wsub.add_parser("run", help="Run a workflow YAML file")
    pr.add_argument("flow", help="Path to the workflow YAML file")
    pr.add_argument("--target", default=None,
                    help="Override the workflow's vars.target")
    pr.set_defaults(func=cmd_workflow_run)
    pi = wsub.add_parser("init", help="Write an example workflow file")
    pi.add_argument("--out", default="flow.yaml",
                    help="Output path (default: flow.yaml)")
    pi.set_defaults(func=cmd_workflow_init)
    return p


def dispatch(args, ctx):
    func = getattr(args, "func", None)
    if callable(func):
        return func(args, ctx)
    raise ValueError("no command dispatch configured for workflow")
