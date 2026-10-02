"""DECLARATIVE YAML WORKFLOWS for PENTRIX ARSENAL (v2).

`arsenal workflow run flow.yaml [--target T] [--var k=v ...]`
`arsenal workflow init [--out flow.yaml]`

Schema:
    name:        flow name
    description: what the flow does
    vars:
      target:    default target (overridable with --target)
    for_each:    <var name> — run the whole flow once per item in $var,
                 with the item available as $item (optional)
    steps:
      - module: <REGISTRY module name>
        target: "$target" | literal target   (variable refs expand from vars)
        args:   {}                            (passed through to the module ctx)
        if:     "<condition>"                 (skip the step unless true)
        for_each: "$targets"                  (run this step once per item,
                                             item available as $item)
      - parallel:                             (run branches concurrently)
          - module: a
          - module: b
        if: "<condition>"                     (optional, gates the branch set)

Conditions are small safe expressions over $vars, results (list of prior
step results with .status/.module/.findings) and findings (count so far),
e.g. `if: "results[0].status == 'ok' and findings > 0"`. $var references
expand to vars["var"].

Steps execute in order via the module REGISTRY and findings are collected
into the workspace. Library functions never print; the CLI below may.
"""

from __future__ import annotations

import ast
import os
import re
import types
from concurrent.futures import ThreadPoolExecutor

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
    return _validate_flow(flow)


def _validate_flow(flow):
    if not isinstance(flow, dict):
        return None, "workflow must be a YAML mapping"
    steps = flow.get("steps")
    if not isinstance(steps, list) or not steps:
        return None, "workflow must define a non-empty 'steps' list"
    for i, step in enumerate(steps):
        err = _validate_step(step, "step %d" % i)
        if err:
            return None, err
    for_each = flow.get("for_each")
    if for_each is not None and not isinstance(for_each, str):
        return None, "'for_each' must be a variable name string"
    return flow, None


def _validate_step(step, where):
    if not isinstance(step, dict):
        return "%s must be a mapping" % where
    if "parallel" in step:
        branches = step["parallel"]
        if not isinstance(branches, list) or not branches:
            return "%s 'parallel' must be a non-empty list of steps" % where
        for j, branch in enumerate(branches):
            err = _validate_step(branch, "%s parallel branch %d" % (where, j))
            if err:
                return err
        return None
    if not step.get("module"):
        return "%s must have a 'module' key (or a 'parallel' block)" % where
    if "if" in step and not isinstance(step["if"], str):
        return "%s 'if' must be a condition string" % where
    if "for_each" in step and not isinstance(step["for_each"], str):
        return "%s 'for_each' must be a '$var' reference string" % where
    return None


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


# --------------------------------------------------------------------------
# v2 execution: conditionals, for_each loops, parallel branches
# --------------------------------------------------------------------------

_VAR_REF_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")

_ALLOWED_AST_NODES = (
    ast.Expression, ast.BoolOp, ast.UnaryOp, ast.BinOp, ast.Compare,
    ast.Name, ast.Constant, ast.Attribute, ast.Subscript, ast.List,
    ast.Tuple, ast.Load, ast.And, ast.Or, ast.Not, ast.Eq, ast.NotEq,
    ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn, ast.Add,
    ast.Sub, ast.Mult, ast.USub,
)


def _to_namespace(value):
    """Recursively convert dicts to attribute-accessible namespaces for
    condition evaluation (results[0].status style access)."""
    if isinstance(value, dict):
        return types.SimpleNamespace(
            **{str(k): _to_namespace(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return [_to_namespace(v) for v in value]
    return value


def _eval_condition(expr, variables, results, findings_count) -> bool:
    """Safely evaluate an `if:` condition string.

    $var refs become vars["var"]. Available names: vars (dict), results
    (list of prior step result dicts), findings (int count so far).
    Unknown names evaluate to None; any parse/eval error means False
    (fail-closed: the step is skipped).
    """
    if not isinstance(expr, str) or not expr.strip():
        return True
    rewritten = _VAR_REF_RE.sub(lambda m: 'vars[%r]' % m.group(1), expr)
    try:
        tree = ast.parse(rewritten, mode="eval")
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_AST_NODES):
            return False
    scope = {
        "vars": dict(variables or {}),
        "results": [_to_namespace(r) for r in (results or [])],
        "findings": int(findings_count or 0),
    }

    def _resolve(value):
        if isinstance(value, dict):
            return {k: _resolve(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [_resolve(v) for v in value]
        return value

    safe_scope = {k: _resolve(v) for k, v in scope.items()}
    try:
        return bool(eval(compile(tree, "<condition>", "eval"),
                         {"__builtins__": {}}, safe_scope))
    except Exception:
        return False


def _resolve_for_each(ref, variables):
    """Resolve a for_each reference ("$targets" or "targets") to a list."""
    if not isinstance(ref, str):
        return []
    name = ref[1:] if ref.startswith("$") else ref
    items = (variables or {}).get(name, [])
    if isinstance(items, str):
        items = [x.strip() for x in items.split(",") if x.strip()]
    return list(items) if isinstance(items, (list, tuple)) else []


def _execute_module_step(step, variables, ctx, registry, idx):
    """Run one module step. Returns a result dict. Never raises."""
    name = expand_vars(step.get("module"), variables)
    step_target = expand_vars(step.get("target", "$target"), variables)
    step_args = expand_vars(step.get("args", {}), variables)
    mod = registry.get(name)
    if mod is None:
        return {"step": idx, "module": name, "status": "skipped",
                "error": "module %r not in REGISTRY" % name, "findings": 0}
    run = getattr(mod, "run", None)
    if not callable(run):
        return {"step": idx, "module": name, "status": "skipped",
                "error": "module %r has no run()" % name, "findings": 0}
    try:
        res = run(step_target, _scoped_ctx(ctx, step_args))
        status, err = "ok", None
    except Exception as e:
        res, status, err = None, "failed", str(e)
    findings = [f for f in (res or []) if isinstance(f, dict)] if isinstance(res, list) else []
    if findings and step_target:
        _store_findings(ctx, step_target, findings)
    return {"step": idx, "module": name, "status": status, "error": err,
            "findings": len(findings), "_finding_dicts": findings}


def _run_step_list(steps, variables, ctx, registry, results, collected,
                   base_idx=0):
    """Execute steps honoring if/for_each/parallel. Appends to results and
    collected. Returns the next step index."""
    idx = base_idx
    for step in steps:
        if not isinstance(step, dict):
            idx += 1
            continue
        condition = step.get("if")
        if condition is not None and not _eval_condition(
                condition, variables, results, len(collected)):
            results.append({"step": idx, "module": step.get("module", "parallel"),
                            "status": "skipped", "error": "condition false: %s"
                            % condition, "findings": 0})
            idx += 1
            continue
        # Parallel branches run concurrently (bounded pool).
        if "parallel" in step:
            branches = [b for b in step["parallel"] if isinstance(b, dict)]
            branch_results = []
            if branches:
                with ThreadPoolExecutor(
                        max_workers=min(len(branches), 8),
                        thread_name_prefix="arsenal-flow") as pool:
                    futures = [pool.submit(_execute_module_step, b, variables,
                                           ctx, registry, idx)
                               for b in branches]
                    for fut in futures:
                        try:
                            branch_results.append(fut.result())
                        except Exception as e:
                            branch_results.append(
                                {"step": idx, "module": "?",
                                 "status": "failed", "error": str(e),
                                 "findings": 0})
            total = sum(r.get("findings", 0) for r in branch_results)
            for r in branch_results:
                collected.extend(r.pop("_finding_dicts", []))
            results.append({"step": idx, "module": "parallel[%d]" % len(branches),
                            "status": "ok" if all(
                                r["status"] in ("ok", "skipped")
                                for r in branch_results) else "failed",
                            "error": None, "findings": total,
                            "branches": branch_results})
            idx += 1
            continue
        # for_each loops one step over a list variable ($item per iteration).
        for_each_ref = step.get("for_each")
        if for_each_ref:
            items = _resolve_for_each(for_each_ref, variables)
            if not items:
                results.append({"step": idx, "module": step.get("module"),
                                "status": "skipped",
                                "error": "for_each %r resolved to no items"
                                % for_each_ref, "findings": 0})
                idx += 1
                continue
            loop_total, loop_status, loop_err = 0, "ok", None
            for item in items:
                ivars = dict(variables)
                ivars["item"] = item
                r = _execute_module_step(step, ivars, ctx, registry, idx)
                collected.extend(r.pop("_finding_dicts", []))
                loop_total += r.get("findings", 0)
                if r["status"] == "failed":
                    loop_status, loop_err = "failed", r.get("error")
            results.append({"step": idx, "module": step.get("module"),
                            "status": loop_status, "error": loop_err,
                            "findings": loop_total,
                            "for_each": for_each_ref,
                            "iterations": len(items)})
            idx += 1
            continue
        r = _execute_module_step(step, variables, ctx, registry, idx)
        collected.extend(r.pop("_finding_dicts", []))
        results.append(r)
        idx += 1
    return idx


def run_flow(flow, variables, ctx):
    """Execute flow steps in order (v2: if/for_each/parallel). Returns a
    result dict. Never prints."""
    registry = _get_registry()
    variables = dict(variables or {})
    results = []
    collected = []
    flow_for_each = flow.get("for_each")
    if flow_for_each:
        items = _resolve_for_each(flow_for_each, variables)
        if not items:
            return {"name": flow.get("name", "?"), "steps": results,
                    "findings": collected,
                    "error": "flow for_each %r resolved to no items" % flow_for_each}
        for item in items:
            ivars = dict(variables)
            ivars["item"] = item
            # When looping a targets list, each iteration hunts one target.
            if str(flow_for_each).lstrip("$") == "targets":
                ivars["target"] = item
            _run_step_list(flow.get("steps", []), ivars, ctx, registry,
                           results, collected)
    else:
        _run_step_list(flow.get("steps", []), variables, ctx, registry,
                       results, collected)
    return {"name": flow.get("name", "?"), "steps": results,
            "findings": collected}


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
            status = r["status"] + (": " + r["error"] if r.get("error") else "")
            if r.get("branches"):
                detail = "%s (%d branches)" % (r["module"], len(r["branches"]))
            elif r.get("for_each"):
                detail = "%s x%d" % (r["module"], r.get("iterations", 0))
            else:
                detail = str(r["module"])
            table.add_row(str(r["step"]), detail, status,
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
    for item in getattr(args, "var", None) or []:
        if "=" not in item:
            print("Error: --var expects k=v, got %r" % item)
            return 2
        key, value = item.split("=", 1)
        variables[key.strip()] = value.strip()
    if not variables.get("target") and not flow.get("for_each"):
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
    pr.add_argument("--var", action="append", default=[], metavar="k=v",
                    help="Override a workflow variable (repeatable)")
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
