# Workflow Engine v2

Declarative YAML workflows compose registry modules into repeatable hunts:

```bash
arsenal workflow run workflows/api-hunt.yaml --target https://target.com
arsenal workflow run flow.yaml --var target=example.com --var depth=2
arsenal workflow init --out myflow.yaml
```

## Schema

```yaml
name: api-hunt
description: What this flow does.
vars:
  target: ""            # overridable with --target or --var target=X
  targets: []           # lists work too (see for_each)
for_each: targets       # optional: run the whole flow once per item in $targets
                        # (each iteration gets $item; for "targets" also $target)
steps:
  - module: tech        # REGISTRY module name
    target: "$target"   # $var references expand from vars
    args: {}            # passed through to the module ctx as workflow_args

  - module: paramminer
    target: $target
    args: {}
    if: "findings > 0" # conditional step (see below)

  - module: fuzz        # per-item loop over a list variable
    target: $item
    for_each: "$targets"

  - parallel:           # branches run concurrently (bounded pool)
      - module: fuzz
        target: $target
      - module: headers
        target: $target
```

## Conditionals (`if:`)

A step runs only when its `if:` expression is true. Expressions are
evaluated by a small safe evaluator (no imports, no function calls;
unknown names are `None`; parse errors fail closed to false):

* `$var` references: `$target`, `$depth`
* `results`: list of prior step results; each has `.status`
  (`ok`/`failed`/`skipped`), `.module`, `.findings`
* `findings`: integer count of findings collected so far

Examples:

```yaml
if: "results[0].status == 'ok'"
if: "findings > 0 and results[1].status != 'failed'"
if: "$target != ''"
```

## Loops (`for_each`)

* **Step level:** `for_each: "$targets"` runs the step once per item;
  the item is available as `$item` (and `$target` is untouched).
* **Flow level:** `for_each: targets` runs every step once per item;
  when the variable is named `targets`, each iteration also sets
  `$target` to the item, so `workflows/continuous-monitor.yaml` fans
  out over a target list with `--var`.

`for_each` accepts a YAML list or a comma-separated string.

## Parallel branches (`parallel:`)

A step with a `parallel:` list runs its branches concurrently in a
bounded `ThreadPoolExecutor` (max 8 workers). The step result records
per-branch outcomes under `branches`; the step is `ok` only when every
branch is `ok` or `skipped`.

## CLI

* `arsenal workflow run flow.yaml [--target T] [--var k=v ...]`
* `arsenal workflow init [--out flow.yaml]`

`load_flow()` validates the file before anything runs; `run_flow(flow,
variables, ctx)` is the library entry point and never prints.

## Shipped workflows

| File | Purpose |
|------|---------|
| `workflows/passive.yaml` | Passive-only recon (no packets to the target). |
| `workflows/web-basic.yaml` | Baseline web assessment. |
| `workflows/api-hunt.yaml` | API surface discovery + GraphQL/auth probing with conditionals and parallel branches. |
| `workflows/business-logic.yaml` | Business-logic pack: discovery automation plus structured manual checkpoints (IDOR matrices, two-session differential, price tampering, step-skip/replay). |
| `workflows/continuous-monitor.yaml` | Scheduled sweep over a target list (`for_each`), tech-gated CVE lookups; pair with `arsenal trends` for drift. |

## Ask Arsenal

`arsenal ask --plan "hunt XSS on example.com"` parses the request with
a rule-based NL parser (optional LLM refinement when a key is set) and
writes a workflow YAML into `workflows/`, ready to run.
