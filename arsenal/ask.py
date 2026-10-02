"""ASK ARSENAL: conversational Q&A over the workspace for a target.

gather_context() builds a compact, truncated textual summary of everything the
workspace knows about a target. answer() replies to a question using the LLM
when available, with a keyword-based rule engine as fallback. Library
functions never print; the CLI dispatch prints the answer (via rich if present).
"""

from __future__ import annotations

import os

from arsenal import llm
from arsenal.triage import _ws_call, _ws_get


_MAX_PER_SECTION = 12
_MAX_TEXT = 400


def _trunc(text: str, limit: int = _MAX_TEXT) -> str:
    text = str(text or "")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _severity_rank(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
        str(sev or "").lower(), 5
    )


def gather_context(target, ctx) -> str:
    """Build a truncated workspace summary for a target."""
    ws = getattr(ctx, "workspace", None)

    findings = _ws_call(ws, "get_findings", target, None)
    if findings is None:
        findings = _ws_get(ws, "findings", None)
    if isinstance(findings, dict):
        findings = findings.get(target, [])
    findings = [f for f in (findings or []) if isinstance(f, dict)]

    tech = _ws_call(ws, "get_tech", target, None) or _ws_get(ws, "tech", []) or []
    alerts = _ws_call(ws, "get_alerts", target, None) or _ws_get(ws, "alerts", []) or []
    coverage = _ws_call(ws, "get_coverage", target, None) or _ws_get(ws, "coverage", {}) or {}
    hosts_hint = _ws_call(ws, "get_hosts", target, None) or _ws_get(ws, "hosts", []) or []

    by_sev, by_module, host_scores = {}, {}, {}
    open_titles, untriaged_highs = [], []
    for f in findings:
        sev = str(f.get("severity") or "unknown").lower()
        mod = str(f.get("module") or "unknown").lower()
        by_sev[sev] = by_sev.get(sev, 0) + 1
        by_module[mod] = by_module.get(mod, 0) + 1
        host = str(f.get("host") or f.get("target") or target)
        host_scores[host] = host_scores.get(host, 0) + (5 - _severity_rank(sev))
        if not f.get("triaged") and "verdict" not in f:
            open_titles.append(str(f.get("title") or "untitled"))
            if sev in ("critical", "high"):
                untriaged_highs.append(str(f.get("title") or "untitled"))

    priority_hosts = sorted(host_scores, key=lambda h: (-host_scores[h], h))
    if not priority_hosts and hosts_hint:
        priority_hosts = [str(h) for h in hosts_hint]

    lines = ["Workspace summary for target: %s" % target]
    lines.append("Total findings: %d" % len(findings))
    if by_sev:
        lines.append(
            "By severity: "
            + ", ".join("%s=%d" % (k, by_sev[k]) for k in sorted(by_sev, key=_severity_rank))
        )
    if by_module:
        lines.append(
            "By module: "
            + ", ".join(
                "%s=%d" % kv
                for kv in sorted(by_module.items(), key=lambda kv: -kv[1])[:_MAX_PER_SECTION]
            )
        )
    if tech:
        tech_list = tech if isinstance(tech, list) else [tech]
        lines.append(
            "Technology: "
            + ", ".join(str(t) for t in tech_list[:_MAX_PER_SECTION])
        )
    if priority_hosts:
        lines.append(
            "Top priority hosts: " + ", ".join(priority_hosts[:5])
        )
    if coverage:
        if isinstance(coverage, dict):
            cov = ", ".join("%s=%s" % (k, _trunc(v, 80)) for k, v in list(coverage.items())[:8])
        else:
            cov = _trunc(coverage, 200)
        lines.append("Coverage: %s" % cov)
    lines.append("Open (unreviewed) findings: %d" % len(open_titles))
    for t in open_titles[:_MAX_PER_SECTION]:
        lines.append("  - %s" % _trunc(t, 120))
    if alerts:
        lines.append("Recent monitor alerts: %d" % len(alerts))
        for a in alerts[:_MAX_PER_SECTION]:
            if isinstance(a, dict):
                a = a.get("message") or a.get("title") or str(a)
            lines.append("  - %s" % _trunc(a, 160))
    return "\n".join(lines)


_ASK_SYSTEM = (
    "You are a bug bounty hunting assistant. Answer from the provided workspace "
    "data only; do not invent findings, hosts, or technologies. Be concrete and "
    "cite finding titles when you reference them. If the data does not contain "
    "the answer, say so plainly and suggest what to scan or check next."
)


def _rule_answer(question: str, target, ctx) -> str:
    ws = getattr(ctx, "workspace", None)
    findings = _ws_call(ws, "get_findings", target, None) or []
    findings = [f for f in findings if isinstance(f, dict)]

    q = question.lower()

    def title(f):
        return str(f.get("title") or "untitled")

    def host(f):
        return str(f.get("host") or f.get("target") or target)

    if "xss" in q:
        xs = [f for f in findings if str(f.get("module") or "").lower() == "xss"]
        if not xs:
            return "No XSS findings are stored for %s. Run the xss module against in-scope parameters and reflected inputs to look for some." % target
        parts = ["XSS findings for %s (%d):" % (target, len(xs))]
        for f in sorted(xs, key=lambda f: _severity_rank(f.get("severity")))[:8]:
            verdict = f.get("verdict")
            parts.append(
                "- [%s] %s on %s%s"
                % (
                    str(f.get("severity") or "?").upper(),
                    title(f),
                    host(f),
                    " (triage: %s)" % verdict if verdict else " (untriaged)",
                )
            )
        parts.append("Confirm each in a private window and check the CSP header before reporting.")
        return "\n".join(parts)

    if "report" in q:
        by_sev = {}
        for f in findings:
            s = str(f.get("severity") or "unknown").lower()
            by_sev[s] = by_sev.get(s, 0) + 1
        top = sorted(findings, key=lambda f: _severity_rank(f.get("severity")))[:5]
        parts = ["Report draft for %s:" % target]
        parts.append(
            "Counts: " + (", ".join("%s=%d" % kv for kv in sorted(by_sev.items())) or "no findings")
        )
        parts.append("Top findings:")
        for f in top:
            parts.append(
                "- [%s] %s (%s)"
                % (str(f.get("severity") or "?").upper(), title(f), str(f.get("module") or "?"))
            )
        parts.append("Triage any untriaged items with `arsenal triage %s` before writing the final report." % target)
        return "\n".join(parts)

    if "next" in q or "what should" in q or "todo" in q or "priorit" in q:
        scores = {}
        for f in findings:
            h = host(f)
            scores[h] = scores.get(h, 0) + (5 - _severity_rank(f.get("severity")))
        top_hosts = sorted(scores, key=lambda h: (-scores[h], h))[:3]
        highs = [
            f for f in findings
            if str(f.get("severity") or "").lower() in ("critical", "high")
            and not f.get("triaged") and "verdict" not in f
        ]
        parts = ["Suggested next steps for %s:" % target]
        if top_hosts:
            parts.append("Top priority hosts: " + ", ".join(top_hosts))
        if highs:
            parts.append("Untriaged high-severity findings to review first:")
            for f in highs[:5]:
                parts.append("- %s (%s)" % (title(f), str(f.get("module") or "?")))
        if not top_hosts and not highs:
            parts.append("No findings stored yet. Start with recon (subdomains, tech fingerprinting), then run the xss and sqli modules on the highest-value hosts.")
        parts.append("Then re-run triage and ask for a report draft.")
        return "\n".join(parts)

    # default: workspace summary + suggested questions
    summary = gather_context(target, ctx)
    return (
        summary
        + "\n\nYou can ask me things like:\n"
        + '- "what should I do next?"\n'
        + '- "summarize the xss findings"\n'
        + '- "draft a report"\n'
    )


def answer(question: str, target, ctx) -> str:
    """Answer a question about a target's workspace. LLM first, rules on failure."""
    context = gather_context(target, ctx)
    if llm.llm_available():
        messages = [
            {"role": "system", "content": _ASK_SYSTEM},
            {
                "role": "user",
                "content": "Workspace data:\n%s\n\nQuestion: %s" % (context, question),
            },
        ]
        try:
            return llm.chat(messages, max_tokens=800, timeout=30, ctx=ctx)
        except Exception:
            pass  # fall through to the rule-based engine
    return _rule_answer(question, target, ctx)


# --------------------------------------------------------------------------
# ASK ARSENAL --plan: natural-language hunt planning -> YAML workflow
# --------------------------------------------------------------------------

import re as _re

_TARGET_RE = _re.compile(
    r"(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+"
    r"(?::\d{1,5})?(?:/[^\s]*)?|\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?)"
)

# (keywords, modules) in priority order; first match wins per keyword group.
_INTENT_MODULES = [
    (("xss", "cross-site scripting", "cross site scripting"), ["xss"]),
    (("sqli", "sql injection", "sql-injection"), ["sqli"]),
    (("ssti", "template injection", "server-side template"), ["ssti"]),
    (("cors", "cross-origin"), ["cors"]),
    (("open redirect", "redirect"), ["redirect"]),
    (("graphql",), ["graphql"]),
    (("jwt", "json web token"), ["jwt"]),
    (("oauth", "oidc", "openid connect"), ["oauth"]),
    (("secret", "api key", "leak"), ["secrets", "jssecrets"]),
    (("security header", "headers", "csp", "hsts"), ["headers"]),
    (("tech", "fingerprint", "stack detection"), ["tech"]),
    (("host header",), ["hostheader"]),
    (("cache poison", "cache deception"), ["cachepoison"]),
    (("prototype pollution",), ["ppollution"]),
    (("param", "fuzz"), ["fuzz", "paramminer"]),
    (("cve", "known vulnerabilit"), ["cve"]),
    (("phish", "phishing"), ["phish"]),
    (("api", "endpoint"), ["jsintel", "graphql"]),
    (("subdomain", "recon"), ["recon"]),
    (("portscan", "port scan", "open port"), ["portscan"]),
]

_FULL_WEB_SET = ["tech", "headers", "cors", "redirect", "jssecrets", "wordlist",
                 "graphql", "oauth", "hostheader", "xss", "sqli", "ssti",
                 "fuzz", "paramminer", "ppollution", "cachepoison"]
_PASSIVE_SET = ["recon", "cve"]
_BASELINE_SET = ["tech", "headers", "cors", "jssecrets"]


def parse_hunt_request(text: str) -> dict:
    """Rule-based NL parsing of a hunt request.

    Returns {"targets": [...], "modules": [...], "mode": "targeted"|"full"|
    "passive"|"baseline", "raw": text}. Never raises.
    """
    text = str(text or "")
    low = text.lower()
    targets = []
    for match in _TARGET_RE.finditer(text):
        candidate = match.group(0).strip().rstrip(".,;:!?")
        if "." in candidate and candidate not in targets:
            targets.append(candidate)
    mode = "targeted"
    if any(w in low for w in ("passive", "osint only", "no active")):
        mode = "passive"
    elif any(w in low for w in ("full", "everything", "deep", "complete", "all modules")):
        mode = "full"
    elif any(w in low for w in ("quick", "baseline", "basic")):
        mode = "baseline"

    modules = []
    if mode == "passive":
        modules = list(_PASSIVE_SET)
    elif mode == "full":
        modules = list(_FULL_WEB_SET)
    elif mode == "baseline":
        modules = list(_BASELINE_SET)
    else:
        for keywords, mods in _INTENT_MODULES:
            if any(k in low for k in keywords):
                for m in mods:
                    if m not in modules:
                        modules.append(m)
        # A targeted web hunt always starts with recon + tech context.
        if modules and not any(m in ("recon", "portscan") for m in modules):
            modules = ["recon", "tech"] + modules
    if not modules:
        modules = list(_BASELINE_SET)
    return {"targets": targets, "modules": modules, "mode": mode, "raw": text}


def _slugify(text: str) -> str:
    slug = _re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-")
    return slug[:60] or "hunt"


def build_workflow(plan: dict) -> dict:
    """Turn a parsed hunt plan into a workflow dict (workflows.py schema)."""
    targets = plan.get("targets") or ["example.com"]
    modules = plan.get("modules") or []
    name = "hunt-%s-%s" % ("-".join(modules[:3]) or "web",
                           _slugify(targets[0]))
    steps = [{"module": m, "target": "$target", "args": {}} for m in modules]
    flow = {
        "name": _slugify(name),
        "description": "Generated by `arsenal ask --plan`: %s" % plan.get("raw", ""),
        "vars": {"target": targets[0]},
        "steps": steps,
    }
    if len(targets) > 1:
        flow["vars"] = {"targets": targets}
        flow["for_each"] = "targets"
    return flow


def _llm_refine_plan(plan: dict, ctx):
    """Optionally let the LLM improve the module selection. Best-effort."""
    if not llm.llm_available():
        return plan
    try:
        from arsenal.modules import REGISTRY
        known = sorted(REGISTRY)
    except Exception:
        known = []
    prompt = (
        "You are a bug bounty hunt planner. The user asked: %r. "
        "A rule-based parser chose modules %s (mode %s). "
        "Valid module names: %s. "
        "Respond with STRICT JSON only: "
        '{"modules": ["ordered", "module", "names"], "reason": "one sentence"}. '
        "Only use valid module names; keep the list focused (max 10)."
        % (plan.get("raw"), plan.get("modules"), plan.get("mode"),
           ", ".join(known) if known else "unknown")
    )
    try:
        raw = llm.chat([{"role": "user", "content": prompt}],
                       max_tokens=400, timeout=30, ctx=ctx)
        data = _extract_plan_json(raw)
        refined = [m for m in data.get("modules", []) if m in known]
        if refined:
            plan = dict(plan)
            plan["modules"] = refined
            plan["llm_reason"] = str(data.get("reason", ""))[:200]
    except Exception:
        pass
    return plan


def _extract_plan_json(raw: str) -> dict:
    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("no JSON in LLM response")
    import json as _json
    return _json.loads(raw[start:end + 1])


def plan_hunt(text: str, ctx, out_dir="workflows") -> dict:
    """Parse NL hunt text and write a YAML workflow file.

    Returns {"path", "flow", "plan"}. Never prints.
    """
    plan = parse_hunt_request(text)
    if not plan["targets"]:
        raise ValueError("could not find a target domain/IP/URL in %r" % text)
    plan = _llm_refine_plan(plan, ctx)
    flow = build_workflow(plan)
    try:
        import yaml as _yaml
    except Exception:
        _yaml = None
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, flow["name"] + ".yaml")
    with open(path, "w", encoding="utf-8") as fh:
        if _yaml is not None:
            _yaml.safe_dump(flow, fh, sort_keys=False, default_flow_style=False)
        else:
            fh.write(_flow_to_yaml_fallback(flow))
    return {"path": path, "flow": flow, "plan": plan}


def _flow_to_yaml_fallback(flow: dict) -> str:
    """Minimal YAML emitter used when pyyaml is unavailable."""
    lines = ["name: %s" % flow.get("name", "hunt"),
             "description: %s" % str(flow.get("description", "")).replace("\n", " "),
             "vars:"]
    for k, v in (flow.get("vars") or {}).items():
        if isinstance(v, list):
            lines.append("  %s:" % k)
            lines.extend("    - %s" % item for item in v)
        else:
            lines.append("  %s: %s" % (k, v))
    if flow.get("for_each"):
        lines.append("for_each: %s" % flow["for_each"])
    lines.append("steps:")
    for step in flow.get("steps", []):
        lines.append("  - module: %s" % step.get("module"))
        lines.append("    target: %s" % step.get("target"))
        lines.append("    args: {}")
    return "\n".join(lines) + "\n"


def cmd_plan(args, ctx):
    text = " ".join(args.plan_text) if isinstance(args.plan_text, list) else str(args.plan_text or "")
    if not text.strip():
        print("Usage: arsenal ask --plan \"hunt XSS on example.com\"")
        return 2
    try:
        result = plan_hunt(text, ctx)
    except ValueError as exc:
        print("Error: %s" % exc)
        return 1
    plan = result["plan"]
    print("Hunt plan written to %s" % result["path"])
    print("  mode:    %s" % plan["mode"])
    print("  targets: %s" % ", ".join(plan["targets"]))
    print("  modules: %s" % ", ".join(plan["modules"]))
    if plan.get("llm_reason"):
        print("  llm:     %s" % plan["llm_reason"])
    print("Run it with: arsenal workflow run %s" % result["path"])
    return 0


# --------------------------------------------------------------------------
# CLI: arsenal ask <target> "question"  |  arsenal ask --plan "hunt ..."
# --------------------------------------------------------------------------

def cmd_ask(args, ctx):
    question = " ".join(args.question) if isinstance(args.question, list) else str(args.question or "")
    text = answer(question, target=args.target, ctx=ctx)
    try:
        from rich.console import Console

        Console().print(text)
    except Exception:
        print(text)
    return 0


def add_parsers(sub):
    p = sub.add_parser("ask", help="Ask Arsenal about a target, or plan a hunt")
    p.add_argument("target", nargs="?", default=None,
                   help="Target identifier (as stored in the workspace)")
    p.add_argument("question", nargs="*", help="Question to ask (defaults to a workspace summary)")
    p.add_argument("--plan", dest="plan_text", nargs="*", default=None,
                   metavar="REQUEST",
                   help='Plan a hunt from natural language, e.g. --plan "hunt XSS on example.com" (writes a YAML workflow)')
    p.set_defaults(func=dispatch_ask)
    return p


def dispatch_ask(args, ctx):
    if getattr(args, "plan_text", None):
        return cmd_plan(args, ctx)
    if not args.target:
        print('Usage: arsenal ask <target> "question"  OR  arsenal ask --plan "hunt XSS on example.com"')
        return 2
    return cmd_ask(args, ctx)


def dispatch(args, ctx):
    func = getattr(args, "func", None)
    if callable(func):
        return func(args, ctx)
    raise ValueError("no command dispatch configured for ask")
