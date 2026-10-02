"""ASK ARSENAL: conversational Q&A over the workspace for a target.

gather_context() builds a compact, truncated textual summary of everything the
workspace knows about a target. answer() replies to a question using the LLM
when available, with a keyword-based rule engine as fallback. Library
functions never print; the CLI dispatch prints the answer (via rich if present).
"""

from __future__ import annotations

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
# CLI: arsenal ask <target> "question"
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
    p = sub.add_parser("ask", help="Ask Arsenal about a target's workspace")
    p.add_argument("target", help="Target identifier (as stored in the workspace)")
    p.add_argument("question", nargs="*", help="Question to ask (defaults to a workspace summary)")
    p.set_defaults(func=cmd_ask)
    return p


def dispatch(args, ctx):
    func = getattr(args, "func", None)
    if callable(func):
        return func(args, ctx)
    raise ValueError("no command dispatch configured for ask")
