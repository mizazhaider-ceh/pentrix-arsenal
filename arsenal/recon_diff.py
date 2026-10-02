"""RECON DIFF REPORTS: "what changed since last run".

ZAP has no cross-run intelligence; the recon stack gives you two text
files and a prayer. This module diffs stored recon artifacts per target
(subdomains, endpoints, tech stack, certificates) and scores every
change by bounty priority, emitting markdown + JSON.

Artifact layout (written by recon flows, read here):

    <workspace>/recon/<target-slug>/subdomains.json   {"items": [...], "ts"}
    <workspace>/recon/<target-slug>/endpoints.json
    <workspace>/recon/<target-slug>/tech.json         {"items": {...}}
    <workspace>/recon/<target-slug>/certs.json        {"items": [...]}

Provider API::

    from arsenal import recon_diff
    recon_diff.save_artifact(workspace, target, "subdomains", items)
    report = recon_diff.diff_target(workspace, target, current={...})
    recon_diff.render_markdown(report)  # markdown string
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone

KINDS = ("subdomains", "endpoints", "tech", "certs")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-")[:80] or "t"


def _ws_dir(workspace, *parts) -> str:
    import os
    if workspace is not None and hasattr(workspace, "path"):
        try:
            base = workspace.path(parts[0])
        except TypeError:
            base = workspace.path(*parts)
        return os.path.join(str(base), *[str(p) for p in parts[1:]])
    from pathlib import Path
    return str(Path.home() / ".arsenal" / os.path.join(*[str(p) for p in parts]))


def artifact_path(workspace, target: str, kind: str) -> str:
    base = _ws_dir(workspace, "recon", _slug(target))
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, kind + ".json")


def save_artifact(workspace, target: str, kind: str, items) -> str:
    """Store the current artifact. items: list (or dict for tech)."""
    if kind not in KINDS:
        raise ValueError("kind must be one of %s" % (KINDS,))
    path = artifact_path(workspace, target, kind)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"items": items,
                   "ts": datetime.now(timezone.utc).isoformat()},
                  fh, indent=2, ensure_ascii=False)
    return path


def load_artifact(workspace, target: str, kind: str):
    path = artifact_path(workspace, target, kind)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Bounty-priority scoring
# ---------------------------------------------------------------------------

_SUB_HIGH = ("admin", "internal", "dev", "staging", "test", "api", "vpn",
             "git", "jenkins", "grafana", "kibana", "db", "backup", "portal",
             "sso", "auth", "pay", "beta", "legacy", "old")
_SUB_MED = ("blog", "docs", "status", "cdn", "static", "assets", "mail")


def score_subdomain(sub: str) -> tuple[str, str]:
    low = sub.lower().split(".")[0]
    for kw in _SUB_HIGH:
        if kw in low:
            return "high", "prefix '%s' suggests privileged infra" % kw
    for kw in _SUB_MED:
        if kw in low:
            return "medium", "prefix '%s' is usually secondary surface" % kw
    return "low", "new subdomain"


def score_tech_change(name: str, old_v, new_v) -> tuple[str, str]:
    low = name.lower()
    if old_v is None:
        if any(k in low for k in ("waf", "cdn", "bot", "captcha")):
            return "medium", "new protective tech changes bypass calculus"
        return "low", "new tech detected"
    return "medium", "version changed %s -> %s" % (old_v, new_v)


def diff_target(workspace, target: str, current: dict) -> dict:
    """Diff current recon data vs stored artifacts.

    current: {kind: items}. Returns a report dict with scored changes.
    First run stores the baseline and reports no changes.
    """
    changes = []
    is_first = True
    for kind in KINDS:
        items = current.get(kind)
        if items is None:
            continue
        old_doc = load_artifact(workspace, target, kind)
        if old_doc is not None:
            is_first = False
            old_items = old_doc.get("items")
            new, gone = _diff_items(kind, old_items, items)
            for item in new:
                prio, reason = _score(kind, item, old_items, items)
                changes.append({"kind": kind, "change": "added",
                                "item": item, "priority": prio,
                                "reason": reason})
            for item in gone:
                changes.append({"kind": kind, "change": "removed",
                                "item": item, "priority": "low",
                                "reason": "surface shrank"})
        save_artifact(workspace, target, kind, items)
    order = {"high": 0, "medium": 1, "low": 2}
    changes.sort(key=lambda c: (order[c["priority"]], c["kind"]))
    return {
        "target": target,
        "ts": datetime.now(timezone.utc).isoformat(),
        "baseline": is_first,
        "changes": changes,
        "summary": _summarize(changes),
    }


def _as_set(items):
    if isinstance(items, dict):
        return set(json.dumps(v, sort_keys=True) for v in items.values()), items
    return set(map(str, items or [])), None


def _diff_items(kind, old_items, new_items):
    if kind == "tech" and isinstance(old_items, dict) \
            and isinstance(new_items, dict):
        new, gone = [], []
        for k, v in new_items.items():
            if k not in old_items:
                new.append("%s=%s" % (k, v))
            elif old_items[k] != v:
                new.append("%s: %s -> %s" % (k, old_items[k], v))
        for k in old_items:
            if k not in new_items:
                gone.append(k)
        return new, gone
    old_set = set(map(str, old_items or []))
    new_set = set(map(str, new_items or []))
    return sorted(new_set - old_set), sorted(old_set - new_set)


def _score(kind, item, old_items, new_items):
    if kind == "subdomains":
        return score_subdomain(item)
    if kind == "endpoints":
        from arsenal.diff import score_endpoint
        return score_endpoint(item)
    if kind == "tech":
        m = re.match(r"([^=:]+)(?::\s*(.*?)\s*->\s*(.*)|=(.*))?$", item)
        if m and "->" in item:
            return score_tech_change(m.group(1), m.group(2), m.group(3))
        return score_tech_change(item.split("=")[0], None, None)
    return "low", "new certificate observed"


def _summarize(changes):
    counts = {}
    for c in changes:
        counts[c["priority"]] = counts.get(c["priority"], 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_markdown(report: dict) -> str:
    lines = ["# Recon diff: %s" % report["target"],
             "_%s_" % report["ts"], ""]
    if report["baseline"]:
        lines.append("Baseline stored. Future runs will diff against it.")
        return "\n".join(lines)
    if not report["changes"]:
        lines.append("No changes since last run.")
        return "\n".join(lines)
    lines.append("## Summary")
    for prio in ("high", "medium", "low"):
        n = report["summary"].get(prio, 0)
        if n:
            lines.append("- **%s**: %d" % (prio, n))
    lines.append("")
    cur_kind = None
    for c in report["changes"]:
        if c["kind"] != cur_kind:
            cur_kind = c["kind"]
            lines.append("## %s" % cur_kind)
        mark = {"high": "[HIGH]", "medium": "[MED]", "low": "[low]"}[c["priority"]]
        arrow = "+" if c["change"] == "added" else "-"
        lines.append("%s %s `%s` - %s" % (mark, arrow, c["item"], c["reason"]))
    return "\n".join(lines)


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)


ARGPARSE_SNIPPET = '''
# --- integrator: add to arsenal/cli.py subparsers ---
p = sub.add_parser("recondiff", help="Recon diff reports")
p.add_argument("--target", required=True)
p.add_argument("--subdomains", nargs="*", default=None)
p.add_argument("--endpoints", nargs="*", default=None)
p.add_argument("--format", choices=["md", "json"], default="md")
p.set_defaults(func=arsenal.recon_diff.cmd_recondiff)
'''


def cmd_recondiff(args, ctx) -> int:
    current = {}
    if args.subdomains is not None:
        current["subdomains"] = args.subdomains
    if args.endpoints is not None:
        current["endpoints"] = args.endpoints
    report = diff_target(ctx.workspace, args.target, current)
    print(render_markdown(report) if args.format == "md"
          else render_json(report))
    return 0
