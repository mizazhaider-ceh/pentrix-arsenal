"""DUPLICATE FINDING CHECK + DEDUP ENGINE.

    arsenal dupcheck <target>

Cross-module finding deduplication and duplicate prediction:

* fingerprint(finding) -> stable string key from kind+host+param+evidence
  hash, so the same issue found by two modules (or two runs) collapses.
* dedupe_findings(findings) -> (unique, duplicates); duplicates get a
  "duplicate_of" pointer to the surviving finding's fingerprint.
* similarity(a, b) -> 0.0-1.0 weighted field similarity for duplicate
  prediction.
* predict_duplicate(finding, ctx) -> (score, reason): how likely this
  finding duplicates an already-known one.
* check(finding, ctx) / warn_duplicates(findings, ctx): warn when a
  finding resembles a record the analyst already marked "duplicate".

Library functions never print (the CLI entry point below may).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from rich.console import Console

console = Console()

_STOPWORDS = {
    "the", "and", "for", "with", "from", "via", "into", "that", "this",
    "these", "those", "are", "was", "were", "has", "have", "had", "its",
    "our", "your", "their", "not", "but", "all", "any", "can", "may",
    "one", "two", "new", "old", "using", "used", "use", "allow",
    "allows", "potential", "possible", "found", "page",
}


def _significant_words(title) -> set:
    words = re.findall(r"[a-z0-9]+", str(title or "").lower())
    return {w for w in words if len(w) >= 3 and w not in _STOPWORDS}


def _norm_host(finding) -> str:
    host = (finding.get("host") or finding.get("target") or "")
    host = str(host).strip().lower()
    if "://" in host:
        try:
            from urllib.parse import urlsplit
            host = urlsplit(host).hostname or host
        except Exception:
            pass
    return host.split("/")[0].split(":")[0]


def _norm_param(finding) -> str:
    for key in ("param", "parameter", "injection_point", "field"):
        val = finding.get(key)
        if val:
            return str(val).strip().lower()
    # Fall back to the first query parameter of a recorded URL.
    for key in ("url", "location"):
        val = str(finding.get(key) or "")
        if "?" in val:
            try:
                from urllib.parse import urlsplit, parse_qsl
                pairs = parse_qsl(urlsplit(val).query)
                if pairs:
                    return pairs[0][0].lower()
            except Exception:
                pass
    return ""


def _norm_kind(finding) -> str:
    for key in ("kind", "vuln_class", "class"):
        val = finding.get(key)
        if val:
            return str(val).strip().lower()
    return str(finding.get("module") or "").strip().lower()


def fingerprint(finding) -> str:
    """Stable dedup key: sha1(kind | host | param | evidence-hash).

    The evidence hash uses only the first 400 chars so re-runs with
    slightly different trailing evidence still collapse.
    """
    if not isinstance(finding, dict):
        return "invalid"
    kind = _norm_kind(finding)
    host = _norm_host(finding)
    param = _norm_param(finding)
    evidence = str(finding.get("evidence") or "")[:400]
    ev_hash = hashlib.sha1(evidence.encode("utf-8", errors="replace")).hexdigest()[:12]
    raw = "%s|%s|%s|%s" % (kind, host, param, ev_hash)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def dedupe_findings(findings):
    """Collapse findings with identical fingerprints.

    Returns (unique, duplicates). Each duplicate gets "duplicate_of" set
    to the surviving finding's fingerprint and keeps its original index in
    "_dup_index" for traceability. The first occurrence wins; a finding
    with stronger confidence wins ties (proven > strong > review).
    """
    _CONF_RANK = {"proven": 0, "strong": 1, "review": 2}
    unique = []
    duplicates = []
    by_fp = {}
    for idx, f in enumerate(findings or []):
        if not isinstance(f, dict):
            continue
        fp = fingerprint(f)
        incumbent = by_fp.get(fp)
        if incumbent is None:
            by_fp[fp] = f
            f["_fingerprint"] = fp
            unique.append(f)
            continue
        rank_new = _CONF_RANK.get(str(f.get("confidence", "review")).lower(), 2)
        rank_old = _CONF_RANK.get(str(incumbent.get("confidence", "review")).lower(), 2)
        if rank_new < rank_old:
            # Stronger evidence wins; demote the previous incumbent.
            unique[unique.index(incumbent)] = f
            f["_fingerprint"] = fp
            incumbent["duplicate_of"] = fp
            incumbent["_dup_index"] = idx
            duplicates.append(incumbent)
            by_fp[fp] = f
        else:
            f["duplicate_of"] = fp
            f["_dup_index"] = idx
            duplicates.append(f)
    return unique, duplicates


def similarity(a, b) -> float:
    """Weighted 0.0-1.0 similarity between two finding dicts."""
    if not isinstance(a, dict) or not isinstance(b, dict):
        return 0.0
    score = 0.0
    # Same normalized kind/module: strong signal (0.35).
    if _norm_kind(a) and _norm_kind(a) == _norm_kind(b):
        score += 0.35
    # Same host (0.25).
    if _norm_host(a) and _norm_host(a) == _norm_host(b):
        score += 0.25
    # Same parameter (0.20); only counts when both name one.
    pa, pb = _norm_param(a), _norm_param(b)
    if pa and pa == pb:
        score += 0.20
    # Title word overlap (up to 0.20).
    wa, wb = _significant_words(a.get("title")), _significant_words(b.get("title"))
    if wa and wb:
        overlap = len(wa & wb) / max(len(wa), len(wb))
        score += 0.20 * overlap
    return round(min(1.0, score), 3)


def _workspaces_roots(ctx):
    roots = []
    home = Path.home()
    for name in ("workspaces", "workspace"):
        d = home / ".arsenal" / name
        if d.is_dir():
            roots.append(d)
    extra = getattr(ctx, "workspaces_root", None)
    if extra:
        p = Path(extra)
        if p.is_dir() and p not in roots:
            roots.append(p)
    ws = getattr(ctx, "workspace", None)
    wroot = getattr(ws, "root", None)
    if wroot:
        p = Path(os.path.expanduser(str(wroot)))
        if p.is_dir() and p not in roots:
            roots.append(p)
    return roots


def _known_duplicates(ctx):
    """Yield (finding_dict, source_workspace_name) for status == duplicate."""
    for root in _workspaces_roots(ctx):
        for child in sorted(root.iterdir()):
            if not child.is_dir():
                continue
            path = child / "findings.json"
            if not path.exists():
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(data, dict):
                data = data.get("findings", [])
            if not isinstance(data, list):
                continue
            for rec in data:
                if not isinstance(rec, dict):
                    continue
                if str(rec.get("status") or "").lower() == "duplicate":
                    yield rec, child.name


def _all_known_findings(ctx):
    """Yield (finding_dict, source_workspace_name) for every known finding."""
    for root in _workspaces_roots(ctx):
        for child in sorted(root.iterdir()):
            if not child.is_dir():
                continue
            path = child / "findings.json"
            if not path.exists():
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(data, dict):
                data = data.get("findings", [])
            if not isinstance(data, list):
                continue
            for rec in data:
                if isinstance(rec, dict):
                    yield rec, child.name


def _target_findings(target, ctx):
    """Load findings for a target (workspace files, or ctx.workspace)."""
    candidates = []
    ws = getattr(ctx, "workspace", None)
    if ws is not None:
        try:
            if hasattr(ws, "path"):
                candidates.append(Path(ws.path(target)) / "findings.json")
            else:
                candidates.append(Path(ws) / str(target) / "findings.json")
        except Exception:
            pass
    home = Path.home()
    for name in ("workspace", "workspaces"):
        candidates.append(home / ".arsenal" / name / str(target) / "findings.json")
    for p in candidates:
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            data = data.get("findings", [])
        if isinstance(data, list):
            return [f for f in data if isinstance(f, dict)]
    return []


def predict_duplicate(finding, ctx, threshold=0.6):
    """Score how likely *finding* duplicates an already-known finding.

    Returns (score, reason). score is the best similarity to any known
    finding; reason names the match. An exact fingerprint hit scores 1.0.
    """
    if not isinstance(finding, dict):
        return 0.0, "not a finding dict"
    fp = fingerprint(finding)
    best, best_rec, best_ws = 0.0, None, ""
    for rec, ws_name in _all_known_findings(ctx):
        if rec is finding:
            continue
        if fingerprint(rec) == fp:
            return 1.0, "exact fingerprint match with '%s' in workspace '%s'" % (
                rec.get("title", "?"), ws_name)
        sim = similarity(finding, rec)
        if sim > best:
            best, best_rec, best_ws = sim, rec, ws_name
    if best_rec is not None and best >= threshold:
        return best, "similar to '%s' [%s] in workspace '%s' (similarity %.2f)" % (
            best_rec.get("title", "?"), best_rec.get("module", "?"), best_ws, best)
    return best, "no close match (best similarity %.2f)" % best


def check(finding, ctx):
    """Return warning strings if finding resembles a known duplicate."""
    warnings = []
    if not isinstance(finding, dict):
        return warnings
    module = str(finding.get("module") or "").lower()
    sig = _significant_words(finding.get("title"))
    if not module or len(sig) < 3:
        return warnings
    title = str(finding.get("title") or "untitled")
    for dup, ws_name in _known_duplicates(ctx):
        if str(dup.get("module") or "").lower() != module:
            continue
        shared = sig & _significant_words(dup.get("title"))
        if len(shared) >= 3:
            warnings.append(
                "Possible duplicate: [%s] '%s' shares "
                "%d significant title word(s) "
                "(%s) with a known duplicate "
                "in workspace '%s': '%s'."
                % (module, title, len(shared), ", ".join(sorted(shared)),
                   ws_name, dup.get("title"))
            )
    # Similarity-based prediction against every known finding.
    score, reason = predict_duplicate(finding, ctx)
    if score >= 0.8:
        warnings.append(
            "Duplicate prediction %.0f%%: [%s] '%s' %s."
            % (score * 100, module, title, reason)
        )
    return warnings


def warn_duplicates(findings, ctx):
    """Run check() over every finding; return the combined warnings."""
    warnings = []
    for finding in findings or []:
        warnings.extend(check(finding, ctx))
    return warnings


def cmd_dupcheck(args, ctx) -> int:
    findings = _target_findings(args.target, ctx)
    if not findings:
        console.print("[yellow]No findings stored for target '%s'.[/]" % args.target)
        return 0
    unique, dups = dedupe_findings(findings)
    if dups:
        console.print("[bold yellow]%d of %d finding(s) are exact duplicates "
                      "(same fingerprint):[/]" % (len(dups), len(findings)))
        for d in dups:
            console.print("  [dim]dup of %s[/dim] %s" %
                          (d.get("duplicate_of", "?")[:8],
                           d.get("title", "?")))
    warnings = warn_duplicates(unique, ctx)
    if not warnings and not dups:
        console.print("[green]No likely duplicates found for '%s' "
                      "(%d finding(s) checked).[/]" % (args.target, len(findings)))
        return 0
    if warnings:
        console.print("[bold yellow]%d duplicate warning(s)[/] for '%s':"
                      % (len(warnings), args.target))
        for w in warnings:
            console.print("  [!] %s" % w)
    return 0


def add_parsers(sub):
    p = sub.add_parser(
        "dupcheck",
        help="Dedup findings and warn about likely duplicates",
        description=(
            "Collapses findings with identical fingerprints (kind+host+"
            "param+evidence hash), then scans known workspaces for records "
            "marked 'duplicate' resembling this target's findings."
        ),
    )
    p.add_argument("target", help="Target identifier (as stored in the workspace)")
    p.set_defaults(func=cmd_dupcheck)
    return p


def dispatch(args, ctx):
    func = getattr(args, "func", None)
    if callable(func):
        return func(args, ctx)
    raise ValueError("no command dispatch configured for dupcheck")
