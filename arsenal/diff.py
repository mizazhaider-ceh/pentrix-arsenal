"""SNAPSHOT DIFFING: JS bundles and GraphQL schemas across runs.

katana re-crawls blind every run; nuclei is stateless; nobody tells you
"these 14 endpoints are new since Tuesday". This module snapshots JS
bundles (URL -> sha256 + endpoints extracted with jsintel-style regex)
and GraphQL schemas (introspection hash + operation list) per target
into the workspace, then diffs runs and emits "new endpoints / params /
operations" findings scored by bounty priority.

Provider API::

    from arsenal.diff import snapshot_js, snapshot_graphql, diff_runs

Storage: <workspace>/snapshots/<target-slug>/<kind>/<name>.json
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# JS endpoint extraction (jsintel-style)
# ---------------------------------------------------------------------------

# Quoted strings that look like API paths: "/api/v1/users", 'graphql', ...
QUOTED_PATH_RE = re.compile(
    r"""["'`](/(?:[A-Za-z0-9_.~!$&'()*+,;=:@/-]|%[0-9A-Fa-f]{2})+/?)["'`]""")
BARE_API_RE = re.compile(
    r"""(?<![\w/])(api/[A-Za-z0-9_.\-/{}:]+|v\d+/[A-Za-z0-9_.\-/{}:]+)""")
FETCH_CALL_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|"""
    r"""\$\.(?:get|post|ajax)|XMLHttpRequest)\s*\(\s*["'`]([^"'`]+)["'`]""")
URL_CONCAT_RE = re.compile(
    r"""["'`](https?://[^"'`\s]+)["'`]""")


def extract_js_endpoints(js_text: str) -> list[str]:
    """Extract candidate endpoints from a JS bundle, deduped and sorted."""
    found = set()
    for rx in (QUOTED_PATH_RE, BARE_API_RE, FETCH_CALL_RE):
        for m in rx.finditer(js_text or ""):
            ep = m.group(1).strip().rstrip(";,)")
            if len(ep) > 2 and " " not in ep:
                found.add(ep)
    # full URLs: keep only the path part, they are still new-surface signals
    for m in URL_CONCAT_RE.finditer(js_text or ""):
        try:
            path = urllib.parse.urlparse(m.group(1)).path
            if len(path) > 2:
                found.add(path)
        except Exception:
            continue
    return sorted(found)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def snapshot_js(bundle_url: str, js_text: str) -> dict:
    """Snapshot one JS bundle: hash + extracted endpoints."""
    return {
        "kind": "js",
        "url": bundle_url,
        "sha256": _sha256(js_text or ""),
        "size": len(js_text or ""),
        "endpoints": extract_js_endpoints(js_text or ""),
        "ts": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# GraphQL schema snapshot via introspection
# ---------------------------------------------------------------------------

INTROSPECTION_QUERY = """{
  __schema {
    queryType { name fields { name args { name } } }
    mutationType { name fields { name args { name } } }
    subscriptionType { name fields { name } }
  }
}"""


def introspection_body() -> dict:
    return {"query": INTROSPECTION_QUERY}


def snapshot_graphql(endpoint_url: str, schema_json: dict | None) -> dict:
    """Snapshot a GraphQL schema. schema_json is the parsed __schema dict
    (or None when introspection is disabled)."""
    operations: list[str] = []
    if schema_json:
        for kind in ("queryType", "mutationType", "subscriptionType"):
            node = schema_json.get(kind) or {}
            for field in node.get("fields") or []:
                args = ",".join(a.get("name", "") for a in field.get("args") or [])
                operations.append("%s.%s(%s)" % (
                    kind.replace("Type", ""), field.get("name"), args))
    canonical = json.dumps(schema_json or {}, sort_keys=True, ensure_ascii=False)
    return {
        "kind": "graphql",
        "url": endpoint_url,
        "sha256": _sha256(canonical),
        "introspection_enabled": schema_json is not None,
        "operations": sorted(operations),
        "ts": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Storage + diff
# ---------------------------------------------------------------------------

def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:80] or "target"


def _ws_dir(workspace, *parts) -> str:
    """Workspace subdir that works with the real Workspace.path(target)
    (single-arg) and with duck-typed test doubles."""
    import os
    if workspace is not None and hasattr(workspace, "path"):
        try:
            base = workspace.path(parts[0])
        except TypeError:
            base = workspace.path(*parts)
        return os.path.join(str(base), *[str(p) for p in parts[1:]])
    from pathlib import Path
    return str(Path.home() / ".arsenal" / os.path.join(*[str(p) for p in parts]))


def snapshot_path(workspace, target: str, kind: str, name: str) -> str:
    base = _ws_dir(workspace, "snapshots", _slug(target), kind)
    import os
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, _slug(name) + ".json")


def save_snapshot(workspace, target: str, kind: str, name: str, snap: dict) -> str:
    import os
    path = snapshot_path(workspace, target, kind, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(snap, fh, indent=2, ensure_ascii=False)
    hdir = os.path.join(os.path.dirname(path), ".history", _slug(name))
    os.makedirs(hdir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    with open(os.path.join(hdir, ts + ".json"), "w", encoding="utf-8") as fh:
        json.dump(snap, fh, indent=2, ensure_ascii=False)
    return path


def list_snapshot_names(workspace, target: str):
    """Yield (kind, name) for every stored latest snapshot of a target."""
    import os
    out = []
    base = _ws_dir(workspace, "snapshots", _slug(target))
    if not os.path.isdir(base):
        return out
    for kind in sorted(os.listdir(base)):
        kdir = os.path.join(base, kind)
        if not os.path.isdir(kdir) or kind.startswith("."):
            continue
        for fn in sorted(os.listdir(kdir)):
            if fn.endswith(".json"):
                out.append((kind, fn[:-5]))
    return out


def load_history(workspace, target: str, kind: str, name: str):
    """All snapshots for (target, kind, name), oldest first."""
    import os
    hdir = os.path.join(_ws_dir(workspace, "snapshots", _slug(target), kind),
                        ".history", _slug(name))
    snaps = []
    if not os.path.isdir(hdir):
        return snaps
    for fn in sorted(os.listdir(hdir)):
        if fn.endswith(".json"):
            with open(os.path.join(hdir, fn), encoding="utf-8") as fh:
                snaps.append(json.load(fh))
    return snaps


def load_snapshot(workspace, target: str, kind: str, name: str):
    import os
    path = snapshot_path(workspace, target, kind, name)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Bounty-priority scoring for new surface
# ---------------------------------------------------------------------------

_HIGH_KEYWORDS = ("admin", "internal", "debug", "upload", "export", "backup",
                  "config", "secret", "token", "payment", "billing", "user",
                  "account", "auth", "login", "graphql", "actuator", "console",
                  "swagger", "api-docs", "metrics", "health", "env")
_MED_KEYWORDS = ("v2", "v3", "beta", "staging", "test", "dev", "new",
                 "search", "report", "download", "webhook", "callback")


def score_endpoint(endpoint: str) -> tuple[str, str]:
    """(priority, reason) for a newly seen endpoint."""
    low = endpoint.lower()
    for kw in _HIGH_KEYWORDS:
        if kw in low:
            return "high", "keyword '%s' suggests privileged functionality" % kw
    for kw in _MED_KEYWORDS:
        if kw in low:
            return "medium", "keyword '%s' suggests fresh/unstable surface" % kw
    if re.search(r"/v\d+/", low):
        return "medium", "versioned API path (parallel version = wider surface)"
    return "low", "new endpoint with no priority keywords"


def score_operation(operation: str) -> tuple[str, str]:
    low = operation.lower()
    for kw in _HIGH_KEYWORDS:
        if kw in low:
            return "high", "operation name suggests privileged functionality"
    if low.startswith("mutation."):
        return "medium", "new mutation (state-changing operation)"
    return "low", "new query operation"


def diff_runs(old: dict | None, new: dict, target: str) -> list[dict]:
    """Compare two snapshots; emit scored findings for new surface.

    Findings are plain dicts matching arsenal.findings.make_finding()
    shape (module="diff"). First run (old=None) stores the baseline and
    emits nothing: no noise on day one.
    """
    from arsenal.findings import make_finding
    if old is None:
        return []
    findings = []
    kind = new.get("kind")
    if kind == "js":
        old_eps, new_eps = set(old.get("endpoints", [])), set(new.get("endpoints", []))
        for ep in sorted(new_eps - old_eps):
            prio, reason = score_endpoint(ep)
            sev = {"high": "high", "medium": "medium", "low": "info"}[prio]
            findings.append(make_finding(
                "diff", target, sev,
                "New JS endpoint since last run: %s" % ep,
                "Bundle %s changed (sha %s -> %s). Endpoint %s was not "
                "present in the previous snapshot. %s." % (
                    new.get("url"), old.get("sha256", "")[:12],
                    new.get("sha256", "")[:12], ep, reason),
                evidence="old_sha=%s new_sha=%s endpoint=%s" % (
                    old.get("sha256"), new.get("sha256"), ep),
                confidence="strong", cwe="",
                remediation="Manually review the new endpoint for auth, "
                            "IDOR and injection issues; it has not been "
                            "tested by earlier runs."))
        if old.get("sha256") != new.get("sha256") and not findings:
            findings.append(make_finding(
                "diff", target, "info",
                "JS bundle changed with no new endpoints: %s" % new.get("url"),
                "Bundle hash changed but the extracted endpoint set is "
                "identical; likely a rebuild or version bump.",
                evidence="old_sha=%s new_sha=%s" % (
                    old.get("sha256"), new.get("sha256")),
                confidence="strong"))
    elif kind == "graphql":
        old_ops, new_ops = set(old.get("operations", [])), set(new.get("operations", []))
        for op in sorted(new_ops - old_ops):
            prio, reason = score_operation(op)
            sev = {"high": "high", "medium": "medium", "low": "info"}[prio]
            findings.append(make_finding(
                "diff", target, sev,
                "New GraphQL operation since last run: %s" % op,
                "Schema hash changed (%s -> %s). Operation %s is new. %s." % (
                    old.get("sha256", "")[:12], new.get("sha256", "")[:12],
                    op, reason),
                evidence="operation=%s" % op, confidence="strong",
                remediation="Test the new operation for broken authz "
                            "(call it as low-priv and unauthenticated) and "
                            "for injection in its arguments."))
        if not old.get("introspection_enabled") and new.get("introspection_enabled"):
            findings.append(make_finding(
                "diff", target, "medium",
                "GraphQL introspection newly enabled on %s" % new.get("url"),
                "Introspection was disabled in the previous run and now "
                "returns a schema: the full API surface is exposed.",
                evidence="introspection_enabled=true", confidence="strong"))
    return findings


# ---------------------------------------------------------------------------
# Importable CLI-facing helpers (argparse wiring comes later; the
# integrator needs: arsenal diff snapshot --target URL ... / arsenal diff
# compare --target URL)
# ---------------------------------------------------------------------------

def cmd_snapshot(args, ctx) -> int:
    """Fetch JS bundles / GraphQL schema for a target and store snapshots."""
    from arsenal.http import fetch
    target = args.target
    kinds = (args.kind or "js,graphql").split(",")
    saved = 0
    if "js" in kinds:
        for bundle_url in (args.js_url or []):
            try:
                status, headers, body, _final = fetch(bundle_url, ctx=ctx)
            except Exception as exc:
                print("js fetch failed for %s: %s" % (bundle_url, exc))
                continue
            text = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body)
            snap = snapshot_js(bundle_url, text)
            path = save_snapshot(ctx.workspace, target, "js", bundle_url, snap)
            print("saved %s (%d endpoints)" % (path, len(snap["endpoints"])))
            saved += 1
    if "graphql" in kinds and getattr(args, "graphql_url", None):
        try:
            import urllib.request
            req = urllib.request.Request(
                args.graphql_url,
                data=json.dumps(introspection_body()).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
            schema = ((data.get("data") or {}).get("__schema"))
        except Exception as exc:
            print("graphql introspection failed: %s" % exc)
            schema = None
        snap = snapshot_graphql(args.graphql_url, schema)
        path = save_snapshot(ctx.workspace, target, "graphql", args.graphql_url, snap)
        print("saved %s (%d operations, introspection=%s)" % (
            path, len(snap["operations"]), snap["introspection_enabled"]))
        saved += 1
    return 0 if saved else 1


def cmd_compare(args, ctx) -> int:
    """Diff the two latest snapshots per (kind, name) for a target."""
    target = args.target
    total = 0
    names = list_snapshot_names(ctx.workspace, target)
    if not names:
        print("no snapshots stored for '%s'; run diff snapshot first" % target)
        return 1
    for kind, name in names:
        hist = load_history(ctx.workspace, target, kind, name)
        if len(hist) < 2:
            print("%s %s: only one snapshot, nothing to compare yet" % (kind, name))
            continue
        for f in diff_runs(hist[-2], hist[-1], target):
            print("[%s] %s" % (str(f.get("severity", "info")).upper(),
                               f.get("title", "")))
            total += 1
    if total == 0:
        print("no new surface since the previous snapshot for %s" % target)
    else:
        print("%d new-surface finding(s) for %s" % (total, target))
    return 0


ARGPARSE_SNIPPET = '''
# --- integrator: add to arsenal/cli.py subparsers ---
p = sub.add_parser("diff", help="JS bundle / GraphQL schema snapshot diffing")
dsub = p.add_subparsers(dest="diff_cmd", required=True)
s = dsub.add_parser("snapshot", help="Snapshot JS bundles / GraphQL schema")
s.add_argument("--target", required=True)
s.add_argument("--kind", default="js,graphql")
s.add_argument("--js-url", action="append", default=[])
s.add_argument("--graphql-url")
s.set_defaults(func=arsenal.diff.cmd_snapshot)
c = dsub.add_parser("compare", help="Diff runs (see arsenal.diff.diff_runs)")
c.add_argument("--target", required=True)
c.set_defaults(func=arsenal.diff.cmd_compare)
'''
