"""PENTRIX ARSENAL module: advanced GraphQL checks over POST.

Discovers a GraphQL endpoint (target itself plus /graphql,
/api/graphql, /graphiql) and runs deeper checks than graphql_mod:

1. Full introspection dump: posts the standard __schema query and
   reports when introspection is enabled, with type counts.
2. Field/mutation enumeration: lists query and mutation fields from
   the schema as an attack-surface map.
3. Batching test: sends an array of aliased queries; if the server
   executes the batch, brute-force amplification is possible.
4. Depth/complexity analysis: sends a deeply nested introspection
   query and notes whether the server processes it without depth
   limiting (light probe, no heavy DoS).

Non-intrusive: a few small POSTs; the depth probe is one nested query.
"""

import json
import time
import urllib.parse

from arsenal.findings import make_finding
from arsenal.http import fetch

NAME = "graphql_adv"
DESCRIPTION = (
    "Deeper GraphQL testing over POST: full introspection dump, field "
    "enumeration, batching brute-force test, depth/complexity analysis."
)
TARGET_KIND = "url"
INTRUSIVE = False

TIMEOUT = 15

INTROSPECTION_QUERY = """{
  __schema {
    queryType { name }
    mutationType { name }
    types { name kind }
  }
}"""

MUTATION_ENUM_QUERY = """{
  __schema {
    mutationType {
      fields { name args { name } }
    }
    queryType {
      fields { name args { name } }
    }
  }
}"""

DEPTH_QUERY = "{ __schema { types { fields { type { ofType { ofType { ofType { ofType { ofType { name } } } } } } } } }"


def _timeout(ctx):
    cfg = getattr(ctx, "config", None)
    if isinstance(cfg, dict):
        return cfg.get("timeout", TIMEOUT)
    if cfg is not None:
        return getattr(cfg, "timeout", TIMEOUT)
    return TIMEOUT


def _log(ctx, level, msg):
    log = getattr(ctx, "log", None)
    if log is None:
        return
    try:
        getattr(log, level, log.warning)(msg)
    except Exception:
        pass


def _is_http_url(target):
    try:
        parts = urllib.parse.urlsplit(target)
    except Exception:
        return False
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def _host_of(url):
    try:
        return urllib.parse.urlsplit(url).hostname or ""
    except Exception:
        return ""


def _in_scope(target, ctx):
    scope = getattr(ctx, "scope", None)
    if scope is None:
        return True
    try:
        return bool(scope.contains(_host_of(target)))
    except Exception:
        return True


def _finding(**kwargs):
    kwargs.setdefault("module", NAME)
    return make_finding(**kwargs)


def _post_gql(url, ctx, payload_obj):
    data = json.dumps(payload_obj).encode("utf-8")
    start = time.monotonic()
    try:
        resp = fetch(url, method="POST", timeout=_timeout(ctx),
                     headers={"Content-Type": "application/json",
                              "Accept": "application/json"},
                     data=data, allow_redirects=True, ctx=ctx)
    except Exception as exc:
        _log(ctx, "debug", "%s: request failed for %s: %s" % (NAME, url, exc))
        return None, 0.0
    return resp, time.monotonic() - start


def _json_body(resp):
    if resp is None:
        return None
    _status, _headers, body, _final = resp
    try:
        return json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        return None


def _candidate_endpoints(target):
    parts = urllib.parse.urlsplit(target)
    base = "%s://%s" % (parts.scheme, parts.netloc)
    cands = [target]
    if "graphql" not in parts.path and "graphiql" not in parts.path:
        for p in ("/graphql", "/api/graphql", "/graphiql", "/v1/graphql"):
            cands.append(base + p)
    seen, out = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def run(target, ctx):
    """Run advanced GraphQL checks."""
    try:
        return _run(target, ctx)
    except Exception as exc:
        _log(ctx, "warning", "%s failed on %s: %s" % (NAME, target, exc))
        return []


def _run(target, ctx):
    if not _is_http_url(target):
        return []
    if not _in_scope(target, ctx):
        _log(ctx, "warning", "%s: target out of scope: %s" % (NAME, target))
        return []
    findings = []
    endpoint = None
    for cand in _candidate_endpoints(target):
        resp, _e = _post_gql(cand, ctx, {"query": "{__typename}"})
        data = _json_body(resp)
        if isinstance(data, dict) and "data" in data:
            endpoint = cand
            break
    if endpoint is None:
        return []

    # 1. Full introspection dump.
    resp, _e = _post_gql(endpoint, ctx, {"query": INTROSPECTION_QUERY})
    data = _json_body(resp)
    schema = (data or {}).get("data", {}).get("__schema")
    if isinstance(schema, dict):
        types = schema.get("types") or []
        findings.append(_finding(
            target=target,
            severity="medium",
            title="GraphQL introspection enabled",
            description=(
                "The endpoint answers __schema introspection, exposing the "
                "full API surface (%d types). Dump the schema and hunt for "
                "sensitive fields and mutations." % len(types)),
            evidence=(
                "Endpoint: POST %s\n"
                "\"__schema\" present with %d types; queryType=%s "
                "mutationType=%s"
                % (endpoint, len(types),
                   (schema.get("queryType") or {}).get("name"),
                   (schema.get("mutationType") or {}).get("name"))),
            confidence="strong",
            cwe="CWE-200",
            remediation="Disable introspection in production."))

        # 2. Field/mutation enumeration.
        resp2, _e2 = _post_gql(endpoint, ctx, {"query": MUTATION_ENUM_QUERY})
        data2 = _json_body(resp2)
        sch2 = (data2 or {}).get("data", {}).get("__schema", {})
        mutations = [f.get("name") for f in
                     ((sch2.get("mutationType") or {}).get("fields") or [])
                     if f.get("name")]
        queries = [f.get("name") for f in
                   ((sch2.get("queryType") or {}).get("fields") or [])
                   if f.get("name")]
        if mutations or queries:
            findings.append(_finding(
                target=target, severity="info",
                title="GraphQL field map (%d queries, %d mutations)"
                      % (len(queries), len(mutations)),
                description="Enumerated top-level fields from introspection. "
                            "Prioritize mutations and fields returning user "
                            "objects for IDOR/BOLA testing.",
                evidence="Queries: %s\nMutations: %s"
                         % (", ".join(queries[:30]), ", ".join(mutations[:30])),
                confidence="strong", cwe="CWE-200",
                remediation="Apply field-level authorization; hide admin "
                            "fields from the public schema."))

    # 3. Batching brute-force test.
    batch = [{"query": "{__typename}"},
             {"query": "{__typename}"},
             {"query": "{__typename}"}]
    resp, _e = _post_gql(endpoint, ctx, batch)
    data = _json_body(resp)
    if isinstance(data, list) and len(data) == len(batch) \
            and all(isinstance(x, dict) and "data" in x for x in data):
        findings.append(_finding(
            target=target, severity="low",
            title="GraphQL query batching enabled",
            description=(
                "The server executed a batched array of %d queries in one "
                "request. Batching enables brute-force amplification "
                "(e.g. batched login attempts bypassing rate limits); test "
                "whether batched mutations bypass throttling." % len(batch)),
            evidence="Endpoint: POST %s\nSent %d queries, got %d results."
                     % (endpoint, len(batch), len(data)),
            confidence="strong", cwe="CWE-400",
            remediation="Limit batch size or disable batching; rate-limit "
                        "per operation, not per HTTP request."))

    # 4. Depth/complexity analysis (one light nested query).
    resp, elapsed = _post_gql(endpoint, ctx, {"query": DEPTH_QUERY})
    data = _json_body(resp)
    if isinstance(data, dict) and "data" in data:
        findings.append(_finding(
            target=target, severity="info",
            title="No GraphQL depth limiting observed (light probe)",
            description=(
                "A deeply nested introspection query was processed in "
                "%.2fs without a depth/complexity error. The endpoint may "
                "be open to expensive nested queries; test query-cost "
                "analysis with authorization before reporting." % elapsed),
            evidence="Endpoint: POST %s | nested query accepted, %.2fs"
                     % (endpoint, elapsed),
            confidence="review", cwe="CWE-400",
            remediation="Enforce max query depth and computed query cost."))
    return findings
