"""PENTRIX ARSENAL module: GraphQL introspection detection.

Tries common GraphQL path variants (/graphql, /graphiql, /api/graphql,
...) against the target and sends an introspection query via a GET
request. If the response contains schema data (__schema with queryType),
introspection is enabled, which exposes the full API surface to
attackers. Reported at high severity; the verify step can promote the
confidence to "proven".

Non-intrusive: read-only queries only.
"""

import urllib.parse
from arsenal.modules.base import BaseModule


NAME = "graphql"
DESCRIPTION = (
    "Detects GraphQL endpoints with introspection enabled by sending a "
    "schema query to common GraphQL paths."
)
TARGET_KIND = "url"
INTRUSIVE = False

TIMEOUT = 10
MAX_BODY_BYTES = 2 * 1024 * 1024

PATH_VARIANTS = [
    "",
    "/graphql",
    "/graphiql",
    "/graphql/",
    "/api/graphql",
    "/v1/graphql",
    "/query",
]

INTROSPECTION_QUERY = "{__schema{queryType{name}}}"


# ---------------------------------------------------------------------------
# Shared module helpers, bound from arsenal.modules.base (replaces the old
# per-module copies). All HTTP goes through arsenal.http with ctx, so
# stealth sleeps, UA rotation and proxy settings apply to module traffic.
# ---------------------------------------------------------------------------
_mod = BaseModule(NAME, TIMEOUT)
_timeout = _mod.timeout
_log = _mod.log
_is_http_url = _mod.is_http_url
_host_of = _mod.host_of
_in_scope = _mod.in_scope
_get = _mod.get
_finding = _mod.finding

def run(target, ctx):
    """Detect GraphQL introspection on common endpoint paths."""
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
    base = target.rstrip("/")
    encoded = urllib.parse.quote(INTROSPECTION_QUERY, safe="")
    for variant in PATH_VARIANTS:
        url = "%s%s?query=%s" % (base, variant, encoded)
        resp = _get(url, ctx)
        if resp is None:
            continue
        status, headers, body, final_url = resp
        if status >= 500 or len(body) > MAX_BODY_BYTES:
            continue
        text = body.decode("utf-8", errors="replace")
        if '"__schema"' in text and '"queryType"' in text:
            excerpt = text[:400].replace("\n", " ")
            return [_finding(
                target=target,
                severity="high",
                confidence="review",
                title="GraphQL introspection enabled",
                description=(
                    "The GraphQL endpoint at %s answers introspection "
                    "queries, exposing the full schema (types, queries, "
                    "mutations) to unauthenticated callers." % final_url
                ),
                evidence="GET %s\nHTTP %s\nResponse excerpt: %s..."
                         % (url, status, excerpt),
                cwe="CWE-200",
                remediation=(
                    "Disable introspection in production and restrict the "
                    "GraphQL endpoint to authenticated callers."
                ),
            )]
    return []
