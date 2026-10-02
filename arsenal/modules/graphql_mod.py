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

from arsenal.findings import make_finding
from arsenal.http import fetch

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


def _get(url, ctx):
    try:
        return fetch(url, timeout=_timeout(ctx), allow_redirects=True)
    except Exception as exc:
        _log(ctx, "debug", "%s: request failed for %s: %s" % (NAME, url, exc))
        return None


def _finding(**kwargs):
    kwargs.setdefault("module", NAME)
    return make_finding(**kwargs)


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
