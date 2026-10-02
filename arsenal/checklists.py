"""PENTRIX ARSENAL methodology checklists.

CHECKLISTS maps a vulnerability class to a list of concrete testing steps.
Tick state is stored per target workspace in ``checklists.json``:
``{"xss": [1, 3], ...}`` with 1-based step numbers.

Library code in this module never prints; only ``dispatch`` prints.
"""

import argparse
import json
from pathlib import Path

CHECKLISTS = {
    "xss": [
        "Map all reflection points: parameters, headers, and stored inputs that render in responses.",
        "Test basic HTML injection with a unique canary string to confirm reflection and context.",
        "Identify the reflection context: HTML body, attribute, JavaScript, or URL.",
        "Try breaking out of the context: close tags, quotes, and event handlers.",
        "Test common filter bypasses: case variation, encoding, and alternative vectors.",
        "Check if input is stored and rendered later for other users (stored XSS).",
        "Verify impact safely: cookie theft, session actions, or DOM manipulation on a lab account.",
        "Confirm the finding is reproducible and document the exact payload and response.",
    ],
    "sqli": [
        "Identify inputs reaching the database: URL params, forms, headers, and JSON fields.",
        "Test quote handling: single quote, double quote, and comment sequences.",
        "Confirm the injection type: error-based, boolean-based, time-based, or union-based.",
        "Fingerprint the DBMS from error messages or behavioral differences.",
        "Determine the number of columns with ORDER BY or UNION SELECT probing.",
        "Extract the current database name, user, and version.",
        "Enumerate tables and columns of interest; read only what proves impact.",
        "Document the exact payloads, responses, and why the query logic broke.",
    ],
    "headers": [
        "Record all response headers on key pages: home, login, API, and error pages.",
        "Check for missing security headers: CSP, HSTS, X-Frame-Options, and others.",
        "Inspect the Server and X-Powered-By headers for version disclosure.",
        "Test clickjacking by framing a sensitive page from a controlled origin.",
        "Verify HSTS preload readiness and insecure downgrade paths.",
        "Check cookie flags: HttpOnly, Secure, and SameSite on session cookies.",
        "Confirm each gap is reproducible and note the precise risk it creates.",
    ],
    "jwt": [
        "Locate where tokens are issued, stored, and validated in the app.",
        "Decode the token header and payload; note alg, kid, and jku fields.",
        "Test alg=none: strip the signature and see if the token is accepted.",
        "Try algorithm confusion: an RS256 public key used as an HS256 secret.",
        "Test weak or guessable HMAC secrets with a small wordlist.",
        "Tamper with claims: role, user id, expiry, and issuer.",
        "Check token handling: expiry enforcement, revocation, and refresh flow.",
        "Document which manipulation was accepted and the exact request.",
    ],
    "cors": [
        "Send requests with arbitrary Origin values and record ACAO/ACAC headers.",
        "Test null origin and subdomain reflections.",
        "Check if credentials are allowed with a reflected, attacker-controlled origin.",
        "Probe preflight handling: methods and headers echoed from the request.",
        "Test origin validation tricks: suffix matches, prefix tricks, and parsing quirks.",
        "Verify impact with a proof of concept that reads a credentialed response.",
        "Document the exact request, response headers, and the trust decision that failed.",
    ],
    "redirect": [
        "Find all redirect parameters: url, next, redirect, return, and similar names.",
        "Test with an external domain to confirm open redirection.",
        "Try validation bypasses: protocol tricks, //evil.com, and encoded values.",
        "Check for redirect chains that launder the destination.",
        "Test javascript: and data: schemes where relevant.",
        "Verify impact: phishing delivery or token leakage through the redirect.",
        "Document the vulnerable parameter and the exact bypass used.",
    ],
    "ssrf": [
        "Find inputs that make the server fetch a URL: webhooks, previews, imports, PDF generators.",
        "Confirm outbound requests with a collaborator or controlled listener.",
        "Try to reach cloud metadata endpoints (169.254.169.254).",
        "Test internal hosts and ports: localhost, intranet names, and common services.",
        "Try parser differentials and DNS rebinding style bypasses against allowlists.",
        "Check for response reflection or blind exfiltration channels.",
        "Verify the impact boundary: read-only proof, no destructive actions.",
        "Document the input, the request the server made, and the evidence.",
    ],
    "idor": [
        "Map object references: ids in URLs, bodies, and API parameters.",
        "Swap your id for another user's id and compare responses.",
        "Test predictable ids: sequential numbers, UUIDs in logs, and leaked ids.",
        "Try parameter pollution and method changes on the same endpoint.",
        "Check related objects: nested resources and batch endpoints.",
        "Verify horizontal and vertical cases: same role vs higher privilege.",
        "Confirm with two controlled accounts; never touch real user data.",
        "Document the endpoint, the id swap, and the unauthorized data returned.",
    ],
    "recon": [
        "Define scope precisely: domains, IPs, and what is off limits.",
        "Enumerate subdomains with certificate logs, DNS data, and brute forcing.",
        "Resolve and map IPs, ASNs, and hosting providers.",
        "Scan ports and services on in-scope hosts; fingerprint versions.",
        "Crawl the app: sitemap, robots.txt, JS files, and hidden endpoints.",
        "Harvest secrets from JS, mobile apps, and public repos tied to the target.",
        "Check for takeover candidates: dangling DNS and expired services.",
        "Review tech stack headers, frameworks, and third-party components.",
        "Write up the asset inventory with entry points ranked by promise.",
    ],
    "api": [
        "Discover the full API surface: docs, OpenAPI files, and JS references.",
        "Map authentication: token types, scopes, and how auth is enforced per route.",
        "Test for broken object-level authorization on every id parameter.",
        "Test for broken function-level authorization with lower-privilege tokens.",
        "Fuzz parameters for mass assignment and unexpected fields.",
        "Check rate limits and pagination abuse on expensive endpoints.",
        "Test for injection in API inputs: SQL, NoSQL, and command contexts.",
        "Review error messages and verbose responses for data leakage.",
        "Document each endpoint, the test performed, and the exact response.",
    ],
}


# ---------------------------------------------------------------------------
# State: workspace/checklists.json, per target workspace.
# ---------------------------------------------------------------------------

def _state_path(ctx, target):
    ws = getattr(ctx, "workspace", None)
    if ws is not None and hasattr(ws, "path"):
        return Path(ws.path(target)) / "checklists.json"
    return Path.home() / ".arsenal" / "workspaces" / str(target) / "checklists.json"


def _load_state(ctx, target):
    path = _state_path(ctx, target)
    if not path.exists():
        return {}
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return state if isinstance(state, dict) else {}


def _save_state(ctx, target, state):
    path = _state_path(ctx, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def ticked_steps(ctx, cls, target=None):
    """Return the sorted list of ticked 1-based step numbers for a class."""
    state = _load_state(ctx, target)
    raw = state.get(cls, [])
    steps = [n for n in raw if isinstance(n, int) and 1 <= n <= len(CHECKLISTS[cls])]
    return sorted(set(steps))


def tick(ctx, cls, n, target=None):
    """Mark step n (1-based) of class cls as done. Idempotent.

    Raises KeyError for an unknown class and ValueError for a bad step number.
    """
    if cls not in CHECKLISTS:
        raise KeyError("unknown checklist class: %r" % (cls,))
    total = len(CHECKLISTS[cls])
    if not isinstance(n, int) or not 1 <= n <= total:
        raise ValueError("step must be between 1 and %d" % total)
    state = _load_state(ctx, target)
    steps = set(ticked_steps(ctx, cls, target))
    steps.add(n)
    state[cls] = sorted(steps)
    _save_state(ctx, target, state)
    return state[cls]


def class_progress(ctx, cls, target=None):
    """Return (ticked_count, total, pct) for one class."""
    total = len(CHECKLISTS[cls])
    ticked = len(ticked_steps(ctx, cls, target))
    pct = (ticked / total * 100.0) if total else 0.0
    return ticked, total, pct


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def add_parsers(sub):
    p = sub.add_parser("checklist", help="Methodology checklists per target")
    p.add_argument("target", help="Target name")
    p.add_argument("checklist_class", metavar="class", nargs="?",
                   default=None,
                   help="Checklist class: %s" % ", ".join(CHECKLISTS))
    p.add_argument("--tick", type=int, default=None, metavar="N",
                   help="Mark step N (1-based) as done")
    p.set_defaults(func=dispatch)
    return p


def _render_class(ctx, cls, target=None):
    lines = ["Checklist: %s (%d steps)" % (cls, len(CHECKLISTS[cls]))]
    done = set(ticked_steps(ctx, cls, target))
    for i, step in enumerate(CHECKLISTS[cls], start=1):
        mark = "x" if i in done else " "
        lines.append("[%s] %d. %s" % (mark, i, step))
    return "\n".join(lines)


def _render_overview(ctx, target=None):
    lines = ["Checklist progress:"]
    for cls in CHECKLISTS:
        ticked, total, pct = class_progress(ctx, cls, target)
        lines.append("  %-9s %d/%d (%0.1f%%)" % (cls, ticked, total, pct))
    return "\n".join(lines)


def dispatch(args, ctx):
    target = args.target
    cls = args.checklist_class
    print("Target: %s" % target)
    if cls is None:
        print(_render_overview(ctx, target))
        return
    if cls not in CHECKLISTS:
        print("Unknown checklist class: %r" % (cls,))
        print("Available: %s" % ", ".join(CHECKLISTS))
        return
    if args.tick is not None:
        try:
            tick(ctx, cls, args.tick, target)
            print("Ticked step %d of %s." % (args.tick, cls))
        except (KeyError, ValueError) as exc:
            print("Error: %s" % exc)
            return
    print(_render_class(ctx, cls, target))
