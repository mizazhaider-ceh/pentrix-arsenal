"""Chain suggester: combine individual findings into attack chains.

suggest_chains(findings) matches findings on STRUCTURED fields
(module, kind, param, host, url) first and only falls back to title
keywords where no structured signal exists. Returns ranked chain dicts:
    {"name", "severity", "findings": [titles], "reasoning", "next_steps"}
"""

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sig(finding):
    """Structured signals for one finding."""
    module = str(finding.get("module") or "").lower()
    kind = str(finding.get("kind") or finding.get("vuln_class") or "").lower()
    param = str(finding.get("param") or finding.get("parameter") or "").lower()
    host = str(finding.get("host") or finding.get("target") or "").lower()
    url = str(finding.get("url") or finding.get("location") or "").lower()
    title = str(finding.get("title") or "").lower()
    desc = str(finding.get("description") or "").lower()
    evidence = str(finding.get("evidence") or "").lower()
    return {"module": module, "kind": kind, "param": param, "host": host,
            "url": url, "title": title, "desc": desc, "evidence": evidence}


def _text(finding):
    """Lowercased searchable text for one finding (fallback signal)."""
    parts = [
        finding.get("module", ""),
        finding.get("title", ""),
        finding.get("description", ""),
        finding.get("evidence", ""),
    ]
    return " ".join(str(p) for p in parts).lower()


def _by_module(findings, *modules):
    """Findings whose module is one of the given names (structured)."""
    wanted = {m.lower() for m in modules}
    return [f for f in findings if _sig(f)["module"] in wanted]


def _by_kind(findings, *kinds):
    """Findings whose kind/vuln_class matches (structured)."""
    wanted = {k.lower() for k in kinds}
    return [f for f in findings if _sig(f)["kind"] in wanted]


def _any(findings, *keywords):
    """Findings whose text contains any of the keywords (fallback)."""
    return [f for f in findings if any(k in _text(f) for k in keywords)]


def _titles(matched):
    return [f.get("title", "untitled") for f in matched]


def _chain(name, severity, matched, reasoning, next_steps):
    return {
        "name": name,
        "severity": severity,
        "findings": _titles(matched),
        "reasoning": reasoning,
        "next_steps": next_steps,
    }


def suggest_chains(findings):
    """Suggest exploit chains from a list of finding dicts.

    Each rule fires at most once. Chains are ranked: critical/high first.
    Pure function: no network, no printing, no exceptions on bad input.
    """
    findings = [f for f in (findings or []) if isinstance(f, dict)]
    chains = []

    # 1. Open redirect + OAuth issue -> OAuth redirect theft -> ATO
    redirects = _by_module(findings, "redirect")
    if not redirects:
        redirects = _any(findings, "open redirect")
    oauth = _by_module(findings, "oauth")
    if not oauth:
        oauth = _any(findings, "oauth", "openid connect", "openid")
    if redirects and oauth:
        matched = redirects + [f for f in oauth if f not in redirects]
        chains.append(_chain(
            "OAuth redirect theft -> account takeover",
            "high",
            matched,
            "The application has an open redirect, and it also participates in "
            "an OAuth/OIDC flow. An attacker can point the redirect at an "
            "attacker-controlled page, and the victim's browser will carry the "
            "OAuth authorization code or token to it. The attacker redeems the "
            "code and signs in as the victim.",
            "Manually craft the OAuth authorize request with redirect_uri set "
            "to an attacker domain (or the open-redirect endpoint with your "
            "domain as its target). If the provider accepts it and issues a "
            "code, attempt to exchange it for a victim session.",
        ))

    # 2. Reflected XSS + admin panel hint -> XSS to admin session theft
    rxss = _by_kind(findings, "reflected-xss", "xss-reflected")
    if not rxss:
        rxss = [f for f in _by_module(findings, "xss")
                if "reflected" in _sig(f)["kind"] or "reflected" in _text(f)]
    admin = [f for f in findings
             if any(t in _sig(f)["url"] for t in ("/wp-admin", "/admin", "/dashboard"))
             or "admin" in _sig(f)["kind"]]
    if not admin:
        admin = _any(findings, "admin panel", "administrator")
    if rxss and admin:
        matched = rxss + [f for f in admin if f not in rxss]
        chains.append(_chain(
            "XSS to admin session theft",
            "high",
            matched,
            "A reflected XSS fires on the target, and the target exposes an "
            "administrative interface. An admin who follows a crafted link "
            "executes attacker JavaScript in their session, which can read "
            "session cookies or tokens (where not HttpOnly) and send them to "
            "the attacker, handing over an admin session.",
            "Confirm the XSS fires with a harmless marker like an alert box "
            "with a unique string. Then verify whether session cookies are "
            "HttpOnly; if not, simulate cookie exfiltration to your own "
            "collaborator and check for an active admin panel to target.",
        ))

    # 3. SQLi + verbose errors -> error-based SQLi to full DB extraction
    sqli = _by_module(findings, "sqli")
    if not sqli:
        sqli = _any(findings, "sql injection", "sqli")
    errors = _by_kind(findings, "verbose-error", "stack-trace", "debug-mode")
    if not errors:
        errors = _any(findings, "verbose error", "stack trace", "sql error",
                      "database error", "debug mode", "detailed error")
    if sqli and errors:
        matched = sqli + [f for f in errors if f not in sqli]
        chains.append(_chain(
            "Error-based SQLi to full DB extraction",
            "high",
            matched,
            "A SQL injection point exists alongside verbose error output from "
            "the database layer. With error messages echoed back, the attacker "
            "does not need blind guessing: error-based payloads leak table "
            "names, column names and row contents directly in the responses, "
            "turning one injection point into full database extraction.",
            "Manually confirm error reflection with a single-quote probe and "
            "note the DBMS from the error text. Then use error-based payloads "
            "(e.g. extractvalue/floor(rand()) on MySQL) to enumerate schema, "
            "and document one extracted table as proof of impact.",
        ))

    # 4. CORS misconfig + API endpoints (jsintel) -> cross-origin API data theft
    cors = _by_module(findings, "cors")
    if not cors:
        cors = _any(findings, "cors", "access-control-allow-origin")
    apis = _by_module(findings, "jsintel")
    apis = [f for f in apis if "api" in _sig(f)["kind"] or "api" in _text(f)]
    if not apis:
        apis = _any(findings, "api endpoint", "api endpoints", "rest api")
    if cors and apis:
        matched = cors + [f for f in apis if f not in cors]
        chains.append(_chain(
            "Cross-origin API data theft",
            "medium",
            matched,
            "The target reflects arbitrary origins in CORS headers while "
            "exposing API endpoints. A victim visiting an attacker page has "
            "their browser make authenticated cross-origin requests to the "
            "API, and the permissive CORS policy lets the attacker page read "
            "the responses, leaking the victim's data.",
            "Send an Origin: https://evil.example request to the API endpoint "
            "with the victim's session cookies and check whether "
            "Access-Control-Allow-Origin echoes the origin with "
            "Access-Control-Allow-Credentials: true. Then confirm a read of "
            "one sensitive field.",
        ))

    # 5. Subdomain takeover + login/cookie scope -> session theft via takeover
    takeover = _by_kind(findings, "subdomain-takeover", "takeover")
    if not takeover:
        takeover = _any(findings, "subdomain takeover", "takeover")
    session_scope = [f for f in findings
                     if _sig(f)["kind"] in ("login-page", "cookie-scope")
                     or "/login" in _sig(f)["url"]]
    if not session_scope:
        session_scope = _any(findings, "login", "cookie", "session")
    if takeover and session_scope:
        matched = takeover + [f for f in session_scope if f not in takeover]
        chains.append(_chain(
            "Session theft via takeover",
            "high",
            matched,
            "A dangling subdomain can be claimed by an attacker, and the "
            "application's login or session cookies are scoped broadly enough "
            "to be relevant on it. Once the attacker controls the subdomain, "
            "they can host credential-harvesting pages under the victim's "
            "brand and set or read cookies valid for the parent domain, "
            "capturing live sessions.",
            "Claim (or, with permission, verify claimability of) the dangling "
            "subdomain on the indicated service. Then check the Set-Cookie "
            "Domain attributes on the main app: if cookies are scoped to the "
            "parent domain, demonstrate a session cookie being readable from "
            "the taken-over host.",
        ))

    # 6. Exposed .env/git + secrets -> credential compromise chain
    exposed = _by_module(findings, "wordlist", "secrets", "jssecrets")
    exposed = [f for f in exposed
               if any(t in _sig(f)["url"] for t in ("/.env", "/.git"))
               or _sig(f)["kind"] in ("exposed-file", "exposed-git")]
    if not exposed:
        exposed = _any(findings, ".env", ".git", "exposed", "git repository",
                       "directory listing")
    secrets = _by_module(findings, "secrets", "jssecrets")
    if not secrets:
        secrets = _any(findings, "secret", "api key", "password", "token",
                       "credential", "private key")
    if exposed and secrets:
        matched = exposed + [f for f in secrets if f not in exposed]
        chains.append(_chain(
            "Credential compromise chain",
            "high",
            matched,
            "Exposed source or environment files were found, and secrets were "
            "identified alongside them. Attackers routinely pull .env files "
            "and .git directories to recover database passwords, API keys and "
            "cloud tokens, then reuse them against the production services "
            "they belong to, often gaining full backend access.",
            "Fetch the exposed file (e.g. curl https://target/.env) and "
            "catalog every secret. Test each credential manually against its "
            "service (database, admin panel, cloud console) to confirm which "
            "are live, and document the highest-privilege access reached.",
        ))

    # 7. Info disclosure + auth endpoint -> credential stuffing setup
    info = _any(findings, "information disclosure", "info disclosure",
                "disclosure")
    auth = _any(findings, "auth", "login", "token endpoint", "oauth",
                "sign-in", "signin")
    if info and auth:
        matched = info + [f for f in auth if f not in info]
        chains.append(_chain(
            "Credential stuffing setup",
            "medium",
            matched,
            "An information disclosure finding sits next to an authentication "
            "endpoint. Leaked usernames, email addresses or password hints give "
            "an attacker a validated username list, which removes the "
            "hardest part of credential stuffing: knowing which accounts "
            "exist before spraying passwords.",
            "Manually harvest the disclosed identifiers (usernames or emails) "
            "and test whether the login endpoint distinguishes valid from "
            "invalid accounts (different error messages or timing). If it "
            "does, confirm rate limiting is absent before reporting.",
        ))

    # 8. Missing security headers (3+) on login page -> clickjacking
    missing_headers = [
        f for f in findings
        if "header" in _text(f) and ("missing" in _text(f) or "absent" in _text(f))
    ]
    login_headers = [f for f in missing_headers if "login" in _text(f)]
    if len(login_headers) >= 3:
        chains.append(_chain(
            "Clickjacking/UI redress on login",
            "low",
            login_headers,
            "The login page is missing several security headers, typically "
            "including frame protections. Without them, the login form can be "
            "framed by an attacker page and overlaid with invisible decoys, "
            "tricking the victim into clicking actions or typing credentials "
            "into attacker-controlled fields.",
            "Build a local proof-of-concept page that iframes the login URL. "
            "If it loads without being blocked by X-Frame-Options or "
            "frame-ancestors, overlay a transparent element on the login "
            "button to demonstrate the clickjacking primitive.",
        ))

    chains.sort(key=lambda c: (_SEVERITY_RANK.get(c["severity"], 4), c["name"]))
    return chains
