"""SMART MONITOR for PENTRIX ARSENAL.

run(target, ctx) re-scans a target and compares against the stored
baseline (workspace baseline.json). The first run creates the baseline
and emits no alerts. Every run saves a plain diff to diffs/<ts>.json and
appends alert findings to the target's findings.json.

SMART ALERTS (meaning, not just diff):
  - new subdomain serving a login page            -> high
  - newly opened port on an existing host         -> medium
  - tech stack change on a login/admin host       -> medium
  - JS file changed: re-run secret scan; new secrets -> medium
  - /.git/HEAD or /.env newly exposed            -> high
  - visual change beyond threshold                -> low

Where arsenal.modules.* scanners exist they are used; otherwise built-in
lightweight collectors (urllib fetch, threaded TCP connect scan, header
fingerprinting, visual thumbnails) keep the monitor self-sufficient.
Never crashes on missing data.
"""

import concurrent.futures
import hashlib
import json
import os
import re
import socket
import urllib.request
import urllib.error
from datetime import datetime

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]

_UA = {"User-Agent": "PentrixArsenal/1.0 (monitor)"}

_JS_SECRET_PATTERNS = [
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("generic_secret", re.compile(r"(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['\"][^'\"\s]{8,}['\"]")),
    ("bearer", re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]{20,}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----")),
]


def _ws_dir(ctx, target) -> str:
    ws = getattr(ctx, "workspace", None)
    if ws is not None and hasattr(ws, "path"):
        try:
            return ws.path(target)
        except Exception:
            pass
    return os.path.expanduser(os.path.join("~", ".arsenal", "workspace", str(target)))


def _scope_hosts(ctx, target) -> list:
    scope = getattr(ctx, "scope", None)
    hosts = []
    if isinstance(scope, dict):
        hosts = list(scope.get("hosts", []) or scope.get("in_scope", []))
    elif isinstance(scope, (list, tuple)):
        hosts = list(scope)
    if not hosts:
        hosts = [target]
    cleaned = []
    for h in hosts:
        h = str(h).strip()
        h = re.sub(r"^https?://", "", h).split("/")[0]
        if h and h not in cleaned:
            cleaned.append(h)
    return cleaned or [str(target)]


# --------------------------------------------------------------------------
# Collectors
# --------------------------------------------------------------------------

def _fetch(url: str, timeout: int = 10):
    """Return (status, headers dict, text) or (None, {}, "")."""
    try:
        req = urllib.request.Request(url, headers=_UA)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(1_500_000)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            status = resp.status
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(200_000)
        except Exception:
            raw = b""
        headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
        status = exc.code
    except Exception:
        return None, {}, ""
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        text = ""
    return status, headers, text


def _is_login_page(html_text: str) -> bool:
    low = (html_text or "").lower()
    return 'type="password"' in low or "type='password'" in low


def _try_module(name: str, target, ctx):
    """Best-effort call into arsenal.modules.<name>; return None on failure."""
    try:
        mod = __import__("arsenal.modules.%s" % name, fromlist=["*"])
    except Exception:
        return None
    for attr in ("run", "scan", "enumerate", "collect"):
        fn = getattr(mod, attr, None)
        if callable(fn):
            for args in ((target, ctx), (target,), (ctx, target)):
                try:
                    return fn(*args)
                except TypeError:
                    continue
                except Exception:
                    return None
    return None


def _scan_ports(host: str, ports=None, timeout: float = 1.0) -> list:
    ports = ports or COMMON_PORTS
    hostname = host.split(":")[0]

    def probe(port):
        try:
            with socket.create_connection((hostname, port), timeout=timeout):
                return port
        except Exception:
            return None

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        for result in pool.map(probe, ports):
            if result is not None:
                open_ports.append(result)
    return sorted(open_ports)


def _quick_tech(base_url: str) -> dict:
    status, headers, text = _fetch(base_url, timeout=10)
    tech = {}
    if status is None:
        return tech
    for header in ("server", "x-powered-by", "x-aspnet-version"):
        if headers.get(header):
            tech[header] = headers[header]
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', text, re.I)
    if m:
        tech["generator"] = m.group(1)
    return tech


def _js_urls(html_text: str, base_url: str) -> list:
    urls = []
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html_text or "", re.I):
        src = m.group(1)
        if src.startswith("http"):
            urls.append(src)
        elif src.startswith("//"):
            urls.append("https:" + src)
        elif src.startswith("/") and src.endswith(".js"):
            urls.append(base_url.rstrip("/") + src)
        elif src.endswith(".js"):
            urls.append(base_url.rstrip("/") + "/" + src)
    return sorted(set(urls))


def _scan_js_secrets(js_text: str) -> list:
    found = []
    for name, pattern in _JS_SECRET_PATTERNS:
        for m in pattern.finditer(js_text or ""):
            found.append("%s:%s" % (name, m.group(0)[:60]))
    return sorted(set(found))


def _exposed(base_url: str):
    """Check /.git/HEAD and /.env exposure. Returns dict."""
    out = {"git": False, "env": False}
    status, _h, text = _fetch(base_url.rstrip("/") + "/.git/HEAD", timeout=8)
    if status == 200 and text.strip().startswith("ref:"):
        out["git"] = True
    status, _h, text = _fetch(base_url.rstrip("/") + "/.env", timeout=8)
    if status == 200 and re.search(r"(?m)^[A-Z_]{2,}\s*=", text):
        out["env"] = True
    return out


def _collect_state(target, ctx) -> dict:
    """Run all collectors; never raises."""
    state = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "subdomains": [],
        "ports": {},
        "tech": {},
        "js_hashes": {},
        "js_secrets": {},
        "exposed": {},
        "visual": {},
        "login_hosts": [],
    }
    hosts = _scope_hosts(ctx, target)

    # Subdomains: prefer recon module, else scope hosts
    subs = _try_module("recon", target, ctx)
    if isinstance(subs, dict):
        subs = subs.get("subdomains") or subs.get("hosts") or []
    if isinstance(subs, list) and subs:
        norm = []
        for s in subs:
            s = s.get("host") if isinstance(s, dict) else s
            if s:
                norm.append(str(s))
        state["subdomains"] = sorted(set(norm))
    else:
        state["subdomains"] = sorted(set(hosts))

    for host in hosts:
        # Ports: prefer module, else built-in connect scan
        mod_ports = _try_module("portscan", host, ctx)
        if isinstance(mod_ports, dict):
            plist = mod_ports.get(host) or mod_ports.get("ports") or []
        elif isinstance(mod_ports, list):
            plist = mod_ports
        else:
            plist = _scan_ports(host)
        try:
            state["ports"][host] = sorted({int(p.get("port", p)) if isinstance(p, dict) else int(p)
                                           for p in (plist or [])})
        except Exception:
            state["ports"][host] = []

        # Web collectors against http and https
        for scheme in ("https", "http"):
            base = "%s://%s" % (scheme, host)
            status, _h, text = _fetch(base, timeout=8)
            if status is None:
                continue
            tech = _quick_tech(base)
            mod_tech = _try_module("tech", host, ctx)
            if isinstance(mod_tech, dict):
                tech.update({k: str(v) for k, v in mod_tech.items()})
            state["tech"].setdefault(host, {}).update(tech)
            if _is_login_page(text) and host not in state["login_hosts"]:
                state["login_hosts"].append(host)
            for js_url in _js_urls(text, base):
                _st, _hh, js_text = _fetch(js_url, timeout=10)
                if _st is None:
                    continue
                digest = hashlib.sha256(js_text.encode("utf-8", errors="replace")).hexdigest()
                state["js_hashes"][js_url] = digest
                state["js_secrets"][js_url] = _scan_js_secrets(js_text)
            exp = _exposed(base)
            prev = state["exposed"].get(host, {"git": False, "env": False})
            state["exposed"][host] = {"git": prev["git"] or exp["git"],
                                      "env": prev["env"] or exp["env"]}
            # Visual thumbnail
            try:
                from arsenal import visual as _visual
                thumb_dir = os.path.join(_ws_dir(ctx, target), "monitor", "thumbs")
                os.makedirs(thumb_dir, exist_ok=True)
                safe = re.sub(r"[^A-Za-z0-9_.-]", "_", host)
                thumb = os.path.join(thumb_dir, "%s.png" % safe)
                _visual.capture(base, thumb, ctx)
                state["visual"][host] = {"hash": _visual.dhash(thumb), "thumb": thumb}
            except Exception:
                pass
            break  # one working scheme per host is enough
    return state


# --------------------------------------------------------------------------
# Smart evaluation
# --------------------------------------------------------------------------

def _finding(severity, title, description, evidence="", target="",
             confidence="high", cwe="", remediation=""):
    return {
        "module": "monitor",
        "target": target,
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "description": description,
        "evidence": evidence,
        "cwe": cwe,
        "remediation": remediation,
        "verdict": "unreviewed",
    }


def _hamming(a, b) -> int:
    try:
        return bin(int(a) ^ int(b)).count("1")
    except Exception:
        return 999


def evaluate(baseline: dict, current: dict, fetch=None) -> tuple:
    """Compare baseline vs current state. Returns (diff, findings).

    *fetch* is an injectable (status, headers, text) fetcher used by tests;
    defaults to the real HTTP fetcher.
    """
    fetch = fetch or _fetch
    diff = {
        "ts": current.get("ts"),
        "added_subdomains": [],
        "removed_subdomains": [],
        "port_changes": {},
        "tech_changes": [],
        "js_changed": [],
        "new_secrets": [],
        "newly_exposed": {},
        "visual_changes": [],
    }
    findings = []
    target = ""

    base_subs = set(baseline.get("subdomains", []) or [])
    cur_subs = set(current.get("subdomains", []) or [])
    added = sorted(cur_subs - base_subs)
    removed = sorted(base_subs - cur_subs)
    diff["added_subdomains"] = added
    diff["removed_subdomains"] = removed

    # 1. New subdomain serving a login page -> high
    for sub in added:
        login_found = False
        for scheme in ("https", "http"):
            _st, _h, text = fetch("%s://%s" % (scheme, sub))
            if _st is None:
                continue
            if _is_login_page(text):
                login_found = True
            break
        if login_found:
            findings.append(_finding(
                "high", "New subdomain serving a login page: %s" % sub,
                "Subdomain %s appeared since the baseline and serves a login "
                "form. New authentication surfaces are prime targets for "
                "credential attacks and auth bypass testing." % sub,
                evidence="type=password input detected on %s" % sub,
                target=sub, cwe="CWE-200",
                remediation="Verify the host is in scope, enforce MFA and "
                            "rate limiting, and review the login flow for "
                            "enumeration and brute-force weaknesses."))

    # 2. Newly opened ports on existing hosts -> medium
    for host, cur_ports in (current.get("ports", {}) or {}).items():
        base_ports = set(baseline.get("ports", {}).get(host, []) or [])
        new_ports = sorted(set(cur_ports or []) - base_ports)
        if new_ports:
            diff["port_changes"][host] = {"added": new_ports}
            findings.append(_finding(
                "medium", "Newly opened port(s) on %s: %s" % (host, ", ".join(map(str, new_ports))),
                "Ports %s on %s were closed or filtered at baseline and are "
                "now open, expanding the attack surface." % (
                    ", ".join(map(str, new_ports)), host),
                evidence="baseline=%s current=%s" % (sorted(base_ports), sorted(cur_ports or [])),
                target=host,
                remediation="Confirm the newly exposed services are intentional, "
                            "restrict them with firewall rules, and keep them patched."))

    # 3. Tech stack change on login/admin host -> medium
    login_hosts = set(current.get("login_hosts", []) or baseline.get("login_hosts", []))
    for host, cur_tech in (current.get("tech", {}) or {}).items():
        base_tech = baseline.get("tech", {}).get(host, {}) or {}
        if cur_tech != base_tech and host in login_hosts:
            diff["tech_changes"].append(host)
            findings.append(_finding(
                "medium", "Technology stack changed on login host %s" % host,
                "The fingerprint of %s changed since baseline "
                "(%s -> %s). Stack changes on authentication hosts can "
                "introduce new CVEs or misconfigurations." % (
                    host, base_tech, cur_tech),
                target=host,
                remediation="Identify what changed (upgrade, migration, new "
                            "component) and re-run vulnerability checks against "
                            "the new stack."))

    # 4. JS changed -> re-run secret scan; new secrets -> medium
    for url, cur_hash in (current.get("js_hashes", {}) or {}).items():
        base_hash = (baseline.get("js_hashes", {}) or {}).get(url)
        if base_hash and base_hash != cur_hash:
            diff["js_changed"].append(url)
            _st, _h, js_text = fetch(url)
            new_secrets = []
            if _st is not None:
                cur_secrets = set(_scan_js_secrets(js_text or ""))
                base_secrets = set((baseline.get("js_secrets", {}) or {}).get(url, []) or [])
                new_secrets = sorted(cur_secrets - base_secrets)
            if new_secrets:
                diff["new_secrets"].append({"url": url, "secrets": new_secrets})
                findings.append(_finding(
                    "medium", "New secrets in changed JS bundle: %s" % url,
                    "JavaScript file %s changed since baseline and now "
                    "contains %d new secret-like string(s)." % (url, len(new_secrets)),
                    evidence="\n".join(new_secrets),
                    target=url, cwe="CWE-200",
                    remediation="Remove secrets from client-side code, rotate "
                                "any exposed credentials, and move them server-side."))

    # 5. /.git/HEAD or /.env newly exposed -> high
    for host, cur_exp in (current.get("exposed", {}) or {}).items():
        base_exp = (baseline.get("exposed", {}) or {}).get(host, {}) or {}
        newly = [k for k in ("git", "env") if cur_exp.get(k) and not base_exp.get(k)]
        if newly:
            diff["newly_exposed"][host] = newly
            which = " and ".join("/.%s%s" % (k, "/HEAD" if k == "git" else "") for k in newly)
            findings.append(_finding(
                "high", "Source/config exposure on %s: %s newly reachable" % (host, which),
                "%s on %s was not exposed at baseline and is now reachable, "
                "potentially leaking source code or credentials." % (which, host),
                evidence="%s exposed" % which, target=host, cwe="CWE-200",
                remediation="Block dotfile and .env access at the web server, "
                            "verify nothing sensitive was committed, and rotate "
                            "any exposed credentials."))

    # 6. Visual change beyond threshold -> low
    for host, cur_vis in (current.get("visual", {}) or {}).items():
        base_vis = (baseline.get("visual", {}) or {}).get(host, {}) or {}
        if base_vis.get("hash") is not None and cur_vis.get("hash") is not None:
            if _hamming(base_vis["hash"], cur_vis["hash"]) > 10:
                diff["visual_changes"].append(host)
                findings.append(_finding(
                    "low", "Visual change detected on %s" % host,
                    "The rendered structure of %s changed beyond the visual "
                    "threshold since baseline. Often benign (redesign), but "
                    "worth a glance for defacement or injected content." % host,
                    target=host, confidence="medium",
                    remediation="Review the new page visually and confirm the "
                                "change was expected."))

    return diff, findings


# --------------------------------------------------------------------------
# Persistence and CLI
# --------------------------------------------------------------------------

def _append_findings(ctx, target, findings) -> None:
    if not findings:
        return
    path = os.path.join(_ws_dir(ctx, target), "findings.json")
    existing = []
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                existing = json.load(fh) or []
        except Exception:
            existing = []
    existing.extend(findings)
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(existing, fh, indent=2, ensure_ascii=False)
    try:
        from arsenal.crm import ensure_ids
        ensure_ids(target, ctx)
    except Exception:
        pass


def run(target, ctx) -> dict:
    """Run the smart monitor for *target*. Returns a result dict."""
    ws_dir = _ws_dir(ctx, target)
    os.makedirs(ws_dir, exist_ok=True)
    baseline_path = os.path.join(ws_dir, "baseline.json")

    current = _collect_state(target, ctx)

    if not os.path.exists(baseline_path):
        with open(baseline_path, "w", encoding="utf-8") as fh:
            json.dump(current, fh, indent=2, ensure_ascii=False)
        return {"target": target, "baseline_created": True,
                "findings": [], "diff_path": None}

    try:
        with open(baseline_path, "r", encoding="utf-8") as fh:
            baseline = json.load(fh) or {}
    except Exception:
        baseline = {}

    diff, findings = evaluate(baseline, current)

    diffs_dir = os.path.join(ws_dir, "diffs")
    os.makedirs(diffs_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    diff_path = os.path.join(diffs_dir, "%s.json" % ts)
    with open(diff_path, "w", encoding="utf-8") as fh:
        json.dump(diff, fh, indent=2, ensure_ascii=False)

    _append_findings(ctx, target, findings)
    return {"target": target, "baseline_created": False,
            "findings": findings, "diff_path": diff_path,
            "alerts": len(findings)}


def add_parsers(sub):
    """Register `arsenal monitor <target>`."""
    p = sub.add_parser("monitor", help="Smart change monitor with baseline alerts")
    p.add_argument("target", help="Target name")
    p.set_defaults(func=dispatch)
    return sub


def dispatch(args, ctx):
    """CLI dispatch for `arsenal monitor`."""
    result = run(args.target, ctx)
    if result.get("baseline_created"):
        print("Baseline created for %s; no alerts on first run." % args.target)
        return 0
    print("Monitor run for %s: %d alert(s); diff saved to %s" % (
        args.target, result.get("alerts", 0), result.get("diff_path")))
    for f in result.get("findings", []):
        print("  [%s] %s" % (str(f.get("severity", "")).upper(), f.get("title")))
    return 0
