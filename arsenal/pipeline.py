"""Event-driven recon pipeline for PENTRIX ARSENAL.

Discovery is driven by a bounded work queue of events instead of a fixed
linear stage list::

    {"kind": "subdomain" | "host" | "port" | "service" | "tech" | "url",
     "value": ...,
     "depth": int}

The queue is seeded with the target domain. Workers:

* subdomain -> recon_mod (OSINT subdomain enumeration) + alive check
  -> host events for alive hosts, subdomain events for new names
* host      -> portscan_mod -> port events for open ports
* port      -> http/https services become url events and run the web
  modules from SERVICE_MAP; other services only get an informational
  finding (no active probes beyond the portscan itself)
* url       -> tech_mod + web modules; jsintel results become new url
  events; tech hints become tech events
* tech      -> tech-specific modules (e.g. graphql hints -> graphql_mod)
* service   -> informational bookkeeping

Bounds: depth tracks subdomain discovery generations only (so a full
subdomain -> host -> port -> url -> tech chain completes inside the
budget), capped at MAX_DEPTH; the queue is capped at MAX_EVENTS events;
a visited set prevents loops. The progress callback fires once per
processed event.

Passive mode (ctx.passive): guarantees zero active packets to the
target. Only recon_mod (OSINT sources), wayback historic data and
cve_mod (NVD lookups) run. No alive checks, no portscan, no tech
fingerprinting fetches, no intrusive modules.

Resume (ctx.resume): after every processed event the pipeline persists
workspace/<target>/pipeline_state.json with {"completed": [...],
"queue": [...]}. A resumed run skips completed events. KeyboardInterrupt
is caught, state is flushed, and a partial summary is returned.

Module contract (other builders): each arsenal.modules.<name> module
exposes NAME, DESCRIPTION, TARGET_KIND and a run(target, ctx) callable.
run() returns either a dict such as::

    {"findings": [...], "subdomains": [...], "alive": [...],
     "open_ports": [{"port": 80, "service": "http"}], "urls": [...],
     "tech": [...]}

or a plain list of findings. Every module import and every module call
is wrapped: a missing or crashing module only logs a warning and the
pipeline continues.
"""

import collections
import importlib
import ipaddress
import json
import logging
import os
import re
import urllib.parse
from datetime import datetime, timezone

from arsenal import findings as findings_lib
from arsenal import http as http_lib

PASSIVE_MODULES = {"recon", "cve"}

MAX_DEPTH = 3
MAX_EVENTS = 200

SERVICE_MAP = {
    "http": ["headers_mod", "cors_mod", "redirect_mod", "jsintel_mod", "tech_mod"],
    "https": ["headers_mod", "cors_mod", "redirect_mod", "jsintel_mod", "tech_mod"],
}

INTRUSIVE_WEB_MODULES = [
    "xss_mod", "sqli_mod", "fuzz_mod", "ssti_mod", "paramminer_mod",
    "graphql_mod", "hostheader_mod", "cachepoison_mod", "ppollution_mod",
    "oauth_mod",
]

TECH_MODULE_MAP = {
    "graphql": "graphql_mod",
}

NON_HTTP_SERVICE_NOTE = {
    "21": "FTP on 21: consider manual anonymous-login and banner checks",
    "22": "SSH on 22: consider manual auth, banner and brute-force policy checks",
    "23": "Telnet on 23: consider manual banner and credential checks",
    "25": "SMTP on 25: consider manual mail relay and spoofing checks",
    "53": "DNS on 53: consider manual zone transfer and enumeration checks",
    "110": "POP3 on 110: consider manual auth and banner checks",
    "143": "IMAP on 143: consider manual auth and banner checks",
    "445": "SMB on 445: consider manual share enumeration checks",
    "3306": "MySQL on 3306: consider manual auth and version checks",
    "3389": "RDP on 3389: consider manual auth policy checks",
    "5432": "PostgreSQL on 5432: consider manual auth and version checks",
    "6379": "Redis on 6379: consider manual unauthenticated access checks",
    "27017": "MongoDB on 27017: consider manual unauthenticated access checks",
}

PORT_SERVICE_GUESS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 6379: "redis",
    8080: "http", 8443: "https", 27017: "mongodb",
}

_null_log = logging.getLogger("arsenal.pipeline.null")
_null_log.addHandler(logging.NullHandler())


def _log(ctx):
    log = getattr(ctx, "log", None)
    return log if log is not None else _null_log


def _lazy_module(name, ctx):
    """Import arsenal.modules.<name>; warn and return None when missing."""
    try:
        return importlib.import_module("arsenal.modules." + name)
    except ImportError:
        _log(ctx).warning("module %s is not installed, skipping", name)
        return None
    except Exception as exc:
        _log(ctx).warning("module %s failed to import: %s", name, exc)
        return None


def run_module(mod, target, ctx):
    """Run one module defensively.

    Returns {"findings": [validated findings], "extra": {module extras}}.
    Never raises for module errors.
    """
    log = _log(ctx)
    findings = []
    extra = {}
    run = getattr(mod, "run", None)
    if not callable(run):
        log.warning("module %s exposes no run() callable",
                    getattr(mod, "NAME", repr(mod)))
        return {"findings": findings, "extra": extra}
    try:
        result = run(target, ctx)
    except Exception as exc:
        log.warning("module %s failed on %r: %s",
                    getattr(mod, "NAME", "?"), target, exc)
        return {"findings": findings, "extra": extra}
    if isinstance(result, dict):
        raw = result.get("findings", [])
        extra = {k: v for k, v in result.items() if k != "findings"}
    elif isinstance(result, list):
        raw = result
    else:
        raw = []
    for item in raw:
        if isinstance(item, dict) and findings_lib.validate(item):
            findings.append(item)
        elif isinstance(item, dict):
            log.debug("dropping malformed finding from %s",
                      getattr(mod, "NAME", "?"))
    return {"findings": findings, "extra": extra}


def call_optional(modname, funcname, *args):
    """Import modname and call funcname(*args), tolerating absence.

    Drops a trailing ctx argument on TypeError and returns None when the
    module or function is unavailable or fails.
    """
    try:
        mod = importlib.import_module(modname)
    except ImportError:
        return None
    fn = getattr(mod, funcname, None)
    if not callable(fn):
        return None
    try:
        return fn(*args)
    except TypeError:
        if args:
            try:
                return fn(*args[:-1])
            except Exception:
                return None
        return None
    except Exception:
        return None


def _event_key(event):
    return "%s:%s" % (event.get("kind"),
                      json.dumps(event.get("value"), sort_keys=True, default=str))


def _looks_like_ip(value):
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def _normalize_target(target):
    text = str(target).strip()
    if "://" in text:
        host = urllib.parse.urlsplit(text).hostname
        if host:
            return host
    return text.split("/")[0]


def _state_path(ctx, target):
    return os.path.join(ctx.workspace.path(target), "pipeline_state.json")


def _persist_state(ctx, target, completed, queue, hosts=None, findings=None,
                   host_urls=None, host_tech=None):
    try:
        payload = {
            "target": target,
            "ts": datetime.now(timezone.utc).isoformat(),
            "completed": list(completed),
            "queue": [dict(e) for e in queue],
            "hosts": list(hosts or []),
            "findings": list(findings or []),
            "host_urls": {h: sorted(u) for h, u in (host_urls or {}).items()},
            "host_tech": {h: sorted(t) for h, t in (host_tech or {}).items()},
        }
        path = _state_path(ctx, target)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        os.replace(tmp, path)
    except Exception as exc:
        _log(ctx).warning("could not persist pipeline state: %s", exc)


def _load_state(ctx, target):
    try:
        with open(_state_path(ctx, target), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and isinstance(data.get("completed"), list):
            return data
    except (OSError, ValueError):
        pass
    return None


def _wayback_urls(domain, ctx, limit=50):
    """Historic URLs for a domain via the Wayback CDX API.

    Passive-safe: it only talks to web.archive.org, never the target.
    """
    api = ("https://web.archive.org/cdx/search/cdx?url=%s/*&output=json"
           "&fl=original&collapse=urlkey&limit=%d"
           % (urllib.parse.quote(domain), limit))
    status, data, _final = http_lib.fetch_json(api, timeout=20)
    if status != 200 or not isinstance(data, list):
        return []
    urls = []
    for row in data[1:]:
        if isinstance(row, list) and row and isinstance(row[0], str):
            urls.append(row[0])
    return urls


def _alive_check(host, ctx, timeout=8):
    """True when the host answers HTTP or HTTPS (active check)."""
    for scheme in ("https", "http"):
        status, _hdrs, _body, _final = http_lib.fetch(
            "%s://%s/" % (scheme, host), timeout=timeout, ctx=ctx)
        if status:
            return True
    return False


_ALIVE_TITLE = "Alive host:"
_PORT_TITLE_RE = re.compile(
    r"^(?:Risky open port|Open port):\s*(\d+)/tcp\s*\(([^)]*)\)",
    re.IGNORECASE)
_TECH_TITLE = "Technology:"


def _derive_alive_hosts(module_result):
    """Best-effort: alive hosts from recon-style finding titles.

    Used when recon_mod returns a plain finding list without the
    "alive" extra.
    """
    hosts = []
    for item in module_result["findings"]:
        title = str(item.get("title", ""))
        if title.startswith(_ALIVE_TITLE):
            host = item.get("target") or title[len(_ALIVE_TITLE):].strip()
            if host:
                hosts.append(str(host))
    return hosts


def _derive_open_ports(module_result, default_host=""):
    """Best-effort: open ports from portscan-style finding titles.

    Used when portscan_mod returns a plain finding list without the
    "open_ports" extra. Returns [{"host", "port", "service"}].
    """
    ports = []
    for item in module_result["findings"]:
        match = _PORT_TITLE_RE.match(str(item.get("title", "")))
        if not match:
            continue
        host = str(item.get("target", "") or "")
        if ":" in host:
            host = host.rsplit(":", 1)[0]
        ports.append({
            "host": host or default_host,
            "port": int(match.group(1)),
            "service": match.group(2).strip().lower(),
        })
    return ports


def _derive_tech_hints(module_result):
    """Best-effort: technology names from tech-style finding titles."""
    hints = []
    for item in module_result["findings"]:
        title = str(item.get("title", ""))
        if title.startswith(_TECH_TITLE):
            name = title[len(_TECH_TITLE):].split("(")[0].strip().lower()
            if name and name not in hints:
                hints.append(name)
    return hints


def run_pipeline(target, ctx, progress=None):
    """Run the event-driven recon pipeline.

    progress is an optional callable(stage:str, detail:str, done:bool)
    invoked once per processed event and at major phase transitions.

    Returns {"target", "hosts", "findings", "chains", "priority",
             "events_processed", "interrupted"} (plus "error" when the
    scope check refuses the target).
    """
    log = _log(ctx)
    target = _normalize_target(target)
    passive = bool(getattr(ctx, "passive", False))

    def emit(stage, detail, done=False):
        if progress is None:
            return
        try:
            progress(stage, detail, done)
        except Exception:
            pass

    # Scope firewall.
    scope = getattr(ctx, "scope", None)
    if scope is not None:
        try:
            allowed = scope.contains(target)
        except Exception as exc:
            log.warning("scope check failed (%s); treating as out of scope", exc)
            allowed = False
        if not allowed:
            log.error("target %s is outside the authorized scope; aborting", target)
            emit("scope", "out of scope", True)
            return {"target": target, "error": "out_of_scope", "hosts": [],
                    "findings": [], "chains": [], "priority": []}

    if passive:
        banner = "PASSIVE MODE: no packets sent to target"
        log.warning(banner)
        emit("passive", banner, False)

    ws = ctx.workspace
    queue = collections.deque()
    completed = []
    visited = set()
    findings = []
    hosts = []
    urls_seen = []
    host_urls = {}
    host_tech = {}
    def enqueue(event):
        if event.get("depth", 0) > MAX_DEPTH:
            return
        if _event_key(event) in visited:
            return
        # Scope firewall: never pursue discovered assets outside the scope.
        if scope is not None and event.get("kind") in ("subdomain", "host",
                                                       "url"):
            try:
                if not scope.contains(event.get("value", "")):
                    log.info("scope: skipping out-of-scope discovery %s",
                             event.get("value", ""))
                    return
            except Exception:
                return
        queue.append(event)

    if bool(getattr(ctx, "resume", False)):
        state = _load_state(ctx, target)
        if state:
            for key in state["completed"]:
                visited.add(key)
            completed = list(state["completed"])
            for event in state.get("queue", []):
                if isinstance(event, dict) and "kind" in event:
                    queue.append(event)
            restored_hosts = state.get("hosts", [])
            restored_findings = state.get("findings", [])
            if isinstance(restored_hosts, list):
                hosts_restored = [h for h in restored_hosts if isinstance(h, str)]
            else:
                hosts_restored = []
            if isinstance(restored_findings, list):
                findings_restored = [f for f in restored_findings
                                     if isinstance(f, dict)]
            else:
                findings_restored = []
            hosts.extend(hosts_restored)
            findings.extend(findings_restored)
            for h, urls in (state.get("host_urls") or {}).items():
                if isinstance(urls, list):
                    host_urls.setdefault(h, set()).update(urls)
            for h, techs in (state.get("host_tech") or {}).items():
                if isinstance(techs, list):
                    host_tech.setdefault(h, set()).update(techs)
            log.info("resumed pipeline for %s: %d completed, %d queued",
                     target, len(completed), len(queue))
        else:
            hosts_restored, findings_restored = [], []
    else:
        hosts_restored, findings_restored = [], []

    if not queue and not visited:
        seed_kind = "host" if _looks_like_ip(target) else "subdomain"
        enqueue({"kind": seed_kind, "value": target, "depth": 0})

    # -- workers ------------------------------------------------------
    def handle_subdomain(event):
        domain = event["value"]
        depth = event["depth"]
        if depth == 0:
            recon = _lazy_module("recon_mod", ctx)
            if recon is not None:
                res = run_module(recon, domain, ctx)
                findings.extend(res["findings"])
                subs = res["extra"].get("subdomains", []) or []
                alive = res["extra"].get("alive", []) or []
                if not subs and not alive:
                    alive = _derive_alive_hosts(res)
                for sub in subs:
                    enqueue({"kind": "subdomain", "value": str(sub),
                             "depth": depth + 1})
                for host in alive:
                    enqueue({"kind": "host", "value": str(host),
                             "depth": depth})
            if passive:
                cve = _lazy_module("cve_mod", ctx)
                if cve is not None:
                    findings.extend(run_module(cve, domain, ctx)["findings"])
        for url in _wayback_urls(domain, ctx):
            enqueue({"kind": "url", "value": url, "depth": depth})
        if passive:
            return
        if _alive_check(domain, ctx):
            enqueue({"kind": "host", "value": domain, "depth": depth})

    def handle_host(event):
        host = event["value"]
        depth = event["depth"]
        if host not in hosts:
            hosts.append(host)
        if passive:
            log.info("passive mode: skipping portscan for %s", host)
            return
        portscan = _lazy_module("portscan_mod", ctx)
        if portscan is None:
            return
        res = run_module(portscan, host, ctx)
        findings.extend(res["findings"])
        ports = res["extra"].get("open_ports", []) or res["extra"].get("ports", []) or []
        normalized = []
        for item in ports:
            if isinstance(item, dict):
                port, service = item.get("port"), item.get("service") or ""
            else:
                port, service = item, ""
            try:
                port = int(port)
            except (TypeError, ValueError):
                continue
            service = str(service).lower() or PORT_SERVICE_GUESS.get(port, "")
            normalized.append({"host": host, "port": port, "service": service})
        if not normalized:
            normalized = _derive_open_ports(res, default_host=host)
        for entry in normalized:
            enqueue({"kind": "port",
                     "value": {"host": entry["host"], "port": entry["port"],
                               "service": entry["service"]},
                     "depth": depth})

    def _looks_like_http(host, port):
        """Probe whether a port speaks HTTP (for ambiguous service hints)."""
        if port in (80, 8080, 8000, 8888):
            return "http"
        if port in (443, 8443):
            return "https"
        try:
            from arsenal.http import fetch as _fetch
            status, _h, _b, _f = _fetch("http://%s:%s/" % (host, port),
                                        timeout=5)
            if status != 0:
                return "http"
        except Exception:
            pass
        return None

    def handle_port(event):
        value = event["value"] or {}
        host = value.get("host")
        port = value.get("port")
        service = str(value.get("service")
                      or PORT_SERVICE_GUESS.get(port, "")).lower()
        depth = event["depth"]
        web_service = None
        if service in ("http", "https"):
            web_service = service
        elif "http" in service:
            web_service = "https" if "https" in service else "http"
        elif not service or service == "unknown":
            # Ambiguous: actively probe; a HTTP response means a web target.
            if not passive:
                web_service = _looks_like_http(host, port)
        if web_service:
            netloc = host if port in (80, 443) else "%s:%s" % (host, port)
            enqueue({"kind": "url", "value": "%s://%s/" % (web_service, netloc),
                     "depth": depth})
            enqueue({"kind": "service",
                     "value": {"host": host, "port": port,
                               "service": web_service},
                     "depth": depth})
        else:
            label = service or "unknown"
            note = NON_HTTP_SERVICE_NOTE.get(
                str(port),
                "%s on port %s: consider manual checks" % (label.upper(), port))
            findings.append(findings_lib.make_finding(
                "portscan", host, "info",
                "Non-HTTP service %s on port %s" % (label, port),
                note))

    def handle_url(event):
        url = event["value"]
        depth = event["depth"]
        if url in urls_seen:
            return
        urls_seen.append(url)
        url_host = urllib.parse.urlsplit(url).hostname or ""
        if url_host:
            host_urls.setdefault(url_host, set()).add(url)
        if passive:
            return
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        url_findings = []
        for modname in SERVICE_MAP.get(scheme, SERVICE_MAP["http"]):
            mod = _lazy_module(modname, ctx)
            if mod is None:
                continue
            res = run_module(mod, url, ctx)
            findings.extend(res["findings"])
            url_findings.extend(res["findings"])
            extra = res["extra"]
            for new_url in extra.get("urls", []) or []:
                full = urllib.parse.urljoin(url, str(new_url))
                enqueue({"kind": "url", "value": full, "depth": depth})
            techs = extra.get("tech", []) or extra.get("technologies", []) or []
            for tech in techs:
                enqueue({"kind": "tech",
                         "value": {"tech": str(tech).lower(), "url": url},
                         "depth": depth})
        for hint in _derive_tech_hints({"findings": url_findings}):
            if url_host:
                host_tech.setdefault(url_host, set()).add(hint)
            enqueue({"kind": "tech",
                     "value": {"tech": hint, "url": url},
                     "depth": depth})
        if ctx.allow_intrusive:
            for modname in INTRUSIVE_WEB_MODULES:
                mod = _lazy_module(modname, ctx)
                if mod is None:
                    continue
                findings.extend(run_module(mod, url, ctx)["findings"])

    def handle_tech(event):
        value = event["value"] or {}
        tech = str(value.get("tech", "")).lower()
        url = value.get("url")
        if url and tech:
            url_host = urllib.parse.urlsplit(url).hostname or ""
            if url_host:
                host_tech.setdefault(url_host, set()).add(tech)
        if passive:
            return
        modname = TECH_MODULE_MAP.get(tech)
        if not modname:
            log.info("no dedicated module for tech '%s' (%s)", tech, url)
            return
        if not ctx.allow_intrusive:
            log.info("tech module %s needs --intrusive, skipping", modname)
            return
        mod = _lazy_module(modname, ctx)
        if mod is not None:
            findings.extend(run_module(mod, url or target, ctx)["findings"])

    def handle_service(event):
        value = event["value"] or {}
        log.info("service %s on %s:%s",
                 value.get("service"), value.get("host"), value.get("port"))

    handlers = {
        "subdomain": handle_subdomain,
        "host": handle_host,
        "port": handle_port,
        "service": handle_service,
        "tech": handle_tech,
        "url": handle_url,
    }

    # -- event loop ---------------------------------------------------
    processed = 0
    interrupted = False
    in_flight = None
    try:
        while queue and processed < MAX_EVENTS:
            event = queue.popleft()
            in_flight = event
            key = _event_key(event)
            if key in visited:
                in_flight = None
                continue
            emit("event", "%s %s" % (event.get("kind"), event.get("value")), False)
            handler = handlers.get(event.get("kind"))
            if handler is None:
                log.warning("unknown event kind %r, skipping", event.get("kind"))
            else:
                try:
                    handler(event)
                except Exception as exc:
                    log.warning("event %s failed: %s", key, exc)
            visited.add(key)
            completed.append(key)
            processed += 1
            in_flight = None
            _persist_state(ctx, target, completed, queue, hosts, findings, host_urls, host_tech)
    except KeyboardInterrupt:
        interrupted = True
        if in_flight is not None:
            queue.appendleft(in_flight)
            in_flight = None
        log.warning("pipeline interrupted; state saved, resume with --resume")
        _persist_state(ctx, target, completed, queue, hosts, findings, host_urls, host_tech)

    if processed >= MAX_EVENTS and queue:
        log.warning("event budget (%d) exhausted with %d events left",
                    MAX_EVENTS, len(queue))

    # -- post-processing ----------------------------------------------
    emit("verify", "verifying findings", False)
    verified = []
    for item in findings:
        updated = call_optional("arsenal.verify", "verify_finding", item, ctx)
        verified.append(updated if isinstance(updated, dict) else item)

    emit("triage", "triaging findings", False)
    triaged = call_optional("arsenal.triage", "triage_all", verified, ctx)
    if not isinstance(triaged, list):
        triaged = verified

    emit("priority", "ranking targets", False)
    host_infos = []
    for h in hosts:
        urls = sorted(host_urls.get(h, ()))
        alive_url = ""
        for u in urls:
            if u.startswith("https://"):
                alive_url = u
                break
        if not alive_url and urls:
            alive_url = urls[0]
        host_infos.append({
            "host": h,
            "alive_url": alive_url,
            "tech": sorted(host_tech.get(h, ())),
        })
    priority = call_optional("arsenal.priority", "rank_targets", host_infos)
    if not isinstance(priority, list):
        priority = []

    emit("chains", "suggesting attack chains", False)
    chains = call_optional("arsenal.chains", "suggest_chains", triaged, ctx)
    if not isinstance(chains, list):
        chains = []

    emit("save", "saving to workspace", False)
    try:
        ws.save_scan(target, "pipeline", triaged)
        ws.append_findings(target, triaged)
    except Exception as exc:
        log.warning("workspace save failed: %s", exc)

    emit("pipeline", "done", True)
    return {
        "target": target,
        "hosts": hosts,
        "findings": triaged,
        "chains": chains,
        "priority": priority,
        "events_processed": processed,
        "interrupted": interrupted,
    }
