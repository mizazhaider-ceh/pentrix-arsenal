"""Event-driven recon pipeline for PENTRIX ARSENAL (v2).

Discovery is driven by a bounded work queue of events instead of a fixed
linear stage list::

    {"kind": "subdomain" | "host" | "port" | "service" | "tech" | "url",
     "value": ...,
     "depth": int}

The queue is seeded with the target domain. Events are processed by a
bounded ThreadPoolExecutor worker pool (stdlib only); all shared state is
guarded by a lock and per-host throttling hooks cap request pressure.

Workers:

* subdomain -> recon_mod (OSINT subdomain enumeration) + alive check
  -> host events for alive hosts, subdomain events for new names
* host      -> portscan_mod -> port events for open ports
* port      -> http/https services become url events and run the web
  modules from the per-module plan; other services only get an
  informational finding (no active probes beyond the portscan itself)
* url       -> tech_mod + web modules; jsintel results become new url
  events; tech hints become tech events
* tech      -> tech-specific modules (TECH_MODULE_MAP) + CVE linkage on
  versioned tech (tech_mod name + version -> cve_mod keyword search)
* service   -> informational bookkeeping

Module-extras contract (primary mechanism): each module's run() returns
either a dict such as::

    {"findings": [...], "subdomains": [...], "alive": [...],
     "open_ports": [{"port": 80, "service": "http"}], "urls": [...],
     "tech": [...]}

or a plain list of findings. Structured extras are consumed first; the
legacy _derive_* title-parsing helpers remain as a backward-compatible
fallback for modules that only return finding lists.

Intrusive classification: the single source of truth is each module's
INTRUSIVE flag. The pipeline reads the declaration at runtime instead of
maintaining its own list, so graphql/oauth/hostheader (which declare
INTRUSIVE = False, read-only probes) run without --intrusive, while
xss/sqli/jsintel (INTRUSIVE = True) still require it.

Per-module selection/ordering: ctx.config["pipeline"] may define
"web_modules" (ordered allowlist, accepts "headers" or "headers_mod"
spellings) and "skip_modules" (denylist). Default order is REGISTRY
order with non-intrusive modules first.

Bounds: depth tracks subdomain discovery generations only (so a full
subdomain -> host -> port -> url -> tech chain completes inside the
budget), capped at MAX_DEPTH; the queue is capped at MAX_EVENTS events;
a visited set prevents loops. The progress callback fires once per
processed event, plus live "finding" events as new findings land.

Passive mode (ctx.passive): guarantees zero active packets to the
target. Only recon_mod (OSINT sources), wayback historic data and
cve_mod (NVD lookups) run. No alive checks, no portscan, no tech
fingerprinting fetches, no intrusive modules.

Resume (ctx.resume): pipeline state is persisted to
workspace/<target>/pipeline_state.json every N events (default 10) or M
seconds (default 30), plus on interrupt and at completion. A resumed run
skips completed events. KeyboardInterrupt is caught, state is flushed,
and a partial summary is returned.

Per-host throttling: _HostThrottler enforces a minimum interval between
requests to the same host and a cap on concurrent workers per host.
The active throttler is exposed as ctx.throttle so modules can reuse the
same hooks.
"""

import collections
import importlib
import ipaddress
import json
import logging
import os
import re
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime, timezone

from arsenal import findings as findings_lib
from arsenal import http as http_lib

PASSIVE_MODULES = {"recon", "cve"}

MAX_DEPTH = 3
MAX_EVENTS = 200

# Legacy constants kept for backward compatibility (other code may import
# them). Gating now reads each module's INTRUSIVE flag instead.
SERVICE_MAP = {
    "http": ["headers_mod", "cors_mod", "redirect_mod", "jsintel_mod", "tech_mod"],
    "https": ["headers_mod", "cors_mod", "redirect_mod", "jsintel_mod", "tech_mod"],
}
INTRUSIVE_WEB_MODULES = [
    "xss_mod", "sqli_mod", "fuzz_mod", "ssti_mod", "paramminer_mod",
    "cachepoison_mod", "ppollution_mod",
]

# Service-aware auto-enum: normalized technology name -> module name.
# Keys are matched against normalized tech strings (lowercased, version
# suffix stripped). Only modules that exist in this tree are listed.
TECH_MODULE_MAP = {
    "graphql": "graphql_mod",
    "graph ql": "graphql_mod",
    "oauth": "oauth_mod",
    "oauth2": "oauth_mod",
    "openid": "oauth_mod",
    "openid connect": "oauth_mod",
    "oidc": "oauth_mod",
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


def _pipeline_cfg(ctx):
    cfg = getattr(ctx, "config", None) or {}
    if isinstance(cfg, dict):
        pcfg = cfg.get("pipeline")
        if isinstance(pcfg, dict):
            return pcfg
    return {}


_plugins_cache = None


def _load_plugins_cached():
    """Load user plugins once per process (cheap refresh per pipeline run)."""
    global _plugins_cache
    if _plugins_cache is None:
        try:
            from arsenal import plugins as plugins_mod
            _plugins_cache = plugins_mod.load_plugins()
        except Exception:
            _plugins_cache = {}
    return _plugins_cache


def _lazy_module(name, ctx):
    """Import arsenal.modules.<name>; fall back to user plugins by NAME.

    Warns and returns None when missing. Never raises.
    """
    try:
        return importlib.import_module("arsenal.modules." + name)
    except ImportError:
        pass
    except Exception as exc:
        _log(ctx).warning("module %s failed to import: %s", name, exc)
        return None
    # Plugin fallback: match by plugin NAME ("robots") or slug form.
    needle = str(name).lower().replace("_mod", "").replace("-", "_")
    for pname, pmod in _load_plugins_cached().items():
        slug = str(pname).lower().replace(" ", "_").replace("-", "_")
        if str(pname).lower() == str(name).lower() or slug == needle:
            return pmod
    _log(ctx).warning("module %s is not installed, skipping", name)
    return None


_intrusive_cache = {}


def _module_is_intrusive(modname, ctx):
    """Single source of truth for intrusiveness: the module's INTRUSIVE flag."""
    if modname in _intrusive_cache:
        return _intrusive_cache[modname]
    mod = _lazy_module(modname, ctx)
    intrusive = bool(getattr(mod, "INTRUSIVE", False)) if mod is not None else False
    _intrusive_cache[modname] = intrusive
    return intrusive


def _registry_url_modules():
    """Yield (lazy_name, module) for REGISTRY modules with TARGET_KIND url.

    Non-intrusive modules come first, then intrusive ones, each in
    REGISTRY order.
    """
    try:
        from arsenal.modules import REGISTRY
    except Exception:
        return
    safe, intrusive = [], []
    for key in REGISTRY:
        mod = REGISTRY[key]
        try:
            kind = str(getattr(mod, "TARGET_KIND", "")).lower()
        except Exception:
            continue
        if kind != "url":
            continue
        lazy_name = getattr(mod, "__name__", "").split(".")[-1] or (key + "_mod")
        (intrusive if bool(getattr(mod, "INTRUSIVE", False)) else safe).append(
            (lazy_name, mod))
    for entry in safe + intrusive:
        yield entry


def _web_module_plan(ctx):
    """Ordered [(lazy_name, module_or_None)] for url events.

    Honors pipeline.web_modules (ordered allowlist; accepts "headers" or
    "headers_mod") and pipeline.skip_modules (denylist). Modules are
    imported lazily; entries whose import fails are kept with module None
    so _lazy_module can warn at use time.
    """
    pcfg = _pipeline_cfg(ctx)
    allow = pcfg.get("web_modules") or getattr(ctx, "module_allowlist", None)
    deny = set(pcfg.get("skip_modules") or getattr(ctx, "module_denylist", None) or ())

    def denied(lazy_name, key):
        return lazy_name in deny or key in deny

    if allow:
        plan = []
        registry_names = {}
        try:
            from arsenal.modules import REGISTRY
            for key, mod in REGISTRY.items():
                lazy = getattr(mod, "__name__", "").split(".")[-1] or (key + "_mod")
                registry_names[key] = (lazy, mod)
                registry_names[lazy] = (lazy, mod)
        except Exception:
            pass
        for wanted in allow:
            wanted = str(wanted)
            if wanted in registry_names:
                lazy, mod = registry_names[wanted]
                if not denied(lazy, wanted):
                    plan.append((lazy, mod))
            elif not denied(wanted, wanted):
                plan.append((wanted, None))  # lazy import (or plugin) later
        # Plugins explicitly allowlisted by NAME.
        for pname, pmod in _load_plugins_cached().items():
            if pname in allow and not denied(pname, pname):
                plan.append((pname, pmod))
        return plan

    plan = []
    seen = set()
    for lazy_name, mod in _registry_url_modules():
        key = lazy_name[:-4] if lazy_name.endswith("_mod") else lazy_name
        if denied(lazy_name, key) or lazy_name in seen:
            continue
        seen.add(lazy_name)
        plan.append((lazy_name, mod))
    # User plugins with TARGET_KIND url join the plan (safe ones inline,
    # intrusive ones still gated on --intrusive by their INTRUSIVE flag).
    for pname, pmod in _load_plugins_cached().items():
        try:
            kind = str(getattr(pmod, "TARGET_KIND", "")).lower()
        except Exception:
            continue
        if kind == "url" and pname not in seen and pname not in deny:
            seen.add(pname)
            plan.append((pname, pmod))
    return plan


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


def _extra_list(extra, *keys):
    """First non-empty list found under any of the given extras keys."""
    if not isinstance(extra, dict):
        return []
    for key in keys:
        vals = extra.get(key)
        if isinstance(vals, list) and vals:
            return vals
    return []


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


class _HostThrottler:
    """Per-host request throttling hooks (stdlib, thread-safe).

    * min_interval: minimum seconds between the *start* of two gated
      sections for the same host.
    * max_per_host: maximum concurrent gated sections per host.
    """

    def __init__(self, min_interval=0.0, max_per_host=4):
        self.min_interval = float(min_interval or 0.0)
        self.max_per_host = max(1, int(max_per_host or 1))
        self._lock = threading.Lock()
        self._last = {}
        self._sems = {}

    @classmethod
    def from_ctx(cls, ctx):
        pcfg = _pipeline_cfg(ctx)
        return cls(
            min_interval=pcfg.get("min_interval", pcfg.get("throttle_seconds", 0.0)),
            max_per_host=pcfg.get("max_per_host", 4),
        )

    def _sem(self, host):
        with self._lock:
            sem = self._sems.get(host)
            if sem is None:
                sem = threading.Semaphore(self.max_per_host)
                self._sems[host] = sem
            return sem

    def wait_turn(self, host):
        """Block until this host is due for another request."""
        if self.min_interval <= 0 or not host:
            return
        with self._lock:
            last = self._last.get(host, 0.0)
            delay = self.min_interval - (time.monotonic() - last)
        if delay > 0:
            time.sleep(delay)
        with self._lock:
            self._last[host] = time.monotonic()

    def slot(self, host):
        """Context manager: per-host concurrency cap + min-interval pacing."""
        throttler = self

        class _Slot:
            def __enter__(self_inner):
                self_inner._sem = throttler._sem(host or "")
                self_inner._sem.acquire()
                throttler.wait_turn(host or "")
                return self_inner

            def __exit__(self_inner, *exc):
                self_inner._sem.release()
                return False

        return _Slot()


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
_VERSION_RE = re.compile(r"v?(\d+(?:\.\d+)+)")
_TECH_VERSION_STRIP_RE = re.compile(r"[\s\-_]+v?\d+(?:\.\d+)*(?:[.\-][a-z0-9]+)?\s*$",
                                    re.IGNORECASE)


def _derive_alive_hosts(module_result):
    """Backward-compat fallback: alive hosts from recon-style finding titles.

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
    """Backward-compat fallback: open ports from portscan-style titles.

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
    """Backward-compat fallback: technology names from tech-style titles."""
    hints = []
    for item in module_result["findings"]:
        title = str(item.get("title", ""))
        if title.startswith(_TECH_TITLE):
            name = title[len(_TECH_TITLE):].split("(")[0].strip().lower()
            if name and name not in hints:
                hints.append(name)
    return hints


def _normalize_tech(raw):
    """Lowercase a tech string and strip a trailing version suffix.

    "WordPress 6.4.1" -> "wordpress"; "jQuery-3.7.1" -> "jquery".
    """
    text = str(raw or "").strip().lower()
    text = _TECH_VERSION_STRIP_RE.sub("", text).strip()
    return text


def _split_tech_entry(entry):
    """Normalize a tech extras entry (str or {"name","version"}) to
    (normalized_name, version)."""
    version = ""
    if isinstance(entry, dict):
        name = entry.get("name") or entry.get("tech") or ""
        version = str(entry.get("version") or "")
    else:
        name = entry
    text = str(name or "").strip()
    if not version:
        match = _VERSION_RE.search(text)
        if match:
            version = match.group(1)
    return _normalize_tech(text), version


def run_pipeline(target, ctx, progress=None, event_mode=False):
    """Run the event-driven recon pipeline.

    progress is an optional callable(stage:str, detail:str, done:bool)
    invoked once per processed event, for live "finding" events, and at
    major phase transitions.

    Returns {"target", "hosts", "findings", "chains", "priority",
             "events_processed", "interrupted"} (plus "error" when the
    scope check refuses the target).
    """
    log = _log(ctx)
    target = _normalize_target(target)
    passive = bool(getattr(ctx, "passive", False))
    pcfg = _pipeline_cfg(ctx)
    max_workers = max(1, int(pcfg.get("max_workers", 4)))
    persist_every = max(1, int(pcfg.get("persist_every", 10)))
    persist_seconds = float(pcfg.get("persist_seconds", 30))
    cve_on_tech = bool(pcfg.get("cve_on_tech", True))

    throttle = _HostThrottler.from_ctx(ctx)
    ctx.throttle = throttle  # hook for modules to reuse

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

    # -- shared state (all mutations under state_lock) ------------------
    state_lock = threading.RLock()
    ws = ctx.workspace
    queue = collections.deque()
    visited = set()
    completed = []
    findings = []
    hosts = []
    urls_seen = set()
    host_urls = {}
    host_tech = {}
    live_findings = []  # drained by the main thread for progress events
    web_plan = _web_module_plan(ctx)

    def enqueue(event):
        if event.get("depth", 0) > MAX_DEPTH:
            return
        key = _event_key(event)
        with state_lock:
            if key in visited:
                return
            # Scope firewall: never pursue discovered assets outside the scope.
            if scope is not None and event.get("kind") in ("subdomain", "host", "url"):
                try:
                    if not scope.contains(event.get("value", "")):
                        log.info("scope: skipping out-of-scope discovery %s",
                                 event.get("value", ""))
                        return
                except Exception:
                    return
            visited.add(key)
            queue.append(event)

    def add_findings(items):
        with state_lock:
            for item in items or []:
                if isinstance(item, dict):
                    findings.append(item)
                    live_findings.append(item)

    def add_host(host):
        with state_lock:
            if host and host not in hosts:
                hosts.append(host)

    def add_url_for_host(url):
        url_host = urllib.parse.urlsplit(url).hostname or ""
        with state_lock:
            if url in urls_seen:
                return False
            urls_seen.add(url)
            if url_host:
                host_urls.setdefault(url_host, set()).add(url)
        return True

    def add_tech_for_host(url, tech_name):
        if not url or not tech_name:
            return
        url_host = urllib.parse.urlsplit(url).hostname or ""
        if url_host:
            with state_lock:
                host_tech.setdefault(url_host, set()).add(tech_name)

    def snapshot_state():
        with state_lock:
            return (list(completed), list(queue), list(hosts),
                    list(findings),
                    {h: set(u) for h, u in host_urls.items()},
                    {h: set(t) for h, t in host_tech.items()})

    last_persist = {"events": 0, "ts": time.monotonic()}

    def maybe_persist(force=False):
        with state_lock:
            done_count = len(completed)
        if not force:
            if done_count - last_persist["events"] < persist_every:
                if time.monotonic() - last_persist["ts"] < persist_seconds:
                    return
        comp, q, h, f, hu, ht = snapshot_state()
        _persist_state(ctx, target, comp, q, h, f, hu, ht)
        last_persist["events"] = done_count
        last_persist["ts"] = time.monotonic()

    if bool(getattr(ctx, "resume", False)):
        state = _load_state(ctx, target)
        if state:
            for key in state["completed"]:
                visited.add(key)
            completed = list(state["completed"])
            for event in state.get("queue", []):
                if isinstance(event, dict) and "kind" in event:
                    enqueue(event)
            for h in state.get("hosts", []) or []:
                if isinstance(h, str):
                    hosts.append(h)
            for f in state.get("findings", []) or []:
                if isinstance(f, dict):
                    findings.append(f)
            for h, urls in (state.get("host_urls") or {}).items():
                if isinstance(urls, list):
                    host_urls.setdefault(h, set()).update(urls)
                    urls_seen.update(urls)
            for h, techs in (state.get("host_tech") or {}).items():
                if isinstance(techs, list):
                    host_tech.setdefault(h, set()).update(techs)
            log.info("resumed pipeline for %s: %d completed, %d queued",
                     target, len(completed), len(queue))

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
                add_findings(res["findings"])
                subs = _extra_list(res["extra"], "subdomains")
                alive = _extra_list(res["extra"], "alive")
                if not subs and not alive:
                    # Backward compat: derive from finding titles.
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
                    add_findings(run_module(cve, domain, ctx)["findings"])
        for url in _wayback_urls(domain, ctx):
            enqueue({"kind": "url", "value": url, "depth": depth})
        if passive:
            return
        with throttle.slot(domain):
            if _alive_check(domain, ctx):
                enqueue({"kind": "host", "value": domain, "depth": depth})

    def handle_host(event):
        host = event["value"]
        depth = event["depth"]
        add_host(host)
        if passive:
            log.info("passive mode: skipping portscan for %s", host)
            return
        portscan = _lazy_module("portscan_mod", ctx)
        if portscan is None:
            return
        with throttle.slot(host):
            res = run_module(portscan, host, ctx)
        add_findings(res["findings"])
        ports = (_extra_list(res["extra"], "open_ports", "ports"))
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
            # Backward compat: derive from finding titles.
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
                with throttle.slot(host):
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
            add_findings([findings_lib.make_finding(
                "portscan", host, "info",
                "Non-HTTP service %s on port %s" % (label, port),
                note)])

    def _run_web_module(lazy_name, mod, url, url_host, depth):
        """Run one web module against a url event (worker thread)."""
        if mod is None:
            mod = _lazy_module(lazy_name, ctx)
            if mod is None:
                return
        intrusive = bool(getattr(mod, "INTRUSIVE", False))
        if intrusive and not ctx.allow_intrusive:
            log.info("skipping intrusive module %s (needs --intrusive)", lazy_name)
            return
        with throttle.slot(url_host):
            res = run_module(mod, url, ctx)
        add_findings(res["findings"])
        extra = res["extra"] if isinstance(res.get("extra"), dict) else {}
        for new_url in _extra_list(extra, "urls", "links"):
            full = urllib.parse.urljoin(url, str(new_url))
            enqueue({"kind": "url", "value": full, "depth": depth})
        for tech_entry in _extra_list(extra, "tech", "technologies"):
            name, version = _split_tech_entry(tech_entry)
            if not name:
                continue
            add_tech_for_host(url, name)
            value = {"tech": name, "url": url}
            if version:
                value["version"] = version
            enqueue({"kind": "tech", "value": value, "depth": depth})
        # Backward compat: derive tech hints from finding titles.
        for hint in _derive_tech_hints(res):
            name, _ver = _split_tech_entry(hint)
            if name:
                add_tech_for_host(url, name)
                enqueue({"kind": "tech",
                         "value": {"tech": name, "url": url},
                         "depth": depth})

    def handle_url(event):
        url = event["value"]
        depth = event["depth"]
        if not add_url_for_host(url):
            return
        url_host = urllib.parse.urlsplit(url).hostname or ""
        if passive:
            return
        for lazy_name, mod in web_plan:
            _run_web_module(lazy_name, mod, url, url_host, depth)

    def handle_tech(event):
        value = event["value"] or {}
        raw_tech = value.get("tech", "")
        tech, version = _split_tech_entry(
            {"name": raw_tech, "version": value.get("version", "")})
        url = value.get("url")
        add_tech_for_host(url, tech or str(raw_tech).lower())
        if passive or not tech:
            return
        # Service-aware auto-enum: detected tech -> relevant module.
        modname = TECH_MODULE_MAP.get(tech)
        if modname:
            mod = _lazy_module(modname, ctx)
            if mod is not None:
                intrusive = bool(getattr(mod, "INTRUSIVE", False))
                if intrusive and not ctx.allow_intrusive:
                    log.info("tech module %s needs --intrusive, skipping", modname)
                else:
                    with throttle.slot(urllib.parse.urlsplit(url or "").hostname or ""):
                        add_findings(
                            run_module(mod, url or target, ctx)["findings"])
        else:
            log.info("no dedicated module for tech '%s' (%s)", tech, url)
        # Tech-version -> CVE linkage: versioned tech gets an NVD lookup.
        if cve_on_tech and version and not passive:
            cve = _lazy_module("cve_mod", ctx)
            if cve is not None:
                keyword = "%s %s" % (tech, version)
                with throttle.slot("nvd.nist.gov"):
                    add_findings(run_module(cve, keyword, ctx)["findings"])

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

    def process_event(event):
        """Run one event's handler. Executed in a worker thread; never raises."""
        key = _event_key(event)
        try:
            handler = handlers.get(event.get("kind"))
            if handler is None:
                log.warning("unknown event kind %r, skipping", event.get("kind"))
            else:
                handler(event)
        except Exception as exc:
            log.warning("event %s failed: %s", key, exc)
        return key

    # -- concurrent event loop ------------------------------------------
    processed = 0
    interrupted = False
    in_flight = {}  # future -> event key
    try:
        with ThreadPoolExecutor(max_workers=max_workers,
                                thread_name_prefix="arsenal-pipe") as pool:
            while True:
                # Submit ready events up to the pool budget.
                with state_lock:
                    budget = max_workers * 2 - len(in_flight)
                    submitted = 0
                    while queue and submitted < budget and processed + len(in_flight) < MAX_EVENTS:
                        event = queue.popleft()
                        key = _event_key(event)
                        # (visited was marked at enqueue; re-check defensively)
                        in_flight[pool.submit(process_event, event)] = key
                        submitted += 1
                    queue_empty = not queue
                if in_flight:
                    done, _ = wait(list(in_flight), timeout=1.0,
                                   return_when=FIRST_COMPLETED)
                else:
                    done = ()
                for fut in done:
                    key = in_flight.pop(fut, None)
                    try:
                        fut.result()
                    except Exception as exc:  # process_event never raises; be safe
                        log.warning("worker error for %s: %s", key, exc)
                    with state_lock:
                        if key is not None and key not in completed:
                            completed.append(key)
                        processed += 1
                    emit("event", "%s" % (key,), False)
                    # Live finding stream: drain findings discovered by workers.
                    with state_lock:
                        fresh = list(live_findings)
                        del live_findings[:]
                    for item in fresh:
                        emit("finding", "%s [%s]" % (
                            item.get("title", "finding"),
                            item.get("severity", "info")), False)
                    maybe_persist()
                if queue_empty and not in_flight:
                    break
                if processed >= MAX_EVENTS and queue:
                    with state_lock:
                        left = len(queue)
                    log.warning("event budget (%d) exhausted with %d events left",
                                MAX_EVENTS, left)
                    break
    except KeyboardInterrupt:
        interrupted = True
        log.warning("pipeline interrupted; state saved, resume with --resume")

    maybe_persist(force=True)

    # -- post-processing ----------------------------------------------
    emit("verify", "verifying findings", False)
    with state_lock:
        all_findings = list(findings)
    verified = []
    for item in all_findings:
        updated = call_optional("arsenal.verify", "verify_finding", item, ctx)
        verified.append(updated if isinstance(updated, dict) else item)

    emit("triage", "triaging findings", False)
    triaged = call_optional("arsenal.triage", "triage_all", verified, ctx)
    if not isinstance(triaged, list):
        triaged = verified

    emit("priority", "ranking targets", False)
    host_infos = []
    with state_lock:
        host_url_snapshot = {h: sorted(u) for h, u in host_urls.items()}
        host_tech_snapshot = {h: sorted(t) for h, t in host_tech.items()}
        host_snapshot = list(hosts)
    for h in host_snapshot:
        urls = host_url_snapshot.get(h, ())
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
            "tech": host_tech_snapshot.get(h, ()),
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
        "hosts": host_snapshot,
        "findings": triaged,
        "chains": chains,
        "priority": priority,
        "events_processed": processed,
        "interrupted": interrupted,
    }
