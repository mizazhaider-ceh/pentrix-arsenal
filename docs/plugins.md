# Plugin SDK

PENTRIX ARSENAL plugins are plain Python files dropped into
`~/.arsenal/plugins/`. They become first-class modules: they appear in
`arsenal plugins`, join `arsenal scan --all`, can be picked with
`arsenal scan --module <NAME>`, and run inside the event-driven recon
pipeline for matching targets.

## The 4-attribute contract

Every plugin file must expose these four attributes:

| Attribute     | Type     | Meaning |
|---------------|----------|---------|
| `NAME`        | `str`    | Unique module name, used on the CLI (`scan --module NAME`). Lowercase, no spaces. |
| `DESCRIPTION` | `str`    | One-line help text shown by `arsenal plugins`. |
| `TARGET_KIND` | `str`    | One of `domain`, `url`, `ip`, `hash`, `path`, `keyword`, `token`. |
| `run`         | callable | `run(target, ctx) -> list[dict]`. The workhorse (see below). |

Two optional attributes are honored:

| Attribute   | Type  | Default | Meaning |
|-------------|-------|---------|---------|
| `INTRUSIVE` | `bool`| `False` | `True` when the plugin sends intrusive probes. The pipeline and `scan` gate intrusive plugins behind `--intrusive`; the module's own declaration is the single source of truth. |
| `VERSION`   | `str` | -       | Your plugin's version, shown by `arsenal plugins`. |

## The run() contract

```python
def run(target, ctx):
    """Probe the target; return a list of finding dicts. Never raise."""
```

Rules:

* **Never print.** Use `ctx.log` (a standard logger) for diagnostics.
* **Never raise.** Wrap per-target work in try/except and return the
  findings you have; the pipeline already wraps you defensively, but a
  clean plugin degrades gracefully on its own.
* **Respect the safety flags.** Check `ctx.passive` (do zero active
  probing when true) and `ctx.scope` (`ctx.scope.contains(host)` before
  touching a host). Read `ctx.allow_intrusive`; never invent your own
  safety policy.
* **Return findings, optionally with extras.** A plain list of finding
  dicts is fine. To feed recursive discovery, return a dict instead:

```python
return {
    "findings": [...],
    "subdomains": ["a.example.com"],   # -> new subdomain events
    "alive": ["host.example.com"],      # -> new host events
    "open_ports": [{"port": 80, "service": "http"}],
    "urls": ["/new/path"],             # resolved against the target URL
    "tech": ["WordPress 6.4.1"],       # or {"name": ..., "version": ...}
}
```

  Extras are the structured replacement for title parsing: the pipeline
  consumes them first and only falls back to parsing finding titles for
  modules that predate the contract.

* **Use the shared HTTP layer.** `from arsenal.http import fetch` and
  pass `ctx=ctx` so stealth sleeps, UA rotation and proxy settings
  apply to your traffic.
* **Build findings with `arsenal.findings.make_finding`.** Required
  keys: `module`, `target`, `severity` (critical/high/medium/low/info),
  `title`, `description`. Recommended: `evidence`, `confidence`
  (proven/strong/review), `cwe`, `remediation`, `url`, `param`, `kind`.

## Minimal example

```python
NAME = "securitytxt"
DESCRIPTION = "Check for a security.txt contact file"
TARGET_KIND = "url"
INTRUSIVE = False
VERSION = "1.0.0"

def run(target, ctx):
    from urllib.parse import urljoin, urlparse
    from arsenal.http import fetch
    from arsenal.findings import make_finding

    findings = []
    try:
        parts = urlparse(target)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return findings
        if ctx.scope is not None and not ctx.scope.contains(parts.hostname):
            return findings
        status, _h, body, _f = fetch(
            urljoin(target, "/.well-known/security.txt"), timeout=10, ctx=ctx)
        if status == 200 and body and b"contact:" in body.lower():
            findings.append(make_finding(
                module=NAME, target=target, severity="info",
                confidence="strong",
                title="security.txt contact file present",
                description="The site publishes a security.txt contact file.",
                evidence=body.decode("utf-8", errors="replace")[:500]))
    except Exception as exc:
        ctx.log.warning("securitytxt failed on %s: %s", target, exc)
    return findings
```

## Installing and validating

```bash
cp examples/plugins/securitytxt_plugin.py ~/.arsenal/plugins/
arsenal plugins            # lists it, with TARGET_KIND and path
arsenal scan https://target.com --module securitytxt
```

Validate a plugin file against the contract from Python:

```python
from arsenal import plugins
import importlib.util
spec = importlib.util.spec_from_file_location("p", "~/.arsenal/plugins/securitytxt_plugin.py")
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
print(plugins.validate_plugin(mod))  # [] means the contract holds
```

## Tips

* Keep plugins single-purpose; compose them with workflows instead of
  building mega-plugins.
* Prefer `TARGET_KIND = "url"` probes that need one request; anything
  heavier belongs in `INTRUSIVE = True`.
* Ship an example in `examples/plugins/` following the existing style
  (module docstring documents the contract; no prints; ctx.log only).
