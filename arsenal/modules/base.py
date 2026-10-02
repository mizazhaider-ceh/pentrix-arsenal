"""Shared base for PENTRIX ARSENAL scan modules.

Every module used to carry its own copy of the same ~60-line helper block
(timeout lookup, logging, URL helpers, scope check, fetch wrapper, finding
factory). BaseModule holds that logic once; each module binds the pieces
it needs at the top of the file:

    from arsenal.modules.base import BaseModule

    _mod = BaseModule(NAME, TIMEOUT)
    _timeout = _mod.timeout
    _log = _mod.log
    _is_http_url = _mod.is_http_url
    _host_of = _mod.host_of
    _in_scope = _mod.in_scope
    _get = _mod.get
    _get_no_redirect = _mod.get_no_redirect
    _finding = _mod.finding

Bound methods are drop-in replacements for the old module-level helpers.
The fetch wrappers always pass ctx through to arsenal.http.fetch(), so
stealth sleeps, UA rotation and proxy settings actually apply to module
traffic. The guard() helper collapses the usual intrusive / safe_mode /
URL-shape / scope pre-checks into one call.
"""

import urllib.parse

from arsenal import http as http_mod
from arsenal.findings import make_finding


class BaseModule:
    """Shared helpers for one scan module, bound to its NAME and TIMEOUT."""

    def __init__(self, name, timeout=10):
        self.name = name
        self.default_timeout = timeout

    # -- config / logging ---------------------------------------------

    def timeout(self, ctx):
        """Request timeout: ctx config wins, else the module default."""
        cfg = getattr(ctx, "config", None)
        if isinstance(cfg, dict):
            try:
                return cfg.get("timeout", self.default_timeout)
            except Exception:
                return self.default_timeout
        if cfg is not None:
            return getattr(cfg, "timeout", self.default_timeout)
        return self.default_timeout

    def log(self, ctx, level, msg):
        """Log through ctx.log; silent when no logger is attached."""
        log = getattr(ctx, "log", None)
        if log is None:
            return
        try:
            getattr(log, level, log.warning)(msg)
        except Exception:
            pass

    def log_msg(self, ctx, msg):
        """Single-argument log variant (info level) for terse modules."""
        self.log(ctx, "info", msg)

    # -- URL helpers ---------------------------------------------------

    @staticmethod
    def is_http_url(target):
        """True when target is an absolute http(s) URL."""
        try:
            parts = urllib.parse.urlsplit(target)
        except Exception:
            return False
        return parts.scheme in ("http", "https") and bool(parts.netloc)

    @staticmethod
    def host_of(url):
        """Hostname of a URL, or "" when it cannot be parsed."""
        try:
            return urllib.parse.urlsplit(url).hostname or ""
        except Exception:
            return ""

    def in_scope(self, target, ctx):
        """True when no scope is set or the target host is in scope."""
        scope = getattr(ctx, "scope", None)
        if scope is None:
            return True
        try:
            return bool(scope.contains(self.host_of(target)))
        except Exception:
            return True

    # -- HTTP ----------------------------------------------------------

    def get(self, url, ctx, headers=None, **kwargs):
        """GET-ish fetch that honors stealth/proxy via ctx.

        headers may be passed positionally (as the old per-module _get
        helpers allowed) or as a keyword. Other kwargs (method=, data=,
        allow_redirects=) pass straight to arsenal.http.fetch. Returns
        the fetch() tuple, or None when the request failed outright.
        """
        if headers is not None:
            kwargs["headers"] = headers
        try:
            return http_mod.fetch(url, timeout=self.timeout(ctx), ctx=ctx,
                                  **kwargs)
        except Exception as exc:
            self.log(ctx, "debug", "%s: request failed for %s: %s"
                     % (self.name, url, exc))
            return None

    def get_no_redirect(self, url, ctx, **kwargs):
        """get() with redirects disabled (3xx returned untouched)."""
        return self.get(url, ctx, allow_redirects=False, **kwargs)

    def http_text(self, url, ctx, max_bytes=None, timeout=None):
        """GET url, return the decoded body text ("" on any failure)."""
        try:
            status, _headers, body, _final = http_mod.fetch(
                url, timeout=self.timeout(ctx) if timeout is None else timeout,
                ctx=ctx)
        except Exception:
            return ""
        if not status or status >= 400:
            return ""
        text = (body.decode("utf-8", errors="replace")
                if isinstance(body, bytes) else str(body))
        if max_bytes:
            text = text[:max_bytes]
        return text

    # -- findings --------------------------------------------------------

    def finding(self, **kwargs):
        """make_finding() with module= preset to this module's NAME."""
        kwargs.setdefault("module", self.name)
        return make_finding(**kwargs)

    # -- pre-run gates ---------------------------------------------------

    def guard(self, target, ctx, intrusive=False, require_url=True):
        """Run the standard pre-flight checks.

        Returns None when the module may proceed, otherwise a short reason
        string (already logged at a suitable level).
        """
        if (intrusive and getattr(ctx, "safe_mode", False)
                and not getattr(ctx, "allow_intrusive", False)):
            reason = ("%s skipped: safe mode blocks intrusive modules"
                      % self.name)
            self.log(ctx, "warning", reason)
            return reason
        if require_url and not self.is_http_url(target):
            return "not an http(s) URL: %r" % (target,)
        if not self.in_scope(target, ctx):
            reason = "%s: target out of scope: %s" % (self.name, target)
            self.log(ctx, "warning", reason)
            return reason
        return None
