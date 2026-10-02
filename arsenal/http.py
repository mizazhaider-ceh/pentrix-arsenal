"""Shared HTTP client for PENTRIX ARSENAL.

Every module must use fetch() (or the fetch_text / fetch_json wrappers)
instead of rolling its own HTTP code. stdlib only (http.client).

Contract:
    fetch(url, timeout=10, method="GET", headers=None, data=None,
          allow_redirects=True, ctx=None, proxy=None)
        -> (status:int, headers:dict with lowercase keys, body:bytes,
            final_url:str)

fetch() never raises on HTTP error responses (4xx/5xx are returned as
their status code). On total transport failure it retries with backoff
and then returns (0, {}, b"", url) instead of raising.

Features:
- Keep-alive connection pooling: idle connections are reused per
  (scheme, host, port, proxy), so a scan module stops paying a fresh
  TCP+TLS handshake per request.
- Proxy support: explicit proxy= argument wins, then the config
  ``proxy`` block, then the HTTP_PROXY / HTTPS_PROXY environment
  variables. HTTPS targets are reached through the proxy with a CONNECT
  tunnel. Set proxy=False to disable even env proxies.
- Retry with backoff: transport errors, timeouts and HTTP 429 / 5xx are
  retried (configurable count/backoff); other HTTP statuses and malformed
  URLs are returned immediately without retry.
- Response reads are capped (default 8 MiB) before buffering, so one
  hostile response cannot blow up memory.
- Stealth: when ctx carries an enabled stealth config, fetch() sleeps a
  random delay between min_delay and max_delay before the request and
  rotates the User-Agent header.
"""

import http.client
import os
import random
import re
import socket
import ssl
import threading
import time
import urllib.parse

_UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 "
    "Firefox/128.0",
]

_DEFAULT_UA = "pentrix-arsenal/0.1.0"

DEFAULT_MAX_READ_BYTES = 8 * 1024 * 1024
DEFAULT_RETRIES = 2          # retries after the first attempt
DEFAULT_BACKOFF = 0.5        # base seconds; doubled per retry
DEFAULT_POOL_SIZE = 8        # idle connections kept per (scheme, host, port)
MAX_REDIRECTS = 5

# Statuses worth retrying: rate limiting and transient server errors.
_RETRY_STATUSES = {429, 500, 502, 503, 504}
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}

_POOL = {}
_POOL_LOCK = threading.Lock()
_SSL_CONTEXT = None
_SSL_LOCK = threading.Lock()


class _Retryable(Exception):
    """A failure that is worth retrying (timeout, reset, 429/5xx, DNS).

    Carries last_response so the caller can return the most recent HTTP
    response when retries run out, instead of discarding it.
    """

    def __init__(self, msg, last_response=None):
        super().__init__(msg)
        self.last_response = last_response


class _Fatal(Exception):
    """A failure that will not heal on retry (bad URL, TLS validation)."""


def _ssl_context():
    global _SSL_CONTEXT
    with _SSL_LOCK:
        if _SSL_CONTEXT is None:
            _SSL_CONTEXT = ssl.create_default_context()
        return _SSL_CONTEXT


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _stealth_cfg(ctx):
    cfg = getattr(ctx, "config", None)
    if not isinstance(cfg, dict):
        return {}
    stealth = cfg.get("stealth")
    return stealth if isinstance(stealth, dict) else {}


def _http_cfg(ctx):
    cfg = getattr(ctx, "config", None)
    if not isinstance(cfg, dict):
        return {}
    http_cfg = cfg.get("http")
    return http_cfg if isinstance(http_cfg, dict) else {}


def _maybe_stealth_sleep(ctx):
    stealth = _stealth_cfg(ctx)
    if not stealth.get("enabled"):
        return
    low = float(stealth.get("min_delay", 0.5))
    high = float(stealth.get("max_delay", 2.0))
    if high < low:
        low, high = high, low
    time.sleep(random.uniform(low, high))


def _pick_ua(ctx):
    stealth = _stealth_cfg(ctx)
    if stealth.get("enabled") and stealth.get("rotate_ua", True):
        return random.choice(_UA_LIST)
    cfg = getattr(ctx, "config", None)
    if isinstance(cfg, dict):
        try:
            from arsenal.config import get_profile
            ua = get_profile(cfg).get("user_agent")
            if ua:
                return ua
        except Exception:
            pass
    return _DEFAULT_UA


def _no_proxy_hosts(ctx):
    cfg = getattr(ctx, "config", None)
    if isinstance(cfg, dict):
        proxy_cfg = cfg.get("proxy")
        if isinstance(proxy_cfg, dict) and "no_proxy" in proxy_cfg:
            # An explicitly configured list (even empty) wins over the env.
            raw = proxy_cfg.get("no_proxy") or ""
            return {h.strip().lower().lstrip(".")
                    for h in raw.split(",") if h.strip()}
    raw = os.environ.get("NO_PROXY", "") or os.environ.get("no_proxy", "")
    return {h.strip().lower().lstrip(".") for h in raw.split(",") if h.strip()}


def _resolve_proxy(url, ctx, explicit):
    """Return the proxy URL to use, or None.

    Precedence: explicit proxy= argument (wins over no_proxy), then the
    config ``proxy`` block (only when enabled), then HTTP_PROXY/HTTPS_PROXY
    from the environment. explicit=False disables proxies entirely. Hosts
    listed in no_proxy bypass config/env proxies.
    """
    if explicit is False:
        return None
    parts = urllib.parse.urlsplit(url)
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    if explicit:
        # An explicit proxy= argument is the strongest user intent: it wins
        # over no_proxy lists. proxy=False disables proxies entirely.
        return explicit
    proxy_url = None
    cfg = getattr(ctx, "config", None)
    if isinstance(cfg, dict):
        proxy_cfg = cfg.get("proxy")
        if (isinstance(proxy_cfg, dict) and proxy_cfg.get("enabled")
                and proxy_cfg.get("url")):
            proxy_url = proxy_cfg["url"]
    if not proxy_url:
        if scheme == "http":
            proxy_url = (os.environ.get("HTTP_PROXY")
                         or os.environ.get("http_proxy"))
        elif scheme == "https":
            proxy_url = (os.environ.get("HTTPS_PROXY")
                         or os.environ.get("https_proxy"))
    if not proxy_url:
        return None
    for entry in _no_proxy_hosts(ctx):
        if host == entry or host.endswith("." + entry):
            return None
    return proxy_url


# ---------------------------------------------------------------------------
# Connection pool
# ---------------------------------------------------------------------------

def _pool_key(scheme, host, port, proxy_url):
    return (scheme, host, port, proxy_url or "")


def _acquire(scheme, host, port, proxy_url, timeout):
    """Return a connected HTTPConnection, reusing an idle one when possible."""
    key = _pool_key(scheme, host, port, proxy_url)
    with _POOL_LOCK:
        idle = _POOL.get(key, [])
        while idle:
            conn = idle.pop()
            if _conn_usable(conn):
                return conn, key
    if proxy_url:
        p = urllib.parse.urlsplit(proxy_url)
        if not p.hostname:
            raise _Fatal("bad proxy url: %r" % proxy_url)
        pport = p.port or (443 if p.scheme == "https" else 80)
        if p.scheme == "https":
            conn = http.client.HTTPSConnection(
                p.hostname, pport, timeout=timeout,
                context=_ssl_context())
        else:
            conn = http.client.HTTPConnection(p.hostname, pport,
                                              timeout=timeout)
        if scheme == "https":
            # CONNECT tunnel through the proxy to the target.
            conn.set_tunnel(host, port)
    elif scheme == "https":
        conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                           context=_ssl_context())
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    return conn, key


def _conn_usable(conn):
    try:
        sock = getattr(conn, "sock", None)
        return sock is not None
    except Exception:
        return False


def _release(key, conn, response, ctx):
    """Return conn to the pool when the server allows keep-alive."""
    try:
        connection = (response.getheader("Connection") or "").lower()
        http10 = getattr(response, "version", 11) == 10
        if "close" in connection or (http10 and "keep-alive" not in connection):
            conn.close()
            return
        limit = int(_http_cfg(ctx).get("pool_size", DEFAULT_POOL_SIZE))
        with _POOL_LOCK:
            idle = _POOL.setdefault(key, [])
            if len(idle) < max(1, limit):
                idle.append(conn)
            else:
                conn.close()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass


def pool_stats():
    """Return {pool_key: idle_count} for diagnostics/tests."""
    with _POOL_LOCK:
        return {key: len(conns) for key, conns in _POOL.items()}


def close_pool():
    """Close every idle pooled connection."""
    with _POOL_LOCK:
        for conns in _POOL.values():
            for conn in conns:
                try:
                    conn.close()
                except Exception:
                    pass
        _POOL.clear()


# ---------------------------------------------------------------------------
# Single request attempt
# ---------------------------------------------------------------------------

def _lower_headers(header_list):
    out = {}
    for key, value in header_list or []:
        out[str(key).lower()] = value
    return out


def _do_request(url, timeout, method, headers, data, proxy_url, ctx, ua):
    """One attempt: follow redirects manually, return
    (status, headers, body, final_url). Raises _Retryable / _Fatal."""
    try:
        parts = urllib.parse.urlsplit(url)
    except Exception as exc:
        raise _Fatal("bad url %r: %s" % (url, exc))
    scheme = (parts.scheme or "").lower()
    host = parts.hostname
    if scheme not in ("http", "https") or not host:
        raise _Fatal("unsupported url: %r" % url)

    body = data
    if isinstance(body, dict):
        body = urllib.parse.urlencode(body).encode("utf-8")

    hdrs = {"User-Agent": ua, "Accept": "*/*", "Connection": "keep-alive"}
    if headers:
        for key, value in headers.items():
            hdrs[str(key)] = value
    if body and "Content-Length" not in {k.title() for k in hdrs}:
        hdrs["Content-Length"] = str(len(body))

    max_read = int(_http_cfg(ctx).get("max_read_bytes", DEFAULT_MAX_READ_BYTES))
    current_url = url
    current_method = method
    current_body = body

    for _ in range(MAX_REDIRECTS + 1):
        p = urllib.parse.urlsplit(current_url)
        c_host = p.hostname
        c_port = p.port or (443 if p.scheme == "https" else 80)
        if p.scheme == "https" and proxy_url:
            # Tunneled: origin-form request line through the CONNECT tunnel.
            path = urllib.parse.urlunsplit(("", "", p.path or "/", p.query, ""))
        elif proxy_url and p.scheme == "http":
            # Plain proxy: absolute-form request line.
            path = current_url
        else:
            path = urllib.parse.urlunsplit(("", "", p.path or "/", p.query, ""))
        conn, key = _acquire(p.scheme, c_host, c_port, proxy_url, timeout)
        try:
            conn.request(current_method, path, body=current_body,
                         headers=hdrs)
            resp = conn.getresponse()
        except (socket.timeout, TimeoutError) as exc:
            _drop(key, conn)
            raise _Retryable("timeout: %s" % exc)
        except ssl.SSLError as exc:
            _drop(key, conn)
            raise _Fatal("tls error: %s" % exc)
        except (ConnectionError, http.client.HTTPException, socket.error,
                OSError) as exc:
            _drop(key, conn)
            raise _Retryable("transport error: %s" % exc)
        try:
            status = resp.status
            r_headers = _lower_headers(resp.getheaders())
            raw = resp.read(max_read + 1)
        except (socket.timeout, TimeoutError) as exc:
            _drop(key, conn)
            raise _Retryable("read timeout: %s" % exc)
        except (ConnectionError, http.client.HTTPException, OSError) as exc:
            _drop(key, conn)
            raise _Retryable("read error: %s" % exc)
        body_bytes = raw[:max_read]
        final = current_url

        if status in _RETRY_STATUSES:
            _drop(key, conn)
            raise _Retryable("http %d" % status,
                             last_response=(status, r_headers, body_bytes,
                                            final))

        location = r_headers.get("location")
        if location and status in _REDIRECT_STATUSES:
            _release(key, conn, resp, ctx)
            new_url = urllib.parse.urljoin(current_url, location)
            # 303 always becomes GET; 301/302 convert POST to GET.
            if status == 303 or (status in (301, 302)
                                 and current_method.upper() == "POST"):
                current_method = "GET"
                current_body = None
                hdrs.pop("Content-Length", None)
            # Never leak auth material across origins on redirect.
            if urllib.parse.urlsplit(new_url).netloc != p.netloc:
                for sensitive in ("Authorization", "Proxy-Authorization",
                                  "Cookie"):
                    hdrs.pop(sensitive, None)
            current_url = new_url
            final = new_url
            continue

        _release(key, conn, resp, ctx)
        return status, r_headers, body_bytes, final

    raise _Retryable("too many redirects")


def _drop(key, conn):
    try:
        conn.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def fetch(url, timeout=10, method="GET", headers=None, data=None,
          allow_redirects=True, ctx=None, proxy=None):
    """Fetch a URL; see module docstring for the return contract.

    proxy: explicit proxy URL (http://host:port), or False to bypass even
    environment proxies. When None, the config ``proxy`` block and the
    HTTP_PROXY/HTTPS_PROXY environment variables are honored.
    """
    _maybe_stealth_sleep(ctx)
    ua = _pick_ua(ctx)
    proxy_url = _resolve_proxy(url, ctx, proxy)
    retries = int(_http_cfg(ctx).get("retries", DEFAULT_RETRIES))
    backoff = float(_http_cfg(ctx).get("backoff", DEFAULT_BACKOFF))

    attempt = 0
    if not allow_redirects:
        return _fetch_no_redirect(url, timeout, method, headers, data,
                                  proxy_url, ctx, ua)
    while True:
        try:
            return _do_request(url, timeout, method, headers, data,
                               proxy_url, ctx, ua)
        except _Fatal:
            return (0, {}, b"", url)
        except _Retryable as exc:
            if attempt >= max(0, retries):
                # Transport failure -> (0, {}, b"", url); a persistent
                # 429/5xx still returns the last real response so callers
                # can inspect the status and body.
                if exc.last_response is not None:
                    return exc.last_response
                return (0, {}, b"", url)
            time.sleep(backoff * (2 ** attempt) + random.uniform(0, 0.1))
            attempt += 1


def _fetch_no_redirect(url, timeout, method, headers, data, proxy_url, ctx,
                       ua):
    """Single attempt without following redirects (3xx returned as-is)."""
    retries = int(_http_cfg(ctx).get("retries", DEFAULT_RETRIES))
    backoff = float(_http_cfg(ctx).get("backoff", DEFAULT_BACKOFF))
    attempt = 0
    while True:
        try:
            return _do_request_once(url, timeout, method, headers, data,
                                    proxy_url, ctx, ua)
        except _Fatal:
            return (0, {}, b"", url)
        except _Retryable as exc:
            if attempt >= max(0, retries):
                if exc.last_response is not None:
                    return exc.last_response
                return (0, {}, b"", url)
            time.sleep(backoff * (2 ** attempt) + random.uniform(0, 0.1))
            attempt += 1


def _do_request_once(url, timeout, method, headers, data, proxy_url, ctx,
                     ua):
    """Like _do_request but never follows redirects."""
    try:
        parts = urllib.parse.urlsplit(url)
    except Exception as exc:
        raise _Fatal("bad url %r: %s" % (url, exc))
    scheme = (parts.scheme or "").lower()
    host = parts.hostname
    if scheme not in ("http", "https") or not host:
        raise _Fatal("unsupported url: %r" % url)
    port = parts.port or (443 if scheme == "https" else 80)

    body = data
    if isinstance(body, dict):
        body = urllib.parse.urlencode(body).encode("utf-8")
    hdrs = {"User-Agent": ua, "Accept": "*/*", "Connection": "keep-alive"}
    if headers:
        for key, value in headers.items():
            hdrs[str(key)] = value
    if body:
        hdrs.setdefault("Content-Length", str(len(body)))
    max_read = int(_http_cfg(ctx).get("max_read_bytes", DEFAULT_MAX_READ_BYTES))

    if scheme == "https" and proxy_url:
        path = urllib.parse.urlunsplit(("", "", parts.path or "/",
                                        parts.query, ""))
    elif proxy_url and scheme == "http":
        path = url
    else:
        path = urllib.parse.urlunsplit(("", "", parts.path or "/",
                                        parts.query, ""))
    conn, key = _acquire(scheme, host, port, proxy_url, timeout)
    try:
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
    except (socket.timeout, TimeoutError) as exc:
        _drop(key, conn)
        raise _Retryable("timeout: %s" % exc)
    except ssl.SSLError as exc:
        _drop(key, conn)
        raise _Fatal("tls error: %s" % exc)
    except (ConnectionError, http.client.HTTPException, socket.error,
            OSError) as exc:
        _drop(key, conn)
        raise _Retryable("transport error: %s" % exc)
    try:
        status = resp.status
        r_headers = _lower_headers(resp.getheaders())
        raw = resp.read(max_read + 1)
    except (socket.timeout, TimeoutError) as exc:
        _drop(key, conn)
        raise _Retryable("read timeout: %s" % exc)
    except (ConnectionError, http.client.HTTPException, OSError) as exc:
        _drop(key, conn)
        raise _Retryable("read error: %s" % exc)
    if status in _RETRY_STATUSES:
        _drop(key, conn)
        raise _Retryable("http %d" % status,
                         last_response=(status, r_headers, raw[:max_read],
                                        url))
    _release(key, conn, resp, ctx)
    return status, r_headers, raw[:max_read], url


def fetch_text(url, timeout=10, method="GET", headers=None, data=None,
               allow_redirects=True, ctx=None, proxy=None, encoding=None):
    """Fetch a URL and decode the body to text.

    Returns (status:int, text:str, final_url:str).
    """
    status, hdrs, body, final = fetch(url, timeout=timeout, method=method,
                                      headers=headers, data=data,
                                      allow_redirects=allow_redirects, ctx=ctx,
                                      proxy=proxy)
    if encoding is None:
        ctype = hdrs.get("content-type", "")
        match = re.search(r"charset=([\w-]+)", ctype)
        encoding = match.group(1) if match else "utf-8"
    try:
        text = body.decode(encoding, errors="replace")
    except (LookupError, ValueError):
        text = body.decode("utf-8", errors="replace")
    return (status, text, final)


def fetch_json(url, timeout=10, method="GET", headers=None, data=None,
               allow_redirects=True, ctx=None, proxy=None):
    """Fetch a URL and parse the body as JSON.

    Returns (status:int, data-or-None, final_url:str).
    """
    import json
    status, text, final = fetch_text(url, timeout=timeout, method=method,
                                     headers=headers, data=data,
                                     allow_redirects=allow_redirects, ctx=ctx,
                                     proxy=proxy)
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None
    return (status, parsed, final)
