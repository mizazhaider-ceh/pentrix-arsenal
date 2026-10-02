"""Shared HTTP client for PENTRIX ARSENAL.

Every module must use fetch() (or the fetch_text / fetch_json wrappers)
instead of rolling its own HTTP code. urllib only, stdlib only.

Contract:
    fetch(url, timeout=10, method="GET", headers=None, data=None,
          allow_redirects=True, ctx=None)
        -> (status:int, headers:dict with lowercase keys, body:bytes,
            final_url:str)

fetch() never raises on HTTP error responses (4xx/5xx are returned as
their status code). On total transport failure it retries once and
then returns (0, {}, b"", url) instead of raising.

When ctx carries an enabled stealth config, fetch() sleeps a random
delay between min_delay and max_delay before the request and rotates
the User-Agent header.
"""

import json
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request

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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirect handler that refuses to follow redirects.

    Passed (as a subclass) to build_opener, which then skips the
    default HTTPRedirectHandler entirely, so 3xx responses are
    returned untouched.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _stealth_cfg(ctx):
    cfg = getattr(ctx, "config", None)
    if not isinstance(cfg, dict):
        return {}
    stealth = cfg.get("stealth")
    return stealth if isinstance(stealth, dict) else {}


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


def _lower_headers(headers):
    out = {}
    try:
        items = headers.items()
    except AttributeError:
        return out
    for key, value in items:
        out[str(key).lower()] = value
    return out


def _do_fetch(url, timeout, method, headers, data, allow_redirects, ua):
    body = data
    if isinstance(body, dict):
        body = urllib.parse.urlencode(body).encode("utf-8")
    hdrs = {"User-Agent": ua}
    if headers:
        for key, value in headers.items():
            hdrs[str(key)] = value
    request = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    handlers = [urllib.request.HTTPHandler(), urllib.request.HTTPSHandler()]
    if not allow_redirects:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    try:
        response = opener.open(request, timeout=timeout)
        return (response.status,
                _lower_headers(response.headers),
                response.read(),
                response.geturl())
    except urllib.error.HTTPError as exc:
        try:
            err_body = exc.read()
        except Exception:
            err_body = b""
        final = url
        try:
            final = exc.geturl()
        except Exception:
            pass
        return (exc.code, _lower_headers(exc.headers), err_body, final)


def fetch(url, timeout=10, method="GET", headers=None, data=None,
          allow_redirects=True, ctx=None):
    """Fetch a URL; see module docstring for the return contract."""
    _maybe_stealth_sleep(ctx)
    ua = _pick_ua(ctx)
    try:
        return _do_fetch(url, timeout, method, headers, data,
                         allow_redirects, ua)
    except Exception:
        pass
    # One retry on total failure, then give up gracefully.
    try:
        return _do_fetch(url, timeout, method, headers, data,
                         allow_redirects, ua)
    except Exception:
        return (0, {}, b"", url)


def fetch_text(url, timeout=10, method="GET", headers=None, data=None,
               allow_redirects=True, ctx=None, encoding=None):
    """Fetch a URL and decode the body to text.

    Returns (status:int, text:str, final_url:str).
    """
    status, hdrs, body, final = fetch(url, timeout=timeout, method=method,
                                      headers=headers, data=data,
                                      allow_redirects=allow_redirects, ctx=ctx)
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
               allow_redirects=True, ctx=None):
    """Fetch a URL and parse the body as JSON.

    Returns (status:int, data-or-None, final_url:str).
    """
    status, text, final = fetch_text(url, timeout=timeout, method=method,
                                     headers=headers, data=data,
                                     allow_redirects=allow_redirects, ctx=ctx)
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None
    return (status, parsed, final)
