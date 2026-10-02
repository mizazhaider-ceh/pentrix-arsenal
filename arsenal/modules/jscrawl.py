"""Shared JavaScript crawler for PENTRIX ARSENAL.

One canonical JS discovery implementation used by jssecrets_mod and
jsintel_mod (previously each had its own copy, and a pipeline run fetched
the same files twice). Discovers same-host script URLs from a page's
<script src> tags plus a few common bundle paths, and downloads file
content through arsenal.http so stealth/proxy settings apply.

Public API:
    discover_js_urls(page_url, html, extra_paths=None) -> [urls]
    fetch_js(url, ctx, timeout=10, max_bytes=None) -> (status, text)
"""

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from arsenal import http as http_mod

COMMON_JS_PATHS = ["/app.js", "/main.js", "/bundle.js"]

_SRC_RE = re.compile(r"<script[^>]+src\s*=\s*[\"']([^\"']+)[\"']",
                     re.IGNORECASE)


class _ScriptSrcParser(HTMLParser):
    """Collects script src attributes from a page."""

    def __init__(self):
        super().__init__()
        self.srcs = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            for attr_name, value in attrs:
                if attr_name.lower() == "src" and value:
                    self.srcs.append(value)


def discover_js_urls(page_url, html, extra_paths=None):
    """Return ordered, deduplicated same-host JS URLs for a page.

    Sources: <script src> tags (parsed, plus a regex fallback for odd
    markup) and common bundle paths. Cross-host, data: and javascript:
    URLs are dropped.
    """
    found = []
    seen = set()
    base_netloc = urlparse(page_url).netloc.lower()

    def add(raw):
        if not raw or raw.startswith(("data:", "javascript:", "#")):
            return
        abs_url = urljoin(page_url, raw.strip())
        parts = urlparse(abs_url)
        if parts.scheme not in ("http", "https"):
            return
        if parts.netloc.lower() != base_netloc:
            return
        clean = parts._replace(fragment="").geturl()
        if clean not in seen:
            seen.add(clean)
            found.append(clean)

    parser = _ScriptSrcParser()
    try:
        parser.feed(html or "")
    except Exception:
        pass
    for src in parser.srcs:
        add(src)
    for match in _SRC_RE.finditer(html or ""):
        add(match.group(1))
    for path in (extra_paths if extra_paths is not None
                 else COMMON_JS_PATHS):
        add(path)
    return found


def fetch_js(url, ctx, timeout=10, max_bytes=None):
    """GET url via arsenal.http. Returns (status:int|None, body_text:str).

    ctx is passed through so stealth sleeps, UA rotation and proxy
    settings apply. status is None when the request failed outright.
    """
    try:
        status, _headers, body, _final = http_mod.fetch(
            url, timeout=timeout, ctx=ctx)
    except Exception:
        return None, ""
    text = (body.decode("utf-8", errors="replace")
            if isinstance(body, bytes) else str(body))
    if max_bytes:
        text = text[:max_bytes]
    return status, text


def fetch_page_text(url, ctx, timeout=10):
    """GET a page, return decoded text ("" when status is missing/4xx/5xx)."""
    status, text = fetch_js(url, ctx, timeout=timeout)
    if not status or status >= 400:
        return ""
    return text
