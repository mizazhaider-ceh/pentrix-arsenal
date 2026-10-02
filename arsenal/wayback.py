#!/usr/bin/env python3
"""PENTRIX ARSENAL wayback module: CDX API client for web.archive.org.

Exposes historic URLs for a domain (useful for finding forgotten
endpoints, parameters and JavaScript files) and downloads archived
snapshots.

CLI test:
    python -m arsenal.wayback example.com
    python -m arsenal.wayback example.com --js --limit 20
    python -c "from arsenal.wayback import cdx_query; print(cdx_query('example.com', limit=3))"
"""

import json
import sys
import urllib.parse
import urllib.request

CDX_URL = "https://web.archive.org/cdx/search/cdx"
USER_AGENT = "pentrix-arsenal/0.1.0 (wayback cdx client)"
DEFAULT_TIMEOUT = 30


def _http_get(url, timeout=DEFAULT_TIMEOUT):
    """GET a URL, returning (status, raw_bytes). Raises on network errors."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read()


def cdx_query(domain, limit=200, collapse="urlkey", filter_mime=None):
    """Query the CDX API for a domain.

    Returns a list of dict rows with keys: timestamp, original, urlkey,
    statuscode, mimetype, digest. Returns [] on any error.
    """
    domain = (domain or "").strip().rstrip("/").lower()
    if not domain:
        return []
    pairs = [
        ("url", domain + "/*"),
        ("output", "json"),
        ("fl", "timestamp,original,urlkey,statuscode,mimetype,digest"),
        ("limit", str(limit)),
        ("collapse", collapse),
        ("filter", "statuscode:200"),
    ]
    if filter_mime:
        pairs.append(("filter", "mimetype:" + filter_mime))
    url = CDX_URL + "?" + urllib.parse.urlencode(pairs)
    try:
        status, raw = _http_get(url, timeout=DEFAULT_TIMEOUT)
    except Exception:
        return []
    if status != 200 or not raw:
        return []
    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except (ValueError, TypeError):
        return []
    if not isinstance(data, list) or len(data) < 2:
        return []
    header = data[0]
    rows = []
    for row in data[1:]:
        if isinstance(row, list) and len(row) == len(header):
            rows.append(dict(zip(header, row)))
    return rows


def historic_urls(domain, limit=200):
    """Return archived HTML page URLs for a domain, params-bearing first."""
    rows = cdx_query(domain, limit=limit, filter_mime="text/html")
    urls = []
    for row in rows:
        original = row.get("original") or ""
        if original and original not in urls:
            urls.append(original)
    urls.sort(key=lambda u: 0 if "?" in u else 1)
    return urls


def historic_js(domain, limit=100):
    """Return archived JavaScript file URLs for a domain."""
    rows = cdx_query(domain, limit=limit, filter_mime=".*javascript.*")
    urls = []
    for row in rows:
        original = (row.get("original") or "").split("#", 1)[0]
        if original.lower().split("?", 1)[0].endswith(".js") and original not in urls:
            urls.append(original)
    return urls


def fetch_snapshot(original_url, timestamp):
    """Download one archived snapshot. Returns bytes, or None on failure."""
    if not original_url or not timestamp:
        return None
    url = "https://web.archive.org/web/%sid_/%s" % (timestamp, original_url)
    try:
        status, raw = _http_get(url, timeout=DEFAULT_TIMEOUT)
    except Exception:
        return None
    if status != 200 or not raw:
        return None
    return raw


def _cli(argv):
    import argparse

    parser = argparse.ArgumentParser(
        prog="wayback",
        description="Query web.archive.org CDX API for historic URLs of a domain.",
    )
    parser.add_argument("domain", help="domain to query, e.g. example.com")
    parser.add_argument("--limit", type=int, default=20,
                        help="max rows to fetch (default: 20)")
    parser.add_argument("--js", action="store_true",
                        help="list archived JavaScript files instead of pages")
    args = parser.parse_args(argv)

    if args.js:
        urls = historic_js(args.domain, limit=args.limit)
        print("%d archived JS files for %s" % (len(urls), args.domain))
    else:
        urls = historic_urls(args.domain, limit=args.limit)
        print("%d archived URLs for %s" % (len(urls), args.domain))
    for url in urls:
        print(url)
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
