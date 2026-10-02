"""PENTRIX ARSENAL module: WebSocket security checks.

Performs a raw HTTP Upgrade handshake (stdlib socket + ssl only) against
candidate WebSocket endpoints and checks:

1. Missing Origin validation: if the server returns 101 Switching
   Protocols for an arbitrary evil Origin, any site can open the
   socket (CSWSH).
2. Unauthenticated upgrade: reports when an endpoint completes the
   handshake with no credentials, with guidance to test whether
   authenticated actions are reachable over it.
3. WSS downgrade / mixed content: when the page is served over HTTPS
   but references ws:// endpoints, credentials and traffic go in clear.

Candidate endpoints come from ws:// and wss:// URLs found in the page
plus common paths (/ws, /websocket, /socket, /chat). The module only
completes the handshake; it never sends WebSocket frames.

Non-intrusive: a few TCP handshakes.
"""

import base64
import os
import re
import socket
import ssl
import time
import urllib.parse

from arsenal.findings import make_finding
from arsenal.http import fetch

NAME = "ws"
DESCRIPTION = (
    "Checks WebSocket endpoints via raw Upgrade handshakes: Origin "
    "validation, unauthenticated access, and ws:// downgrade on HTTPS pages."
)
TARGET_KIND = "url"
INTRUSIVE = False

TIMEOUT = 10
EVIL_ORIGIN = "https://evil.example.com"
SOCKET_TIMEOUT = 6
COMMON_PATHS = ("/ws", "/websocket", "/socket", "/chat", "/realtime")


def _timeout(ctx):
    cfg = getattr(ctx, "config", None)
    if isinstance(cfg, dict):
        return cfg.get("timeout", TIMEOUT)
    if cfg is not None:
        return getattr(cfg, "timeout", TIMEOUT)
    return TIMEOUT


def _log(ctx, level, msg):
    log = getattr(ctx, "log", None)
    if log is None:
        return
    try:
        getattr(log, level, log.warning)(msg)
    except Exception:
        pass


def _is_http_url(target):
    try:
        parts = urllib.parse.urlsplit(target)
    except Exception:
        return False
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def _host_of(url):
    try:
        return urllib.parse.urlsplit(url).hostname or ""
    except Exception:
        return ""


def _in_scope(target, ctx):
    scope = getattr(ctx, "scope", None)
    if scope is None:
        return True
    try:
        return bool(scope.contains(_host_of(target)))
    except Exception:
        return True


def _finding(**kwargs):
    kwargs.setdefault("module", NAME)
    return make_finding(**kwargs)


def _fetch(url, ctx):
    try:
        return fetch(url, timeout=_timeout(ctx), allow_redirects=True, ctx=ctx)
    except Exception as exc:
        _log(ctx, "debug", "%s: request failed for %s: %s" % (NAME, url, exc))
        return None


def _handshake(ws_url, origin, use_tls):
    """Do a raw WebSocket Upgrade handshake.

    Returns (status_line, response_headers_text) or (None, "") on error.
    """
    parts = urllib.parse.urlsplit(ws_url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "wss" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    req = (
        "GET %s HTTP/1.1\r\nHost: %s\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n"
        "Origin: %s\r\n\r\n" % (path, host, key, origin)
    )
    sock = None
    try:
        raw = socket.create_connection((host, port), timeout=SOCKET_TIMEOUT)
        if use_tls:
            sctx = ssl.create_default_context()
            sock = sctx.wrap_socket(raw, server_hostname=host)
        else:
            sock = raw
        sock.settimeout(SOCKET_TIMEOUT)
        sock.sendall(req.encode("latin-1"))
        data = b""
        start = time.monotonic()
        while time.monotonic() - start < SOCKET_TIMEOUT:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data or len(data) > 8192:
                break
    except Exception:
        return None, ""
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    try:
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    except Exception:
        return None, ""
    lines = head.split("\r\n")
    return (lines[0] if lines else ""), head


def _candidates(target, page_text):
    found = []
    for m in re.finditer(r'wss?://[^\s"\'<>]+', page_text or ""):
        found.append(m.group(0).rstrip(".,;"))
    parts = urllib.parse.urlsplit(target)
    base = "%s://%s" % (parts.scheme, parts.netloc)
    for p in COMMON_PATHS:
        scheme = "wss" if parts.scheme == "https" else "ws"
        found.append("%s://%s%s" % (scheme, parts.netloc, p))
    seen = set()
    out = []
    for u in found:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out[:8]


def run(target, ctx):
    """Check WebSocket endpoints reachable from the target."""
    try:
        return _run(target, ctx)
    except Exception as exc:
        _log(ctx, "warning", "%s failed on %s: %s" % (NAME, target, exc))
        return []


def _run(target, ctx):
    if not _is_http_url(target):
        return []
    if not _in_scope(target, ctx):
        _log(ctx, "warning", "%s: target out of scope: %s" % (NAME, target))
        return []
    findings = []
    resp = _fetch(target, ctx)
    page_text = ""
    if resp is not None:
        _s, _h, body, _f = resp
        try:
            page_text = body.decode("utf-8", errors="replace")
        except Exception:
            page_text = ""
    page_is_https = target.startswith("https://")
    target_origin = "%s://%s" % tuple(urllib.parse.urlsplit(target)[:2])
    page_host = _host_of(target)

    for ws_url in _candidates(target, page_text):
        if _host_of(ws_url) != page_host:
            continue
        use_tls = ws_url.startswith("wss://")
        # 1. Evil origin handshake.
        status, head = _handshake(ws_url, EVIL_ORIGIN, use_tls)
        if status is None:
            continue
        if status.startswith("HTTP/1.1 101") or status.startswith("HTTP/1.0 101"):
            findings.append(_finding(
                target=target,
                severity="medium",
                title="WebSocket missing Origin validation (%s)" % ws_url,
                description=(
                    "The endpoint completed the WebSocket handshake for an "
                    "arbitrary Origin (%s). Any website can open this socket "
                    "in a victim's browser (cross-site WebSocket hijacking) "
                    "and, if the socket carries the victim's session, act on "
                    "their behalf." % EVIL_ORIGIN),
                evidence=(
                    "Endpoint: %s\nRequest Origin: %s\nResponse: %s"
                    % (ws_url, EVIL_ORIGIN, status)),
                confidence="strong",
                cwe="CWE-1385",
                remediation=(
                    "Validate the Origin header against an allowlist on the "
                    "WebSocket handshake; require a CSRF token for the "
                    "upgrade when the socket performs state changes.")))
            # 2. Unauthenticated upgrade note for the same endpoint.
            status2, _h2 = _handshake(ws_url, target_origin, use_tls)
            if status2 and status2.startswith("HTTP/1.1 101"):
                findings.append(_finding(
                    target=target,
                    severity="info",
                    title="WebSocket endpoint accepts unauthenticated upgrade",
                    description=(
                        "The handshake succeeded with no credentials. Verify "
                        "manually whether sensitive actions or data are "
                        "reachable over this socket without a session, and "
                        "whether an authenticated socket leaks other users' "
                        "data."),
                    evidence="Endpoint: %s\nResponse: %s" % (ws_url, status2),
                    confidence="review",
                    cwe="CWE-306",
                    remediation=(
                        "Authenticate the upgrade (session cookie or token) "
                        "and authorize every message server-side.")))
        # 3. ws:// downgrade on an HTTPS page.
        if page_is_https and ws_url.startswith("ws://"):
            findings.append(_finding(
                target=target,
                severity="low",
                title="Insecure ws:// endpoint referenced from HTTPS page",
                description=(
                    "An HTTPS page references a cleartext ws:// WebSocket. "
                    "Traffic and any credentials on that socket are exposed "
                    "to network attackers."),
                evidence="Endpoint: %s (page: %s)" % (ws_url, target),
                confidence="review",
                cwe="CWE-319",
                remediation="Serve WebSockets over wss:// only."))
    return findings
