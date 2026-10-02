"""PENTRIX ARSENAL module: HTTP request smuggling prober.

Sends CL.TE, TE.CL and TE.TE desync probes over raw sockets (stdlib
socket + ssl only, no external HTTP stack so the exact bytes on the
wire are controlled). Detection is timing/response based: after each
smuggling probe a normal follow-up request is sent on the same
connection, and a 400/408/timeout or a smuggled-method echo on the
follow-up indicates the front-end and back-end disagreed on where the
first request ended.

Conservative by design: findings are severity medium with "review"
confidence, describe a *possible* desync, and include the exact probe
bytes for manual confirmation. Only the target host itself is probed,
payloads are tiny, and nothing is poisoned beyond the test connection.

INTRUSIVE = True: request smuggling probes are active and can briefly
confuse a proxy, so safe mode requires explicit opt-in.
"""

import socket
import ssl
import time
import urllib.parse

from arsenal.findings import make_finding

NAME = "smuggle"
DESCRIPTION = (
    "Detects HTTP request smuggling (CL.TE, TE.CL, TE.TE) with raw-socket "
    "timing-based desync probes."
)
TARGET_KIND = "url"
INTRUSIVE = True

TIMEOUT = 10
SOCKET_TIMEOUT = 6


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


def _split_target(target):
    parts = urllib.parse.urlsplit(target)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    use_tls = parts.scheme == "https"
    path = parts.path or "/"
    return host, port, use_tls, path


def _connect(host, port, use_tls):
    raw = socket.create_connection((host, port), timeout=SOCKET_TIMEOUT)
    if use_tls:
        ctx = ssl.create_default_context()
        return ctx.wrap_socket(raw, server_hostname=host)
    return raw


def _recv_all(sock, deadline):
    sock.settimeout(1.0)
    data = b""
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        except Exception:
            break
        if not chunk:
            break
        data += chunk
        if len(data) > 65536:
            break
    return data


def _probe_once(host, port, use_tls, probe, followup_path):
    """Send probe, then a normal follow-up on the same connection.

    Returns (probe_response_bytes, followup_response_bytes, fu_state)
    where fu_state is one of "ok", "timeout", "send_failed",
    "conn_error". A follow-up that could not be sent (server closed the
    connection, the normal case for non-keep-alive servers) is not a
    desync signal.
    """
    sock = None
    try:
        sock = _connect(host, port, use_tls)
        sock.sendall(probe)
        probe_resp = _recv_all(sock, time.monotonic() + 3)
        followup = (
            "GET %s HTTP/1.1\r\nHost: %s\r\n"
            "Connection: close\r\n\r\n" % (followup_path, host)
        ).encode("latin-1")
        start = time.monotonic()
        try:
            sock.sendall(followup)
        except Exception:
            return probe_resp, b"", "send_failed"
        fu_resp = _recv_all(sock, time.monotonic() + 4)
        if (time.monotonic() - start) >= 3.9 and not fu_resp:
            return probe_resp, fu_resp, "timeout"
        return probe_resp, fu_resp, "ok"
    except Exception:
        return b"", b"", "conn_error"
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def _status_line(resp):
    try:
        return resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    except Exception:
        return ""


def _probes(host, path):
    """Yield (name, probe_bytes, what_it_tests)."""
    # CL.TE: front-end uses Content-Length (sees a complete request and
    # leaves "0\r\n\r\nX" in the buffer); back-end uses Transfer-Encoding
    # and treats X as the start of the next request.
    cl_te = (
        "POST %s HTTP/1.1\r\nHost: %s\r\n"
        "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n\r\n"
        "0\r\n\r\nX" % (path, host)
    ).encode("latin-1")
    # TE.CL: front-end uses Transfer-Encoding; the hidden "GPOST" line
    # becomes a smuggled request prefix on a TE.CL back-end.
    te_cl = (
        "POST %s HTTP/1.1\r\nHost: %s\r\n"
        "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n\r\n"
        "5c\r\nGPOST /x HTTP/1.1\r\nContent-Length: 0\r\nHost: %s\r\n\r\n"
        "0\r\n\r\n" % (path, host, host)
    ).encode("latin-1")
    # TE.TE: duplicate Transfer-Encoding, one obfuscated; checks which
    # the chain honors.
    te_te = (
        "POST %s HTTP/1.1\r\nHost: %s\r\n"
        "Transfer-Encoding: xchunked\r\nTransfer-Encoding: chunked\r\n"
        "Content-Length: 6\r\nConnection: keep-alive\r\n\r\n"
        "0\r\n\r\nX" % (path, host)
    ).encode("latin-1")
    return [
        ("CL.TE", cl_te,
         "front-end honors Content-Length while back-end honors Transfer-Encoding"),
        ("TE.CL", te_cl,
         "front-end honors Transfer-Encoding while back-end honors Content-Length"),
        ("TE.TE", te_te,
         "duplicate Transfer-Encoding headers with one obfuscated variant"),
    ]


def run(target, ctx):
    """Run request-smuggling desync probes against the target."""
    try:
        return _run(target, ctx)
    except Exception as exc:
        _log(ctx, "warning", "%s failed on %s: %s" % (NAME, target, exc))
        return []


def _run(target, ctx):
    if INTRUSIVE and getattr(ctx, "safe_mode", False) \
            and not getattr(ctx, "allow_intrusive", False):
        _log(ctx, "warning", "%s skipped: safe mode blocks intrusive modules"
             % NAME)
        return []
    if not _is_http_url(target):
        return []
    if not _in_scope(target, ctx):
        _log(ctx, "warning", "%s: target out of scope: %s" % (NAME, target))
        return []
    host, port, use_tls, path = _split_target(target)
    if not host:
        return []
    findings = []
    for name, probe, theory in _probes(host, path):
        probe_resp, fu_resp, fu_state = _probe_once(
            host, port, use_tls, probe, path)
        fu_status = _status_line(fu_resp)
        signal = None
        if fu_state in ("ok", "timeout"):
            if b"GPOST" in fu_resp or b"Unrecognized method" in fu_resp:
                signal = "follow-up echoed the smuggled method prefix"
            elif fu_status.startswith("HTTP/1.1 400") \
                    or fu_status.startswith("HTTP/1.0 400"):
                signal = ("follow-up got 400 (leftover bytes poisoned the "
                          "connection)")
            elif "HTTP/1.1 408" in fu_status or "HTTP/1.0 408" in fu_status:
                signal = "follow-up got 408 (back-end waited on smuggled bytes)"
            elif fu_state == "timeout" and probe_resp:
                signal = "follow-up timed out while the probe got a response"
        if signal:
            findings.append(_finding(
                target=target,
                severity="medium",
                title="Possible HTTP request smuggling (%s desync)" % name,
                description=(
                    "A %s probe (%s) desynchronized the connection: %s. "
                    "This is a *possible* desync signal; confirm manually "
                    "with a time-delay or differential technique before "
                    "reporting." % (name, theory, signal)),
                evidence=(
                    "Probe (%s):\n%s\nProbe response: %s\n"
                    "Follow-up response: %s"
                    % (name, probe.decode("latin-1", "replace"),
                       _status_line(probe_resp) or "(none)",
                       fu_status or "(timed out / none)")),
                confidence="review",
                cwe="CWE-444",
                remediation=(
                    "Normalize to a single unambiguous framing on every hop "
                    "(reject requests with both CL and TE, or with duplicate "
                    "TE); keep front-end and back-end HTTP parsers in sync.")))
    return findings
