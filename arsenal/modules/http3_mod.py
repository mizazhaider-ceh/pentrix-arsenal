"""PENTRIX ARSENAL module: HTTP/3 + QUIC probing.

The recon stack is HTTP/1.1+2 only; nothing in it finds HTTP/3-only
surfaces. This module does two stdlib-only probes:

1. alt-svc discovery: fetch the target over HTTPS and parse the
   Alt-Svc header for h3 / h3-29 / h2 advertisements.
2. QUIC version negotiation: send a QUIC long-header Initial with a
   reserved version over UDP/443. A QUIC speaker answers with a Version
   Negotiation packet listing the versions it supports. Parsing that
   packet needs only struct, no QUIC library.

A full HTTP/3 request (TLS 1.3 + QUIC handshake + qpack) is out of
scope for stdlib; this module reports the surface (UDP/443 open, QUIC
versions offered, alt-svc advertised) and tells the hunter what to do
with it. Not intrusive: one UDP packet + one HTTPS fetch per host.

Honest limits: some firewalls silently drop UDP/443 (no reply != no
QUIC); version negotiation is disabled by a few hardened stacks.
"""

import socket
import struct
import time
import urllib.parse

from arsenal.findings import make_finding
from arsenal.http import fetch

NAME = "http3"
DESCRIPTION = (
    "HTTP/3 + QUIC surface discovery: Alt-Svc header parsing and UDP/443 "
    "QUIC version-negotiation probing (stdlib socket only)."
)
TARGET_KIND = "host"
INTRUSIVE = False

UDP_PORT = 443
SOCKET_TIMEOUT = 4.0

# QUIC long header: 0xC0 | fixed bit, then 4-byte version.
# A reserved version (0x0A0A0A0A, "grease") forces Version Negotiation.
RESERVED_VERSION = 0x0A0A0A0A


def build_version_negotiation_probe() -> bytes:
    """Minimal QUIC long-header packet that triggers Version Negotiation.

    Layout: flags(0xC0) | version(4, reserved) | dcid_len(1)=8 |
    dcid(8) | scid_len(1)=8 | scid(8). Payload beyond the header is not
    needed: the version alone triggers negotiation (RFC 9000 6.1).
    """
    import os
    dcid = os.urandom(8)
    scid = os.urandom(8)
    return (struct.pack("!B", 0xC0)
            + struct.pack("!I", RESERVED_VERSION)
            + struct.pack("!B", 8) + dcid
            + struct.pack("!B", 8) + scid)


def parse_version_negotiation(data: bytes):
    """Parse a Version Negotiation packet -> list of version ints.

    Returns None when the packet is not a Version Negotiation packet.
    """
    if len(data) < 7:
        return None
    flags, version = struct.unpack("!BI", data[:5])
    if not (flags & 0x80):      # long header bit
        return None
    if version != 0x00000000:   # version 0 == Version Negotiation
        return None
    versions = []
    for i in range(5, len(data) - 3, 4):
        (v,) = struct.unpack("!I", data[i:i + 4])
        versions.append(v)
    return versions


QUIC_VERSION_NAMES = {
    0x00000001: "QUIC v1 (RFC 9000)",
    0x6B3343CF: "QUIC v2 (RFC 9369)",
    0x0A0A0A0A: "reserved/grease",
}


def probe_quic(host: str, port: int = UDP_PORT,
               timeout: float = SOCKET_TIMEOUT) -> dict:
    """Send the negotiation probe; return versions offered (may be empty)."""
    result = {"udp_open": False, "versions": [], "error": None}
    try:
        addrs = socket.getaddrinfo(host, port, socket.AF_INET,
                                   socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        result["error"] = "dns: %s" % exc
        return result
    if not addrs:
        result["error"] = "no address"
        return result
    family, socktype, proto, _, sockaddr = addrs[0]
    sock = socket.socket(family, socktype, proto)
    sock.settimeout(timeout)
    try:
        sock.sendto(build_version_negotiation_probe(), sockaddr)
        result["udp_open"] = True  # sendto succeeded; reply decides QUIC
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            result["error"] = "no reply (UDP filtered or no QUIC)"
            return result
        versions = parse_version_negotiation(data)
        if versions is None:
            result["error"] = "reply was not a Version Negotiation packet"
            return result
        result["versions"] = versions
    except OSError as exc:
        result["error"] = "socket: %s" % exc
    finally:
        sock.close()
    return result


def parse_alt_svc(headers) -> list[str]:
    """Extract advertised protocols from Alt-Svc / Alt-Svc-Used headers."""
    out = []
    h = {str(k).lower(): v for k, v in (headers or {}).items()}
    for name in ("alt-svc", "alt-svc-used"):
        val = h.get(name)
        if not val:
            continue
        for part in str(val).split(","):
            proto = part.strip().split("=")[0].strip().strip('"').lower()
            if proto and proto not in out:
                out.append(proto)
    return out


def check_alt_svc(target: str, ctx) -> list[str]:
    """Fetch target over HTTPS and return advertised alt-svc protocols."""
    url = target if "://" in target else "https://" + target
    try:
        status, headers, body, _final = fetch(url, ctx=ctx, timeout=12)
    except Exception:
        return []
    return parse_alt_svc(headers)


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(target, ctx):
    try:
        return _run(target, ctx)
    except Exception as exc:
        _log(ctx, "warning", "%s failed on %s: %s" % (NAME, target, exc))
        return []


def _log(ctx, level, msg):
    log = getattr(ctx, "log", None)
    if log:
        getattr(log, level, log.info)(msg)


def _run(target, ctx):
    host = urllib.parse.urlsplit(
        target if "://" in target else "https://" + target).hostname or target
    findings = []
    alt = check_alt_svc(target, ctx)
    quic = probe_quic(host)
    versions = quic["versions"]
    named = [QUIC_VERSION_NAMES.get(v, "0x%08X" % v) for v in versions]

    if versions:
        findings.append(make_finding(
            NAME, target, "info",
            "QUIC speaker on UDP/443: %s" % ", ".join(named),
            "Host %s answered QUIC Version Negotiation on UDP/443, "
            "offering: %s. The standard recon stack never probes UDP/443, "
            "so HTTP/3-only behavior (different WAF rules, different "
            "routing, header handling) is untested surface." % (host, ", ".join(named)),
            evidence="udp_open=true versions=%s alt_svc=%s" % (named, alt),
            confidence="strong",
            remediation="Probe the same endpoints over HTTP/3 with a QUIC "
                        "client (quiche, ngtcp2, or curl --http3): WAF and "
                        "access-control behavior may differ from TCP."))
    if any(p.startswith("h3") for p in alt):
        findings.append(make_finding(
            NAME, target, "info",
            "HTTP/3 advertised via Alt-Svc: %s" % ", ".join(alt),
            "The HTTPS response advertises %s. Clients will upgrade to "
            "QUIC; test whether security controls (WAF, auth, rate "
            "limits) apply equally on the UDP path." % ", ".join(alt),
            evidence="alt_svc=%s quic_versions=%s" % (alt, named or "none"),
            confidence="strong"))
    if not versions and not alt:
        findings.append(make_finding(
            NAME, target, "info",
            "No HTTP/3 surface detected on %s" % host,
            "No Alt-Svc advertisement and no QUIC Version Negotiation "
            "reply on UDP/443%s." % (
                " (%s)" % quic["error"] if quic.get("error") else ""),
            evidence="alt_svc=[] quic_error=%s" % quic.get("error"),
            confidence="review"))
    return findings
