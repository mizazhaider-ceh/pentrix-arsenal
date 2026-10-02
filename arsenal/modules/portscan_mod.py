#!/usr/bin/env python3
"""PENTRIX ARSENAL portscan module (TARGET_KIND="ip").

Fast async TCP port scanner with banner grabbing.

Adapted from pentrix-portscan: parse_ports(), scan_port(), run_scan() and
the banner-grab/clean logic are reused here, driven synchronously through
asyncio.run() to fit the module run() contract.
"""

import asyncio
import socket

from arsenal.findings import make_finding

NAME = "portscan"
DESCRIPTION = "Async TCP port scan over common ports with banner grabbing"
TARGET_KIND = "ip"
INTRUSIVE = False

DEFAULT_TIMEOUT = 1.0
DEFAULT_CONCURRENCY = 200
BANNER_READ_BYTES = 1024
BANNER_TIMEOUT = 2.0
BANNER_PREVIEW_LEN = 200

# Top 30 common TCP ports scanned by default.
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 587, 993, 995, 1433, 1521, 1723, 3306,
    3389, 5432, 5900, 6379, 8080, 8081, 8443, 8888, 9200, 27017,
]

# Common TCP ports mapped to a service hint.
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 69: "tftp", 80: "http", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp",
    135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 179: "bgp", 389: "ldap", 443: "https",
    445: "smb", 464: "kpasswd", 465: "smtps", 512: "exec",
    513: "login", 514: "syslog", 515: "printer", 548: "afp",
    554: "rtsp", 587: "submission", 636: "ldaps", 873: "rsync",
    993: "imaps", 995: "pop3s", 1080: "socks", 1099: "rmiregistry",
    1194: "openvpn", 1433: "mssql", 1434: "mssql-monitor",
    1521: "oracle", 1723: "pptp", 1883: "mqtt", 2049: "nfs",
    2375: "docker", 2376: "docker-tls", 3000: "http-alt",
    3306: "mysql", 33060: "mysqlx", 3389: "rdp", 3690: "svn",
    4369: "epmd", 4848: "glassfish", 5000: "http-alt",
    5060: "sip", 5061: "sips", 5432: "postgres", 5601: "kibana",
    5672: "amqp", 5900: "vnc", 5985: "winrm-http", 5986: "winrm-https",
    6000: "x11", 6379: "redis", 6667: "irc", 8000: "http-alt",
    8008: "http-alt", 8009: "ajp", 8080: "http-alt", 8081: "http-alt",
    8089: "splunk", 8090: "http-alt", 8443: "https-alt",
    8888: "http-alt", 8889: "http-alt", 9000: "http-alt",
    9090: "http-alt", 9092: "kafka", 9200: "elasticsearch",
    10000: "webmin", 10050: "zabbix-agent", 10051: "zabbix-server",
    11211: "memcached", 15672: "rabbitmq-mgmt",
    27015: "source-engine", 27017: "mongodb", 25565: "minecraft",
    19132: "minecraft-bedrock",
}

# Ports that usually speak plain HTTP, so a HEAD probe is worth trying.
HTTP_PORTS = {
    80, 3000, 5000, 7001, 7777, 8000, 8008, 8080, 8081,
    8090, 8888, 8889, 9000, 9090, 10000,
}

# Ports whose exposure is commonly risky; findings get medium severity.
RISKY_PORTS = {
    23: ("telnet", "CWE-319"),
    445: ("smb", None),
    3389: ("rdp", None),
    5900: ("vnc", None),
}
RISKY_REMEDIATION = "Restrict to VPN / firewall"


# ---------------------------------------------------------------------------
# helpers (adapted from pentrix-portscan)
# ---------------------------------------------------------------------------

def parse_ports(spec):
    """Parse a port specification into a sorted list of unique ports.

    Accepts comma separated items where each item is one of:
      - a single port:        "80"
      - a range:              "1-1000"
    Raises ValueError on anything invalid.
    """
    ports = set()
    for item in str(spec).split(","):
        item = item.strip().lower()
        if not item:
            continue
        if "-" in item:
            parts = item.split("-", 1)
            try:
                start, end = int(parts[0]), int(parts[1])
            except ValueError:
                raise ValueError("invalid port range %r" % item)
            if start < 1 or end > 65535 or start > end:
                raise ValueError(
                    "port range %r out of bounds (valid: 1-65535)" % item
                )
            ports.update(range(start, end + 1))
            continue
        try:
            port = int(item)
        except ValueError:
            raise ValueError("invalid port %r" % item)
        if port < 1 or port > 65535:
            raise ValueError("port %d out of bounds (valid: 1-65535)" % port)
        ports.add(port)
    if not ports:
        raise ValueError("no ports selected")
    return sorted(ports)


def clean_banner(raw):
    """Turn raw banner bytes into a short, printable, single-line preview."""
    text = raw.decode("utf-8", errors="replace")
    text = "".join(ch for ch in text if ch.isprintable() or ch == "\n")
    lines = [line.strip() for line in text.split("\n") if line.strip()]
    preview = " / ".join(lines[:3])
    if len(preview) > BANNER_PREVIEW_LEN:
        preview = preview[:BANNER_PREVIEW_LEN] + "..."
    return preview


async def grab_banner(reader, writer, port, timeout):
    """Read a service banner, optionally sending a HEAD probe on HTTP ports."""
    try:
        if port in HTTP_PORTS:
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
        data = await asyncio.wait_for(
            reader.read(BANNER_READ_BYTES), timeout=timeout
        )
        return clean_banner(data) if data else ""
    except (asyncio.TimeoutError, ConnectionError, OSError):
        return ""


async def scan_port(host, port, timeout, grab, semaphore):
    """Try to connect to one port. Returns (port, open, banner)."""
    async with semaphore:
        reader = writer = None
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return (port, False, "")
        banner = ""
        if grab:
            banner_timeout = max(timeout, BANNER_TIMEOUT)
            banner = await grab_banner(reader, writer, port, banner_timeout)
        try:
            writer.close()
            await writer.wait_closed()
        except (OSError, AttributeError):
            pass
        return (port, True, banner)


def resolve_target(target):
    """Resolve a hostname to an IP address. Raises socket.gaierror on failure."""
    infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    return infos[0][4][0]


async def run_scan(target, ip, ports, timeout, grab, concurrency):
    """Scan all ports concurrently and return a list of (port, open, banner)."""
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [
        scan_port(ip, port, timeout, grab, semaphore) for port in ports
    ]
    results = []
    for coro in asyncio.as_completed(tasks):
        results.append(await coro)
    results.sort(key=lambda r: r[0])
    return results


# ---------------------------------------------------------------------------
# module entry point
# ---------------------------------------------------------------------------

def run(target, ctx):
    findings = []

    log = getattr(ctx, "log", None)
    config = getattr(ctx, "config", None) or {}

    def _log(level, message):
        try:
            if log is not None:
                getattr(log, level)(message)
        except Exception:
            pass

    host = (target or "").strip()
    if not host:
        _log("warning", "portscan: empty target")
        return findings

    try:
        ip = resolve_target(host)
    except Exception as exc:
        _log("warning", "portscan: could not resolve %r: %s" % (host, exc))
        return findings

    ports_cfg = config.get("portscan_ports", DEFAULT_PORTS)
    try:
        if isinstance(ports_cfg, str):
            ports = parse_ports(ports_cfg)
        else:
            ports = sorted({int(p) for p in ports_cfg if 1 <= int(p) <= 65535})
            if not ports:
                raise ValueError("no ports selected")
    except (ValueError, TypeError) as exc:
        _log("warning", "portscan: bad port config: %s" % exc)
        return findings

    try:
        timeout = float(config.get("portscan_timeout", DEFAULT_TIMEOUT))
        concurrency = int(config.get("portscan_concurrency", DEFAULT_CONCURRENCY))
        grab = bool(config.get("portscan_banner", True))
    except (TypeError, ValueError) as exc:
        _log("warning", "portscan: bad scan config: %s" % exc)
        return findings
    if timeout <= 0 or concurrency < 1:
        _log("warning", "portscan: timeout/concurrency out of range")
        return findings

    _log("info", "portscan: scanning %s (%s), %d ports" % (host, ip, len(ports)))
    try:
        results = asyncio.run(
            run_scan(host, ip, ports, timeout, grab, concurrency)
        )
    except Exception as exc:
        _log("warning", "portscan: scan failed for %s: %s" % (host, exc))
        return findings

    for port, is_open, banner in results:
        if not is_open:
            continue
        service = COMMON_PORTS.get(port, "unknown")
        port_target = "%s:%d" % (host, port)
        evidence = "banner: %s" % (banner if banner else "no banner returned")
        if port in RISKY_PORTS:
            service_hint, cwe = RISKY_PORTS[port]
            findings.append(
                make_finding(
                    module=NAME,
                    target=port_target,
                    severity="medium",
                    confidence="proven",
                    title="Risky open port: %d/tcp (%s)" % (port, service_hint or service),
                    description=(
                        "Port %d/tcp (%s) is reachable from the network. "
                        "Services on this port are frequently abused and "
                        "should not be exposed broadly." % (port, service_hint or service)
                    ),
                    evidence=evidence,
                    cwe=cwe,
                    remediation=RISKY_REMEDIATION,
                )
            )
        else:
            findings.append(
                make_finding(
                    module=NAME,
                    target=port_target,
                    severity="info",
                    confidence="proven",
                    title="Open port: %d/tcp (%s)" % (port, service),
                    description="TCP port %d is open." % port,
                    evidence=evidence,
                    cwe=None,
                    remediation=None,
                )
            )
    _log("info", "portscan: %s done, %d open ports" % (host, len(findings)))
    return findings
