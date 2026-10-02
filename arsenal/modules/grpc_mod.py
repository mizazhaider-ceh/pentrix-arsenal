"""PENTRIX ARSENAL module: gRPC recon.

Nobody in the recon stack speaks gRPC: no reflection enumeration, no
per-method authz testing. This module implements just enough HTTP/2 and
protobuf with stdlib sockets to:

1. Enumerate services via the gRPC Server Reflection protocol
   (grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo).
2. Resolve each service's methods (file_containing_symbol).
3. Per-method authz probe: call each method unauthenticated with an
   empty message and read grpc-status from the trailers. Status 0 (OK)
   or 3 (INVALID_ARGUMENT) means the handler executed without auth;
   16 (UNAUTHENTICATED) / 7 (PERMISSION_DENIED) means it is protected.

Tries TLS+ALPN(h2) first, then plaintext h2c. If the server needs a
full HTTP/2 implementation detail this minimal client lacks (flow
control edge cases, Huffman-encoded HPACK), it degrades gracefully with
a clear "install the h2 library for full coverage" note instead of
failing silently. Not intrusive beyond normal API calls.

Honest limits: no protobuf schema-aware fuzzing (needs .proto files);
method calls use empty messages only.
"""

import socket
import ssl
import struct
import time
import urllib.parse

from arsenal.findings import make_finding

NAME = "grpc"
DESCRIPTION = (
    "gRPC recon: reflection-based service/method enumeration and "
    "per-method unauthenticated authz probing (stdlib HTTP/2 client)."
)
TARGET_KIND = "host"
INTRUSIVE = False

DEFAULT_PORTS = (443, 50051)
SOCKET_TIMEOUT = 8.0

REFLECTION_PATH = ("/grpc.reflection.v1alpha.ServerReflection/"
                   "ServerReflectionInfo")

GRPC_STATUS_NAMES = {
    0: "OK", 1: "CANCELLED", 2: "UNKNOWN", 3: "INVALID_ARGUMENT",
    4: "DEADLINE_EXCEEDED", 5: "NOT_FOUND", 6: "ALREADY_EXISTS",
    7: "PERMISSION_DENIED", 8: "RESOURCE_EXHAUSTED", 9: "FAILED_PRECONDITION",
    10: "ABORTED", 11: "OUT_OF_RANGE", 12: "UNIMPLEMENTED",
    13: "INTERNAL", 14: "UNAVAILABLE", 15: "DATA_LOSS",
    16: "UNAUTHENTICATED",
}


# ---------------------------------------------------------------------------
# Minimal protobuf codec
# ---------------------------------------------------------------------------

def _varint_encode(n: int) -> bytes:
    out = bytearray()
    while True:
        bits = n & 0x7F
        n >>= 7
        if n:
            out.append(bits | 0x80)
        else:
            out.append(bits)
            break
    return bytes(out)


def _varint_decode(buf: bytes, pos: int):
    result, shift = 0, 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 64:
            raise ValueError("varint too long")


def _field(field_no: int, wire: int, payload: bytes) -> bytes:
    return _varint_encode((field_no << 3) | wire) + payload


def bytes_field(field_no: int, data: bytes) -> bytes:
    return _field(field_no, 2, _varint_encode(len(data)) + data)


def decode_message(buf: bytes):
    """Decode protobuf -> list of (field_no, wire_type, value)."""
    fields = []
    pos = 0
    while pos < len(buf):
        key, pos = _varint_decode(buf, pos)
        field_no, wire = key >> 3, key & 0x07
        if wire == 0:
            val, pos = _varint_decode(buf, pos)
        elif wire == 1:
            val, pos = buf[pos:pos + 8], pos + 8
        elif wire == 2:
            ln, pos = _varint_decode(buf, pos)
            val, pos = buf[pos:pos + ln], pos + ln
        elif wire == 5:
            val, pos = buf[pos:pos + 4], pos + 4
        else:
            raise ValueError("unsupported wire type %d" % wire)
        fields.append((field_no, wire, val))
    return fields


def get_field(fields, field_no: int):
    return [v for f, w, v in fields if f == field_no]


# ---------------------------------------------------------------------------
# Reflection request builders
# ---------------------------------------------------------------------------

def req_list_services() -> bytes:
    # ServerReflectionRequest.list_services = field 20, empty message
    return bytes_field(20, b"")


def req_file_containing_symbol(symbol: str) -> bytes:
    # ServerReflectionRequest.file_containing_symbol = field 4
    return bytes_field(4, symbol.encode())


def parse_list_services_response(data: bytes) -> list[str]:
    """ServerReflectionResponse -> service names."""
    services = []
    for f, w, v in decode_message(data):
        if f == 4 and w == 2:  # list_services_response
            for sf, sw, sv in decode_message(v):
                if sf == 1 and sw == 2:  # service (repeated)
                    for nf, nw, nv in decode_message(sv):
                        if nf == 1 and nw == 2:
                            services.append(nv.decode("utf-8", "replace"))
    return services


def parse_file_descriptor_response(data: bytes):
    """ServerReflectionResponse -> [(package, service, [methods])].

    methods: [{"name", "input_type", "output_type"}]. package may be ""
    when the descriptor omits it.
    """
    out = []
    for f, w, v in decode_message(data):
        if f == 5 and w == 2:  # file_descriptor_response
            for ff, fw, fv in decode_message(v):
                if ff == 1 and fw == 2:  # file_descriptor_proto
                    pfields = decode_message(fv)
                    pkgs = get_field(pfields, 2)  # package
                    package = pkgs[0].decode("utf-8", "replace") if pkgs else ""
                    for pf, pw, pv in pfields:
                        if pf == 6 and pw == 2:  # service
                            svc_fields = decode_message(pv)
                            names = get_field(svc_fields, 1)
                            svc_name = names[0].decode("utf-8", "replace") \
                                if names else "?"
                            methods = []
                            for mf, mw, mv in svc_fields:
                                if mf == 2 and mw == 2:
                                    mfields = decode_message(mv)
                                    mn = get_field(mfields, 1)
                                    mi = get_field(mfields, 2)
                                    mo = get_field(mfields, 3)
                                    methods.append({
                                        "name": mn[0].decode("utf-8", "replace") if mn else "?",
                                        "input_type": mi[0].decode("utf-8", "replace") if mi else "",
                                        "output_type": mo[0].decode("utf-8", "replace") if mo else "",
                                    })
                            out.append((package, svc_name, methods))
    return out


# ---------------------------------------------------------------------------
# Minimal HPACK (encode literal-without-indexing; decode common forms)
# ---------------------------------------------------------------------------

_HPACK_STATIC = [None] + [
    (":authority", ""), (":method", "GET"), (":method", "POST"),
    (":path", "/"), (":path", "/index.html"), (":scheme", "http"),
    (":scheme", "https"), (":status", "200"), (":status", "204"),
    (":status", "206"), (":status", "304"), (":status", "400"),
    (":status", "404"), (":status", "500"), ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"), ("accept-language", ""),
    ("accept-ranges", ""), ("accept", ""), ("access-control-allow-origin", ""),
    ("age", ""), ("allow", ""), ("authorization", ""), ("cache-control", ""),
    ("content-disposition", ""), ("content-encoding", ""),
    ("content-language", ""), ("content-length", ""), ("content-location", ""),
    ("content-range", ""), ("content-type", ""), ("cookie", ""), ("date", ""),
    ("etag", ""), ("expect", ""), ("expires", ""), ("from", ""), ("host", ""),
    ("if-match", ""), ("if-modified-since", ""), ("if-none-match", ""),
    ("if-range", ""), ("if-unmodified-since", ""), ("last-modified", ""),
    ("link", ""), ("location", ""), ("max-forwards", ""),
    ("proxy-authenticate", ""), ("proxy-authorization", ""), ("range", ""),
    ("referer", ""), ("refresh", ""), ("retry-after", ""), ("server", ""),
    ("set-cookie", ""), ("strict-transport-security", ""),
    ("transfer-encoding", ""), ("user-agent", ""), ("vary", ""), ("via", ""),
    ("www-authenticate", ""),
]


class HPACKError(Exception):
    pass


def _hpack_int_encode(value: int, prefix_bits: int, first: int) -> bytes:
    max_first = (1 << prefix_bits) - 1
    if value < max_first:
        return bytes([first | value])
    out = bytearray([first | max_first])
    value -= max_first
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _hpack_str_encode(raw: bytes) -> bytes:
    # string literal: Huffman flag (0) + 7-bit-prefix length + bytes
    return _hpack_int_encode(len(raw), 7, 0x00) + raw


def hpack_encode(headers) -> bytes:
    """Encode headers as literal-without-indexing, new names.

    Layout per header: 0x00 (4-bit index prefix = 0 -> new name),
    name string literal, value string literal.
    """
    out = bytearray()
    for name, value in headers:
        out += b"\x00"
        out += _hpack_str_encode(name.encode())
        out += _hpack_str_encode(value.encode())
    return bytes(out)


def _hpack_int_decode(buf: bytes, pos: int, prefix_bits: int):
    mask = (1 << prefix_bits) - 1
    value = buf[pos] & mask
    pos += 1
    if value < mask:
        return value, pos
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        value += (b & 0x7F) << shift
        if not (b & 0x80):
            return value, pos
        shift += 7


def _hpack_str_decode(buf: bytes, pos: int):
    huffman = bool(buf[pos] & 0x80)
    if huffman:
        raise HPACKError("server used Huffman-encoded HPACK; install the "
                         "h2 library for full decoding")
    length, pos = _hpack_int_decode(buf, pos, 7)
    return buf[pos:pos + length].decode("utf-8", "replace"), pos + length


def hpack_decode(buf: bytes):
    """Decode a header block -> list of (name, value)."""
    headers = []
    pos = 0
    while pos < len(buf):
        b = buf[pos]
        if b & 0x80:  # indexed
            idx, pos = _hpack_int_decode(buf, pos, 7)
            if idx < len(_HPACK_STATIC) and _HPACK_STATIC[idx]:
                headers.append(_HPACK_STATIC[idx])
            else:
                raise HPACKError("bad HPACK static index %d" % idx)
        elif b & 0x40:  # literal with incremental indexing
            idx, pos = _hpack_int_decode(buf, pos, 6)
            name = _HPACK_STATIC[idx][0] if idx else None
            if name is None:
                name, pos = _hpack_str_decode(buf, pos)
            value, pos = _hpack_str_decode(buf, pos)
            headers.append((name, value))
        elif b & 0x20:  # dynamic table size update: skip
            _, pos = _hpack_int_decode(buf, pos, 5)
        else:  # literal without indexing / never indexed
            idx, pos = _hpack_int_decode(buf, pos, 4)
            name = _HPACK_STATIC[idx][0] if idx else None
            if name is None:
                name, pos = _hpack_str_decode(buf, pos)
            value, pos = _hpack_str_decode(buf, pos)
            headers.append((name, value))
    return headers


# ---------------------------------------------------------------------------
# Minimal HTTP/2 connection (stdlib sockets)
# ---------------------------------------------------------------------------

_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

_F_DATA, _F_HEADERS, _F_SETTINGS, _F_PING = 0x0, 0x1, 0x4, 0x6
_FLAG_END_STREAM, _FLAG_END_HEADERS = 0x1, 0x4
_FLAG_ACK = 0x1


class H2Error(Exception):
    pass


class H2Connection:
    def __init__(self, host: str, port: int, use_tls: bool,
                 timeout: float = SOCKET_TIMEOUT):
        self.host, self.port, self.use_tls = host, port, use_tls
        self.timeout = timeout
        self.sock = None
        self._buf = bytearray()
        self._next_stream = 1

    def connect(self):
        raw = socket.create_connection((self.host, self.port),
                                       timeout=self.timeout)
        if self.use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2"])
            raw = ctx.wrap_socket(raw, server_hostname=self.host)
            if raw.selected_alpn_protocol() != "h2":
                raw.close()
                raise H2Error("server did not negotiate h2 via ALPN")
        self.sock = raw
        self.sock.settimeout(self.timeout)
        self._send_raw(_PREFACE)
        self._send_frame(_F_SETTINGS, 0, 0, b"")
        # wait for server SETTINGS, ack it
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            for ftype, flags, stream, payload in self._read_frames():
                if ftype == _F_SETTINGS and not (flags & _FLAG_ACK):
                    self._send_frame(_F_SETTINGS, _FLAG_ACK, 0, b"")
                    return
                if ftype == _F_PING and not (flags & _FLAG_ACK):
                    self._send_frame(_F_PING, _FLAG_ACK, 0, payload)
        raise H2Error("no SETTINGS from server")

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        self.sock = None

    # -- framing ------------------------------------------------------
    def _send_raw(self, data: bytes):
        self.sock.sendall(data)

    def _send_frame(self, ftype, flags, stream_id, payload: bytes):
        header = struct.pack("!I", len(payload))[1:] + bytes(
            [ftype, flags]) + struct.pack("!I", stream_id & 0x7FFFFFFF)
        self._send_raw(header + payload)

    def _recv(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise H2Error("connection closed")
            self._buf += chunk
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def _read_frames(self):
        """Yield (type, flags, stream, payload).

        SETTINGS and PING are ACKed inline but still yielded so the
        handshake can observe the server SETTINGS.
        """
        header = self._recv(9)
        length = struct.unpack("!I", b"\x00" + header[:3])[0]
        ftype, flags = header[3], header[4]
        stream = struct.unpack("!I", header[5:9])[0] & 0x7FFFFFFF
        payload = self._recv(length) if length else b""
        if ftype == _F_PING and not (flags & _FLAG_ACK):
            self._send_frame(_F_PING, _FLAG_ACK, 0, payload)
        elif ftype == _F_SETTINGS and not (flags & _FLAG_ACK):
            self._send_frame(_F_SETTINGS, _FLAG_ACK, 0, b"")
        yield ftype, flags, stream, payload

    # -- gRPC call -----------------------------------------------------
    def grpc_call(self, path: str, message: bytes):
        """Unary-style call over the reflection bidi stream.

        Returns (response_bytes, trailers_dict). Sends one request with
        END_STREAM; the server replies with DATA then trailers.
        """
        stream = self._next_stream
        self._next_stream += 2
        headers = [
            (":method", "POST"), (":scheme", "https" if self.use_tls else "http"),
            (":path", path), (":authority", self.host),
            ("content-type", "application/grpc"), ("te", "trailers"),
        ]
        self._send_frame(_F_HEADERS, _FLAG_END_HEADERS, stream,
                         hpack_encode(headers))
        grpc_msg = b"\x00" + struct.pack("!I", len(message)) + message
        self._send_frame(_F_DATA, _FLAG_END_STREAM, stream, grpc_msg)

        data_parts, trailers, stream_ended = [], {}, False
        deadline = time.time() + self.timeout
        while time.time() < deadline and not stream_ended:
            for ftype, flags, fstream, payload in self._read_frames():
                if fstream not in (0, stream):
                    continue
                if ftype == _F_HEADERS:
                    try:
                        for k, v in hpack_decode(payload):
                            trailers[k.lower()] = v
                    except HPACKError as exc:
                        raise H2Error(str(exc))
                    if flags & _FLAG_END_STREAM:
                        stream_ended = True
                elif ftype == _F_DATA:
                    data_parts.append(payload)
                    if flags & _FLAG_END_STREAM:
                        stream_ended = True
        raw = b"".join(data_parts)
        # strip the 5-byte gRPC frame headers
        msgs = []
        pos = 0
        while pos + 5 <= len(raw):
            ln = struct.unpack("!I", raw[pos + 1:pos + 5])[0]
            msgs.append(raw[pos + 5:pos + 5 + ln])
            pos += 5 + ln
        return b"".join(msgs), trailers


# ---------------------------------------------------------------------------
# High-level recon
# ---------------------------------------------------------------------------

def _try_connect(host: str, port: int):
    """TLS+h2 first, then h2c. Returns (conn, how) or raises H2Error."""
    last = None
    for use_tls, how in ((True, "tls+h2"), (False, "h2c")):
        conn = H2Connection(host, port, use_tls)
        try:
            conn.connect()
            return conn, how
        except Exception as exc:  # noqa: BLE001 - probe, keep last error
            last = exc
            conn.close()
    raise H2Error("no HTTP/2 endpoint (%s)" % last)


def enumerate_services(host: str, port: int):
    """Return (services, transport_note)."""
    conn, how = _try_connect(host, port)
    try:
        data, trailers = conn.grpc_call(REFLECTION_PATH, req_list_services())
        status = int(trailers.get("grpc-status", "0"))
        if status != 0:
            return [], "%s: reflection call failed grpc-status=%d (%s)" % (
                how, status, GRPC_STATUS_NAMES.get(status, "?"))
        return parse_list_services_response(data), how
    finally:
        conn.close()


def enumerate_methods(host: str, port: int, service: str):
    conn, how = _try_connect(host, port)
    try:
        data, trailers = conn.grpc_call(
            REFLECTION_PATH, req_file_containing_symbol(service))
        status = int(trailers.get("grpc-status", "0"))
        if status != 0:
            return []
        return parse_file_descriptor_response(data)
    finally:
        conn.close()


def probe_method_authz(host: str, port: int, full_method: str):
    """Call one method unauthenticated with an empty message.

    Returns (grpc_status_int, note). Status 0/3 = handler executed
    without auth (interesting); 16/7 = properly gated.
    """
    conn, how = _try_connect(host, port)
    try:
        _, trailers = conn.grpc_call("/" + full_method.lstrip("/"), b"")
        status = int(trailers.get("grpc-status", "-1"))
        return status, how
    finally:
        conn.close()


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
    parts = urllib.parse.urlsplit(
        target if "://" in target else "https://" + target)
    host = parts.hostname or target
    ports = [parts.port] if parts.port else list(DEFAULT_PORTS)
    findings = []
    for port in ports:
        try:
            services, how = enumerate_services(host, port)
        except H2Error as exc:
            findings.append(make_finding(
                NAME, "%s:%d" % (host, port), "info",
                "No gRPC reflection endpoint on %s:%d" % (host, port),
                "HTTP/2 + reflection probe failed: %s. If you know gRPC "
                "runs here on a custom setup, install the h2 library for "
                "full HTTP/2 coverage (flow control, Huffman HPACK)."
                % exc,
                evidence="error=%s" % exc, confidence="review"))
            continue
        if not services:
            findings.append(make_finding(
                NAME, "%s:%d" % (host, port), "info",
                "gRPC reachable but reflection disabled on %s:%d" % (host, port),
                "Connected via %s; the reflection call did not return "
                "services. Reflection is off (good), or methods need "
                "guessing from mobile apps / JS bundles." % how,
                evidence="transport=%s" % how, confidence="review"))
            continue
        findings.append(make_finding(
            NAME, "%s:%d" % (host, port), "medium",
            "gRPC reflection enabled: %d service(s) exposed" % len(services),
            "Server reflection is on via %s, disclosing the full API "
            "surface: %s. Reflection in production is an info leak that "
            "hands attackers every method signature." % (how, ", ".join(services)),
            evidence="services=%s transport=%s" % (services, how),
            confidence="strong",
            remediation="Disable gRPC reflection in production; publish "
                        ".proto files only where the program allows."))
        for svc in services:
            try:
                methods = enumerate_methods(host, port, svc)
            except H2Error:
                methods = []
            for package, svc_name, mlist in methods or [("", svc, [])]:
                qualified = ("%s.%s" % (package, svc_name)) if package else svc_name
                for m in mlist:
                    full = "%s/%s" % (qualified, m["name"])
                    try:
                        status, _ = probe_method_authz(host, port, full)
                    except H2Error:
                        continue
                    sname = GRPC_STATUS_NAMES.get(status, "status-%d" % status)
                    if status == 0:
                        findings.append(make_finding(
                            NAME, "%s:%d" % (host, port), "high",
                            "Unauthenticated gRPC call SUCCEEDED: %s" % full,
                            "Calling %s with no credentials and an empty "
                            "message returned grpc-status 0 (OK). The "
                            "method executed without authentication." % full,
                            evidence="grpc-status=0 method=%s" % full,
                            confidence="strong"))
                    elif status == 3:
                        findings.append(make_finding(
                            NAME, "%s:%d" % (host, port), "medium",
                            "gRPC method reachable without auth: %s (%s)" % (full, sname),
                            "Unauthenticated call to %s reached the handler "
                            "(INVALID_ARGUMENT on empty input proves the "
                            "method executed past any auth layer). Test "
                            "with valid-shaped messages as both low-priv "
                            "and anonymous callers." % full,
                            evidence="grpc-status=3 method=%s" % full,
                            confidence="strong"))
                    elif status in (7, 16):
                        pass  # properly gated; no finding
                    else:
                        findings.append(make_finding(
                            NAME, "%s:%d" % (host, port), "info",
                            "gRPC method %s returned %s unauthenticated" % (full, sname),
                            "Unauthenticated call to %s returned grpc-status "
                            "%d (%s); review whether this method should be "
                            "reachable without credentials." % (full, status, sname),
                            evidence="grpc-status=%d" % status,
                            confidence="review"))
    return findings
