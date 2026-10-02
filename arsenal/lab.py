"""PENTRIX ARSENAL lab mode.

Local vulnerable fixtures for safe, offline practice of each module.
Every fixture is a minimal intentionally-vulnerable HTTP server bound to
127.0.0.1 only. Run ``arsenal lab up`` to start them all, practice with the
matching module, then stop with Ctrl+C.

Library code in this module never prints; only ``dispatch`` prints.
"""

import base64
import json
import re
import socket
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


# ---------------------------------------------------------------------------
# Quiet base: the stdlib handler logs every request to stderr, which we silence
# because library code must never print.
# ---------------------------------------------------------------------------

class QuietHandler:
    def log_message(self, fmt, *args):  # noqa: D102 - silence stdlib logging
        pass


def _parse_path(handler):
    """Split the request path into (route, query_dict)."""
    parsed = urllib.parse.urlparse(handler.path)
    return parsed.path, urllib.parse.parse_qs(parsed.query)


def _send(handler, body, status=200, content_type="text/html; charset=utf-8",
          extra_headers=None):
    data = body.encode("utf-8") if isinstance(body, str) else body
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(data)))
    for key, value in (extra_headers or {}).items():
        handler.send_header(key, value)
    handler.end_headers()
    handler.wfile.write(data)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# A pre-built alg=none token the JWT fixture accepts.
NONE_TOKEN = (
    _b64url(b'{"alg":"none","typ":"JWT"}')
    + "."
    + _b64url(b'{"sub":"lab-user","role":"user","iat":0}')
    + "."
)


# ---------------------------------------------------------------------------
# Fixtures: one handler class + port each.
# ---------------------------------------------------------------------------

class XSSFixtureHandler(QuietHandler, BaseHTTPRequestHandler):
    """8001: /search?q= reflects q unescaped."""

    def do_GET(self):
        route, query = _parse_path(self)
        if route == "/search":
            q = query.get("q", [""])[0]
            # Intentionally unescaped reflection.
            body = ("<html><body><h1>Search</h1>"
                    "<p>Results for: " + q + "</p></body></html>")
            _send(self, body)
        else:
            _send(self, "<html><body><a href='/search?q=test'>search</a>"
                        "</body></html>")


class SQLiFixtureHandler(QuietHandler, BaseHTTPRequestHandler):
    """8002: /item?id= returns a MySQL error when id contains a quote."""

    def do_GET(self):
        route, query = _parse_path(self)
        if route == "/item":
            item_id = query.get("id", [""])[0]
            if "'" in item_id:
                body = ("You have an error in your SQL syntax; check the "
                        "manual that corresponds to your MySQL server version "
                        "for the right syntax to use near ''%s'' at line 1"
                        % item_id)
                _send(self, body, status=500,
                       content_type="text/plain; charset=utf-8")
            else:
                _send(self, "<html><body><h1>Item %s</h1></body></html>"
                            % item_id)
        else:
            _send(self, "<html><body><a href='/item?id=1'>item 1</a>"
                        "</body></html>")


class HeadersFixtureHandler(QuietHandler, BaseHTTPRequestHandler):
    """8003: / serves Server: nginx/1.18 and no security headers."""

    def version_string(self):
        return "nginx/1.18"

    def do_GET(self):
        _send(self, "<html><body><h1>Welcome</h1></body></html>")


class JWTFixtureHandler(QuietHandler, BaseHTTPRequestHandler):
    """8004: /api accepts alg=none Bearer tokens and echoes Authorization.

    The landing page embeds a usable none-alg token.
    """

    def _handle_api(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[len("Bearer "):].strip()
            parts = token.split(".")
            if len(parts) == 3:
                try:
                    padded = parts[0] + "=" * (-len(parts[0]) % 4)
                    header = json.loads(
                        base64.urlsafe_b64decode(padded).decode("utf-8"))
                except Exception:
                    header = {}
                if header.get("alg") == "none":
                    _send(self, json.dumps({"ok": True,
                                            "echo_authorization": auth}),
                          content_type="application/json")
                    return
        _send(self, json.dumps({"ok": False, "error": "unauthorized"}),
              status=401, content_type="application/json")

    def do_GET(self):
        route, _ = _parse_path(self)
        if route == "/api":
            self._handle_api()
        else:
            body = ("<html><body><h1>JWT lab</h1>"
                    "<p>Try this token as <code>Authorization: Bearer "
                    "&lt;token&gt;</code> against <code>/api</code>:</p>"
                    "<code>" + NONE_TOKEN + "</code></body></html>")
            _send(self, body)

    def do_POST(self):
        route, _ = _parse_path(self)
        if route == "/api":
            self._handle_api()
        else:
            _send(self, "not found", status=404,
                   content_type="text/plain; charset=utf-8")


class RedirectFixtureHandler(QuietHandler, BaseHTTPRequestHandler):
    """8005: /go?url= issues a 302 to the url parameter."""

    def do_GET(self):
        route, query = _parse_path(self)
        if route == "/go":
            url = query.get("url", ["/"])[0]
            self.send_response(302)
            self.send_header("Location", url)
            self.end_headers()
        else:
            _send(self, "<html><body><a href='/go?url=https://example.com'>"
                        "go</a></body></html>")


class CORSFixtureHandler(QuietHandler, BaseHTTPRequestHandler):
    """8006: /api/data echoes the Origin into Access-Control-Allow-Origin."""

    def _handle(self):
        route, _ = _parse_path(self)
        if route == "/api/data":
            origin = self.headers.get("Origin", "*")
            _send(self, json.dumps({"data": "sensitive-ish"}),
                  content_type="application/json",
                  extra_headers={"Access-Control-Allow-Origin": origin,
                                 "Access-Control-Allow-Credentials": "true"})
        else:
            _send(self, "<html><body><h1>CORS lab</h1>"
                        "<p>GET /api/data</p></body></html>")

    def do_GET(self):
        self._handle()

    def do_OPTIONS(self):
        self._handle()


class SSTIFixtureHandler(QuietHandler, BaseHTTPRequestHandler):
    """8007: /hello?name= evaluates {{7*7}} to 49."""

    _SAFE = re.compile(r"^[0-9+\-*/().\s]+$")

    def _eval_expr(self, expr):
        expr = expr.strip()
        if not self._SAFE.match(expr):
            return "[blocked]"
        try:
            return str(eval(expr, {"__builtins__": {}}, {}))  # noqa: S307
        except Exception:
            return "[error]"

    def do_GET(self):
        route, query = _parse_path(self)
        if route == "/hello":
            name = query.get("name", ["guest"])[0]
            rendered = re.sub(r"\{\{(.*?)\}\}",
                              lambda m: self._eval_expr(m.group(1)), name)
            _send(self, "<html><body><h1>Hello " + rendered +
                        "</h1></body></html>")
        else:
            _send(self, "<html><body><a href='/hello?name=guest'>hello</a>"
                        "</body></html>")


class JSSecretsFixtureHandler(QuietHandler, BaseHTTPRequestHandler):
    """8008: / serves a page loading /app.js which holds a fake AWS key."""

    FAKE_KEY = "AKIAIOSFODNN7EXAMPLE"

    def do_GET(self):
        route, _ = _parse_path(self)
        if route == "/app.js":
            js = ("// bundled app\n"
                  'const AWS_ACCESS_KEY_ID = "%s";\n'
                  'const API_BASE = "https://api.example.com/v1";\n'
                  'console.log("app ready");\n' % self.FAKE_KEY)
            _send(self, js, content_type="application/javascript")
        else:
            _send(self, "<html><head><script src='/app.js'></script></head>"
                        "<body><h1>App</h1></body></html>")


class GraphQLFixtureHandler(QuietHandler, BaseHTTPRequestHandler):
    """8009: /graphql answers introspection with a tiny schema."""

    _SCHEMA = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "types": [
                    {"kind": "OBJECT", "name": "Query", "fields": [
                        {"name": "user",
                         "args": [{"name": "id", "type": {"name": "ID"}}]},
                        {"name": "version", "args": []},
                    ]},
                    {"kind": "OBJECT", "name": "User", "fields": [
                        {"name": "id", "args": []},
                        {"name": "email", "args": []},
                    ]},
                ],
            }
        }
    }

    def _handle_graphql(self, query_text):
        if "__schema" in query_text or "IntrospectionQuery" in query_text:
            _send(self, json.dumps(self._SCHEMA),
                  content_type="application/json")
        else:
            _send(self, json.dumps({"data": {"version": "lab-1.0"}}),
                  content_type="application/json")

    def do_POST(self):
        route, _ = _parse_path(self)
        if route != "/graphql":
            _send(self, "not found", status=404,
                   content_type="text/plain; charset=utf-8")
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        try:
            payload = json.loads(raw) if raw else {}
        except Exception:
            payload = {}
        self._handle_graphql(payload.get("query", ""))

    def do_GET(self):
        route, query = _parse_path(self)
        if route != "/graphql":
            _send(self, "<html><body><h1>GraphQL lab</h1>"
                        "<p>POST introspection to /graphql</p></body></html>")
            return
        self._handle_graphql(query.get("query", [""])[0])


class OAuthFixtureHandler(QuietHandler, BaseHTTPRequestHandler):
    """8010: /oauth/authorize redirects to any redirect_uri."""

    def do_GET(self):
        route, query = _parse_path(self)
        if route == "/oauth/authorize":
            redirect_uri = query.get("redirect_uri", ["/"])[0]
            sep = "&" if "?" in redirect_uri else "?"
            self.send_response(302)
            self.send_header("Location",
                             "%s%scode=labcode123" % (redirect_uri, sep))
            self.end_headers()
        else:
            _send(self, "<html><body><a href='/oauth/authorize?"
                        "client_id=lab&redirect_uri=https://client.example/cb'>"
                        "login with lab-oauth</a></body></html>")


class TechFixtureHandler(QuietHandler, BaseHTTPRequestHandler):
    """8011: technology markers - Werkzeug server banner, Express
    X-Powered-By, jQuery + GraphQL markers in HTML, CloudFront header."""

    def version_string(self):
        return "Werkzeug/2.3.7"

    def do_GET(self):
        body = ("<html><head>"
                '<script src="/static/jquery-3.7.1.min.js"></script>'
                "</head><body><h1>Shop</h1>"
                '<a href="/graphql">API</a>'
                "</body></html>")
        _send(self, body, extra_headers={
            "X-Powered-By": "Express",
            "X-Amz-Cf-Id": "lab-cf-id-123",
        })


class FuzzFixtureHandler(QuietHandler, BaseHTTPRequestHandler):
    """8012: /probe?x= reflects x and evaluates {{7*7}} to 49."""

    def do_GET(self):
        route, query = _parse_path(self)
        if route == "/probe":
            x = query.get("x", ["1"])[0]
            rendered = x.replace("{{7*7}}", "49")
            body = ("<html><body><p>probe result: " + rendered +
                    "</p></body></html>")
            _send(self, body)
        else:
            _send(self, "<html><body><a href='/probe?x=1'>probe</a>"
                        "</body></html>")


class ParamminerFixtureHandler(QuietHandler, BaseHTTPRequestHandler):
    """8013: /page changes when a hidden 'debug' parameter is present."""

    def do_GET(self):
        route, query = _parse_path(self)
        if route == "/page":
            if "debug" in query:
                # A realistically verbose debug dump: well over the
                # module's length-delta threshold versus the baseline.
                lines = ["<html><body><h1>Page</h1>", "<p>debug mode on</p>",
                         "<pre>"]
                for i in range(40):
                    lines.append("debug trace line %d: handler=page "
                                 "state=verbose-ok\n" % i)
                lines.append("</pre></body></html>")
                _send(self, "".join(lines))
            else:
                _send(self, "<html><body><h1>Page</h1>"
                            "<p>normal content</p></body></html>")
        else:
            _send(self, "<html><body><a href='/page'>page</a></body></html>")


class HostheaderFixtureHandler(QuietHandler, BaseHTTPRequestHandler):
    """8014: / reflects the Host header value into the body."""

    def do_GET(self):
        host = self.headers.get("Host", "")
        body = ("<html><body><h1>Welcome</h1>"
                "<p>You reached host: " + host + "</p></body></html>")
        _send(self, body)


class JSIntelFixtureHandler(QuietHandler, BaseHTTPRequestHandler):
    """8015: / loads /app.js which calls /api/v1/users; the endpoint
    returns JSON holding an email address (a sensitivity signal)."""

    def do_GET(self):
        route, _ = _parse_path(self)
        if route == "/app.js":
            js = ('// app bundle\n'
                  'fetch("/api/v1/users").then(r => r.json());\n')
            _send(self, js, content_type="application/javascript")
        elif route == "/api/v1/users":
            _send(self, '[{"id": 1, "email": "admin@lab.local"}]',
                  content_type="application/json")
        else:
            _send(self, "<html><head><script src='/app.js'></script></head>"
                        "<body><h1>Users app</h1></body></html>")


class NVDMockFixtureHandler(QuietHandler, BaseHTTPRequestHandler):
    """8016: minimal NVD 2.0-shaped response for offline cve tests."""

    _CVE = {
        "id": "CVE-2026-0001",
        "published": "2026-01-15T00:00:00.000",
        "descriptions": [
            {"lang": "en",
             "value": "Lab fixture vulnerability used for offline testing."}
        ],
        "metrics": {
            "cvssMetricV31": [
                {"cvssData": {"version": "3.1", "baseScore": 7.5},
                 "source": "lab"}
            ]
        },
        "references": [{"url": "https://example.com/lab"}],
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
    }

    def do_GET(self):
        route, _ = _parse_path(self)
        if route.startswith("/rest/json/cves/2.0"):
            _send(self, json.dumps(
                {"vulnerabilities": [{"cve": self._CVE}]}),
                content_type="application/json")
        else:
            _send(self, "not found", status=404,
                   content_type="text/plain; charset=utf-8")


# name -> (port, handler class, example path, description)
FIXTURES = {
    "xss": (8001, XSSFixtureHandler, "/search?q=<payload>",
            "Reflected XSS: q is reflected unescaped"),
    "sqli": (8002, SQLiFixtureHandler, "/item?id=1'",
             "SQLi: a quote in id triggers a MySQL error"),
    "headers": (8003, HeadersFixtureHandler, "/",
                "Headers/tech: Server nginx/1.18, no security headers"),
    "jwt": (8004, JWTFixtureHandler, "/api",
            "JWT: alg=none Bearer token accepted, Authorization echoed"),
    "redirect": (8005, RedirectFixtureHandler, "/go?url=https://example.com",
                 "Open redirect: 302 to the url parameter"),
    "cors": (8006, CORSFixtureHandler, "/api/data",
             "CORS: Origin echoed into Access-Control-Allow-Origin"),
    "ssti": (8007, SSTIFixtureHandler, "/hello?name={{7*7}}",
             "SSTI: {{7*7}} evaluates to 49"),
    "jssecrets": (8008, JSSecretsFixtureHandler, "/app.js",
                  "JS secrets: fake AWS key in the bundle"),
    "graphql": (8009, GraphQLFixtureHandler, "/graphql",
                "GraphQL: introspection enabled"),
    "oauth": (8010, OAuthFixtureHandler,
              "/oauth/authorize?redirect_uri=https://client.example/cb",
              "OAuth: redirect_uri is not validated"),
    "tech": (8011, TechFixtureHandler, "/",
             "Tech: Werkzeug banner, Express, jQuery, GraphQL, CloudFront"),
    "fuzz": (8012, FuzzFixtureHandler, "/probe?x=1",
             "Fuzz: x is reflected, {{7*7}} evaluates to 49"),
    "paramminer": (8013, ParamminerFixtureHandler, "/page",
                   "Paramminer: hidden 'debug' parameter changes the page"),
    "hostheader": (8014, HostheaderFixtureHandler, "/",
                   "Host header: Host value reflected in the body"),
    "jsintel": (8015, JSIntelFixtureHandler, "/api/v1/users",
                "JS intel: /app.js calls /api/v1/users (email in JSON)"),
    "cve": (8016, NVDMockFixtureHandler, "/rest/json/cves/2.0",
            "CVE: mock NVD 2.0 response (offline testing)"),
}


# ---------------------------------------------------------------------------
# LabServer manager
# ---------------------------------------------------------------------------

class LabServer:
    """One fixture server running in a background thread."""

    def __init__(self, name, port, handler):
        self.name = name
        self.port = port
        self.handler = handler
        self._server = None
        self._thread = None

    def start(self):
        self._server = ThreadingHTTPServer(("127.0.0.1", self.port),
                                           self.handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.1},
            daemon=True, name="lab-%s" % self.name)
        self._thread.start()
        return self

    def stop(self):
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None

    @property
    def running(self):
        return self._thread is not None and self._thread.is_alive()


class LabManager:
    """Starts and stops every fixture."""

    def __init__(self):
        self.servers = [LabServer(name, port, handler)
                        for name, (port, handler, _, _) in FIXTURES.items()]

    def start_all(self):
        """Start every fixture. Returns {name: port} once all accept traffic."""
        for server in self.servers:
            server.start()
        for server in self.servers:
            _wait_up(server.port)
        return {server.name: server.port for server in self.servers}

    def stop_all(self):
        for server in self.servers:
            server.stop()


def _wait_up(port, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("lab fixture on port %d did not start" % port)


class BannerTCPServer:
    """Minimal raw-TCP server that sends a banner per connection.

    Used for the portscan check (portscan speaks raw TCP, not HTTP, so it
    cannot use the HTTP fixtures above).
    """

    def __init__(self, banner=b"SSH-2.0-OpenSSH_lab\r\n"):
        self.banner = banner
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(5)
        self._sock.settimeout(0.5)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True,
                                        name="lab-tcp-banner")

    def _serve(self):
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            try:
                conn.sendall(self.banner)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def start(self):
        self._thread.start()
        _wait_up(self.port)
        return self

    def stop(self):
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2)


# ---------------------------------------------------------------------------
# Automated harness: start fixture, run matching module, assert a finding.
#
# run_check(name) starts only the fixture(s) a check needs, runs the module
# through the defensive pipeline.run_module() wrapper, and asserts the
# expected finding shows up. run_all_checks() runs every check and returns
# a {name: (ok, detail)} mapping. The pytest suite in tests/ drives this.
# ---------------------------------------------------------------------------

def make_lab_ctx(**overrides):
    """Ctx for lab checks: short timeouts, intrusive modules allowed."""
    from arsenal.context import make_ctx
    config = {"timeout": 5}
    config.update(overrides.pop("config", {}) or {})
    return make_ctx(config=config, safe_mode=False, allow_intrusive=True,
                    **overrides)


def _check_target_local_hashes():
    import os
    import tempfile
    fd, path = tempfile.mkstemp(prefix="lab-hashes-", suffix=".txt")
    with os.fdopen(fd, "w") as fh:
        fh.write("5d41402abc4b2a76b9719d911017c592\n")
    return path


def _check_target_local_secrets():
    import os
    import tempfile
    directory = tempfile.mkdtemp(prefix="lab-secrets-")
    with open(os.path.join(directory, "config.py"), "w") as fh:
        fh.write('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    return directory


# check name -> spec. fixture names refer to FIXTURES; target may contain
# {port}. min_findings and title_contains drive the assertion.
CHECKS = {
    "xss": {"fixture": "xss", "module": "xss",
            "target": "http://127.0.0.1:{port}/search?q=test",
            "min_findings": 1, "title_contains": "Reflected XSS"},
    "sqli": {"fixture": "sqli", "module": "sqli",
             "target": "http://127.0.0.1:{port}/item?id=1",
             "min_findings": 1, "title_contains": "SQL injection"},
    "headers": {"fixture": "headers", "module": "headers",
                "target": "http://127.0.0.1:{port}/",
                "min_findings": 1,
                "title_contains": "Strict-Transport-Security"},
    "jwt": {"fixture": None, "module": "jwt",
            "target": NONE_TOKEN,
            "min_findings": 1, "title_contains": "none"},
    "redirect": {"fixture": "redirect", "module": "redirect",
                 "target": "http://127.0.0.1:{port}/go?url=https://example.com",
                 "min_findings": 1, "title_contains": "Open redirect"},
    "cors": {"fixture": "cors", "module": "cors",
             "target": "http://127.0.0.1:{port}/api/data",
             "min_findings": 1, "title_contains": "CORS"},
    "ssti": {"fixture": "ssti", "module": "ssti",
             "target": "http://127.0.0.1:{port}/hello?name=guest",
             "min_findings": 1, "title_contains": "template injection"},
    "jssecrets": {"fixture": "jssecrets", "module": "jssecrets",
                  "target": "http://127.0.0.1:{port}/",
                  "min_findings": 1, "title_contains": "AWS Access Key ID"},
    "graphql": {"fixture": "graphql", "module": "graphql",
                "target": "http://127.0.0.1:{port}/graphql",
                "min_findings": 1, "title_contains": "introspection"},
    "oauth": {"fixture": "oauth", "module": "oauth",
              "target": "http://127.0.0.1:{port}/",
              "min_findings": 1, "title_contains": "redirect_uri"},
    "tech": {"fixture": "tech", "module": "tech",
             "target": "http://127.0.0.1:{port}/",
             "min_findings": 3, "title_contains": "GraphQL"},
    "fuzz": {"fixture": "fuzz", "module": "fuzz",
             "target": "http://127.0.0.1:{port}/probe?x=1",
             "min_findings": 1, "title_contains": "Anomalous parameter"},
    "paramminer": {"fixture": "paramminer", "module": "paramminer",
                   "target": "http://127.0.0.1:{port}/page",
                   "min_findings": 1, "title_contains": "debug"},
    "hostheader": {"fixture": "hostheader", "module": "hostheader",
                   "target": "http://127.0.0.1:{port}/",
                   "min_findings": 1, "title_contains": "Host header"},
    "jsintel": {"fixture": "jsintel", "module": "jsintel",
                "target": "http://127.0.0.1:{port}/",
                "min_findings": 1,
                "title_contains": "Unauthenticated API endpoint"},
    "portscan": {"fixture": "tcp-banner", "module": "portscan",
                 "target": "127.0.0.1",
                 "min_findings": 1, "title_contains": "Open port"},
    "hashid": {"fixture": "local-file", "module": "hashid",
               "target_builder": _check_target_local_hashes,
               "min_findings": 1, "title_contains": "Hash identified"},
    "phish": {"fixture": None, "module": "phish",
              "target": "http://93.184.216.34@secure-login-verify-account.com/login",
              "min_findings": 1, "title_contains": "Phishing indicator"},
    "secrets": {"fixture": "local-dir", "module": "secrets",
                "target_builder": _check_target_local_secrets,
                "min_findings": 1, "title_contains": "AWS Access Key ID"},
    "cve": {"fixture": "cve", "module": "cve",
            "target": "lab-fixture",
            "min_findings": 1, "title_contains": "CVE-2026-0001",
            "patch_nvd_base": True},
}


def run_check(name, timeout=60):
    """Run one lab check. Returns (ok: bool, detail: str). Never raises."""
    from arsenal.pipeline import run_module
    spec = CHECKS.get(name)
    if spec is None:
        return False, "unknown check: %r" % (name,)
    servers = []
    tcp_server = None
    target = spec.get("target")
    try:
        fixture = spec.get("fixture")
        if fixture == "tcp-banner":
            tcp_server = BannerTCPServer().start()
            target = "127.0.0.1"
        elif fixture == "local-file":
            target = _check_target_local_hashes()
        elif fixture == "local-dir":
            target = _check_target_local_secrets()
        elif fixture:
            port, handler, _example, _desc = FIXTURES[fixture]
            server = LabServer(fixture, port, handler).start()
            servers.append(server)
            _wait_up(port)
            target = (target or "").format(port=port)

        if spec.get("target_builder"):
            target = spec["target_builder"]()

        ctx = make_lab_ctx()
        if name == "portscan" and tcp_server is not None:
            ctx.config["portscan_ports"] = [tcp_server.port]

        mod = __import__("arsenal.modules.%s_mod" % spec["module"],
                         fromlist=["*"])
        saved_nvd_base = getattr(mod, "NVD_BASE", None)
        if spec.get("patch_nvd_base"):
            # Point the module at the mock NVD fixture instead of nvd.nist.gov.
            port = FIXTURES["cve"][0]
            mod.NVD_BASE = "http://127.0.0.1:%d/rest/json/cves/2.0" % port
        result = run_module(mod, target, ctx)
        if spec.get("patch_nvd_base"):
            mod.NVD_BASE = saved_nvd_base
        findings = result["findings"]
        titles = [str(f.get("title", "")) for f in findings]
        want = spec.get("title_contains", "")
        matched = [t for t in titles if want.lower() in t.lower()]
        if len(findings) >= spec.get("min_findings", 1) and matched:
            return True, "%d finding(s), matched %r" % (len(findings),
                                                        matched[0])
        return False, ("expected >=%d findings with %r in the title, got %d: %s"
                       % (spec.get("min_findings", 1), want, len(findings),
                          titles[:3]))
    except Exception as exc:
        return False, "check raised: %s: %s" % (type(exc).__name__, exc)
    finally:
        for server in servers:
            try:
                server.stop()
            except Exception:
                pass
        if tcp_server is not None:
            try:
                tcp_server.stop()
            except Exception:
                pass


def run_all_checks():
    """Run every check in CHECKS. Returns {name: (ok, detail)}."""
    results = {}
    for name in CHECKS:
        results[name] = run_check(name)
    return results


_MANAGER = None


def start_all():
    """Start all fixtures in background threads. Returns {name: port}."""
    global _MANAGER
    _MANAGER = LabManager()
    return _MANAGER.start_all()


def stop_all():
    """Stop all fixtures started by start_all()."""
    global _MANAGER
    if _MANAGER is not None:
        _MANAGER.stop_all()
        _MANAGER = None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_table(mapping=None):
    rows = []
    for name, (port, _, example, desc) in FIXTURES.items():
        url = "http://127.0.0.1:%d%s" % (port, example)
        rows.append((name, url, desc))
    try:
        from rich.console import Console
        from rich.table import Table
        table = Table(title="PENTRIX ARSENAL lab targets")
        table.add_column("Fixture")
        table.add_column("Target URL")
        table.add_column("Practice")
        for row in rows:
            table.add_row(*row)
        Console().print(table)
    except Exception:
        print("Fixture | Target URL | Practice")
        for row in rows:
            print(" | ".join(row))


def add_parsers(sub):
    p = sub.add_parser("lab", help="Local vulnerable practice targets")
    lab_sub = p.add_subparsers(dest="lab_cmd", required=True)
    lab_sub.add_parser("up",
                       help="Start all lab fixtures (foreground, Ctrl+C to stop)")
    lab_sub.add_parser("down",
                       help="Stop lab fixtures (note: up runs in foreground)")
    lab_sub.add_parser("list",
                       help="List lab fixtures without starting them")
    p.set_defaults(func=dispatch)
    return p


def dispatch(args, ctx=None):
    cmd = args.lab_cmd
    if cmd == "list":
        _print_table()
    elif cmd == "up":
        mapping = start_all()
        _print_table(mapping)
        print("Lab is up. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            stop_all()
        print("Lab stopped.")
    elif cmd == "down":
        print("Lab 'up' runs in the foreground: press Ctrl+C in that "
              "terminal to stop it. There is nothing to shut down.")
    else:
        raise ValueError("unknown lab command: %r" % (cmd,))
