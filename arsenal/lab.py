"""PENTRIX ARSENAL lab mode.

Local vulnerable fixtures for safe, offline practice of each module.
Every fixture is a minimal intentionally-vulnerable HTTP server bound to
127.0.0.1 only. Run ``arsenal lab up`` to start them all, practice with the
matching module, then stop with Ctrl+C.

Library code in this module never prints; only ``dispatch`` prints.
"""

import argparse
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
