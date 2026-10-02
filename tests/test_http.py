"""arsenal.http tests: stealth UA rotation, proxy, retry, read caps, pooling."""

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from arsenal import http as http_lib
from arsenal.context import make_ctx


class _Quiet(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass


@pytest.fixture()
def echo_server():
    """HTTP/1.1 server with controllable behaviors via path."""
    state = {"flaky": 0, "hits": 0, "last_ua": None, "last_path": None}

    class H(_Quiet):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            state["hits"] += 1
            state["last_ua"] = self.headers.get("User-Agent")
            state["last_path"] = self.path
            if self.path == "/flaky":
                state["flaky"] += 1
                if state["flaky"] <= 2:
                    body = b"boom"
                    self.send_response(500)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
            if self.path == "/teapot":
                body = b"nope"
                self.send_response(418)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == "/big":
                body = b"y" * 5000
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == "/ua":
                body = (self.headers.get("User-Agent") or "").encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.1)
    yield srv, state
    srv.shutdown()
    http_lib.close_pool()


def _url(srv, path="/"):
    return "http://127.0.0.1:%d%s" % (srv.server_address[1], path)


def test_basic_fetch_contract(echo_server):
    srv, _ = echo_server
    status, headers, body, final = http_lib.fetch(_url(srv))
    assert status == 200
    assert body == b"ok"
    assert final == _url(srv)
    assert "content-length" in headers  # lowercase keys


def test_stealth_ua_rotation(echo_server):
    srv, _ = echo_server
    ctx = make_ctx(config={"stealth": {"enabled": True, "min_delay": 0,
                                       "max_delay": 0, "rotate_ua": True}})
    seen = set()
    for _ in range(12):
        status, _, body, _ = http_lib.fetch(_url(srv, "/ua"), ctx=ctx)
        assert status == 200
        seen.add(body.decode())
    assert seen <= set(http_lib._UA_LIST)
    assert len(seen) > 1  # rotation actually varies the UA


def test_stealth_ua_is_browser_like(echo_server):
    srv, state = echo_server
    ctx = make_ctx(config={"stealth": {"enabled": True, "min_delay": 0,
                                       "max_delay": 0, "rotate_ua": True}})
    http_lib.fetch(_url(srv), ctx=ctx)
    assert state["last_ua"] in http_lib._UA_LIST
    assert "pentrix-arsenal" not in state["last_ua"]


def test_default_ua_without_ctx(echo_server):
    srv, state = echo_server
    http_lib.fetch(_url(srv))
    assert state["last_ua"] == "pentrix-arsenal/0.1.0"


def test_retry_then_success_on_500(echo_server):
    srv, state = echo_server
    ctx = make_ctx(config={"http": {"retries": 3, "backoff": 0.01}})
    status, _, body, _ = http_lib.fetch(_url(srv, "/flaky"), ctx=ctx)
    assert status == 200
    assert body == b"ok"
    assert state["flaky"] == 3  # two 500s, then the 200


def test_fatal_status_not_retried(echo_server):
    srv, state = echo_server
    before = state["hits"]
    ctx = make_ctx(config={"http": {"retries": 3, "backoff": 0.01}})
    status, _, _, _ = http_lib.fetch(_url(srv, "/teapot"), ctx=ctx)
    assert status == 418
    assert state["hits"] == before + 1  # exactly one request


def test_transport_failure_returns_zero_tuple():
    status, headers, body, final = http_lib.fetch(
        "http://127.0.0.1:1/", timeout=1)
    assert (status, headers, body) == (0, {}, b"")
    assert final == "http://127.0.0.1:1/"


def test_read_cap(echo_server):
    srv, _ = echo_server
    ctx = make_ctx(config={"http": {"max_read_bytes": 100}})
    status, _, body, _ = http_lib.fetch(_url(srv, "/big"), ctx=ctx)
    assert status == 200
    assert len(body) == 100


def test_keepalive_pool_reuse(echo_server):
    srv, _ = echo_server
    http_lib.close_pool()
    for _ in range(3):
        assert http_lib.fetch(_url(srv))[0] == 200
    stats = http_lib.pool_stats()
    assert sum(stats.values()) >= 1


def test_proxy_is_used(echo_server):
    srv, state = echo_server
    target = _url(srv, "/via-proxy")

    seen = {}

    class Proxy(_Quiet):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            seen["path"] = self.path  # absolute URI when proxying plain http
            body = b"proxied-body"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    proxy = ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    time.sleep(0.1)
    try:
        proxy_url = "http://127.0.0.1:%d" % proxy.server_address[1]
        status, _, body, _ = http_lib.fetch(target, proxy=proxy_url)
        assert status == 200
        assert body == b"proxied-body"
        assert seen["path"] == target  # absolute-form request via proxy
        assert state["hits"] == 0  # origin never contacted directly
    finally:
        proxy.shutdown()


def test_proxy_false_bypasses_env(echo_server, monkeypatch):
    srv, state = echo_server
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
    status, _, body, _ = http_lib.fetch(_url(srv), proxy=False, timeout=5)
    assert status == 200 and body == b"ok"
    assert state["hits"] == 1


def test_config_proxy_block(echo_server):
    srv, state = echo_server

    seen = {}

    class Proxy(_Quiet):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            seen["hit"] = True
            body = b"cfg-proxied"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    proxy = ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    time.sleep(0.1)
    try:
        proxy_url = "http://127.0.0.1:%d" % proxy.server_address[1]
        ctx = make_ctx(config={"proxy": {"enabled": True, "url": proxy_url,
                                         "no_proxy": ""}})
        status, _, body, _ = http_lib.fetch(_url(srv), ctx=ctx)
        assert status == 200 and body == b"cfg-proxied"
        assert seen.get("hit") is True
    finally:
        proxy.shutdown()
