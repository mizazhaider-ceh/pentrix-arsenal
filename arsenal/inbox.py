"""SELF-HOSTED BLIND CALLBACK INBOX.

`arsenal inbox [--port 8888] [--check]`

Starts a tiny HTTP listener (stdlib http.server) that logs every inbound
request to ~/.arsenal/inbox.jsonl as one JSON object per line:
    {"ts", "method", "path", "query", "headers", "body", "client"}

One one-line rich alert is printed per hit. `--check` prints recent hits
instead of listening. blind_url(base, tag) builds callback URLs.

Authorized engagements only: use this listener solely for targets you
have written permission to test.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from rich.console import Console

console = Console()

INBOX_DIR = Path.home() / ".arsenal"
INBOX_FILE = INBOX_DIR / "inbox.jsonl"

_lock = threading.Lock()


def blind_url(base, tag) -> str:
    """Build a callback URL: blind_url("http://x:8888", "xss-1")."""
    return f"{str(base).rstrip('/')}/{tag}"


def _log_hit(record: dict) -> None:
    INBOX_DIR.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, ensure_ascii=False)
    with _lock:
        with INBOX_FILE.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")


class _InboxHandler(BaseHTTPRequestHandler):
    server_version = "ArsenalInbox/1.0"

    def _handle(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        body = self.rfile.read(length).decode("utf-8", "replace") if length > 0 else ""
        path, _, query = self.path.partition("?")
        record = {
            "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "method": self.command,
            "path": path,
            "query": query,
            "headers": dict(self.headers),
            "body": body,
            "client": self.client_address[0],
        }
        _log_hit(record)
        console.print(
            f"[bold red]INBOX HIT[/] {record['ts']} "
            f"[cyan]{record['method']}[/] {record['path']}"
            + (f"?{record['query']}" if record["query"] else "")
            + f" from {record['client']}"
        )
        data = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle
    do_PATCH = _handle

    def log_message(self, *args, **kwargs):  # silence default logging
        return


def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return "127.0.0.1"


def _read_hits(limit: int):
    if not INBOX_FILE.exists():
        return []
    hits = []
    try:
        with INBOX_FILE.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    hits.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []
    return hits[-limit:] if limit else hits


def cmd_check(args, ctx) -> int:
    hits = _read_hits(args.limit)
    if not hits:
        console.print(f"[yellow]No inbox hits recorded yet ({INBOX_FILE}).[/]")
        return 0
    console.print(f"[bold]Recent inbox hits[/] (last {len(hits)}, {INBOX_FILE}):")
    for h in hits:
        console.print(
            f"  {h.get('ts', '?')} [cyan]{h.get('method', '?')}[/] "
            f"{h.get('path', '?')}"
            + (f"?{h.get('query')}" if h.get("query") else "")
            + f" from {h.get('client', '?')}"
        )
    return 0


def cmd_inbox(args, ctx) -> int:
    if args.check:
        return cmd_check(args, ctx)
    server = ThreadingHTTPServer(("0.0.0.0", args.port), _InboxHandler)
    server.daemon_threads = True
    actual_port = server.server_address[1]
    local_ip = _local_ip()
    console.print("[bold green]Arsenal blind callback inbox listening[/]")
    console.print(f"  Callback base URL: [bold cyan]http://{local_ip}:{actual_port}[/]")
    console.print(f"  Example tag URL:   http://{local_ip}:{actual_port}/xss-probe-1")
    console.print(f"  Log file:          {INBOX_FILE}")
    console.print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[yellow]Inbox stopped.[/]")
    finally:
        server.server_close()
    return 0


def add_parsers(sub):
    p = sub.add_parser(
        "inbox",
        help="Self-hosted blind callback (OOB) inbox",
        description=(
            "Start a local HTTP listener that logs every inbound request "
            "to ~/.arsenal/inbox.jsonl with a one-line alert per hit. "
            "--check prints recent hits instead of listening. "
            "Authorized engagements only."
        ),
    )
    p.add_argument("--port", type=int, default=8888,
                   help="Listen port (0 = pick an ephemeral port, default: 8888)")
    p.add_argument("--check", action="store_true",
                   help="Print recent hits from ~/.arsenal/inbox.jsonl instead of listening")
    p.add_argument("--limit", type=int, default=10,
                   help="Number of recent hits to show with --check (default: 10)")
    p.set_defaults(func=cmd_inbox)
    return p


def dispatch(args, ctx):
    func = getattr(args, "func", None)
    if callable(func):
        return func(args, ctx)
    raise ValueError("no command dispatch configured for inbox")

# ---------------------------------------------------------------------------
# TOKEN REGISTRY + POLLING API (added for the OOB correlation engine).
#
# arsenal.oob mints a unique token per payload and registers it here with
# the metadata of the exact request that carries it. When a callback lands
# in the inbox, poll_hits() + match_hits() link it back to that request.
# Registry lives in ~/.arsenal/oob_registry.json (survives restarts).
# ---------------------------------------------------------------------------

import secrets as _secrets

REGISTRY_FILE = INBOX_DIR / "oob_registry.json"


def mint_token(prefix="ax") -> str:
    """Mint a unique, low-collision OOB token."""
    return "%s-%s" % (prefix, _secrets.token_urlsafe(9))


def _read_registry() -> dict:
    if not REGISTRY_FILE.exists():
        return {}
    try:
        with REGISTRY_FILE.open(encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _write_registry(reg: dict) -> None:
    INBOX_DIR.mkdir(parents=True, exist_ok=True)
    tmp = REGISTRY_FILE.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(reg, fh, indent=2, ensure_ascii=False)
    tmp.replace(REGISTRY_FILE)


def register_token(token: str, meta: dict) -> None:
    """Register a minted token with the request metadata that carries it.

    meta should include: vuln_class, target, param, method, url,
    payload, ts, note.
    """
    reg = _read_registry()
    entry = dict(meta or {})
    entry.setdefault("token", token)
    entry.setdefault("ts", _dt.datetime.now(_dt.timezone.utc).isoformat())
    entry.setdefault("matched", False)
    reg[token] = entry
    _write_registry(reg)


def lookup_token(token: str):
    """Return the registry entry for a token, or None."""
    return _read_registry().get(token)


def list_tokens(only_unmatched=False) -> list[dict]:
    reg = _read_registry()
    entries = list(reg.values())
    if only_unmatched:
        entries = [e for e in entries if not e.get("matched")]
    return sorted(entries, key=lambda e: e.get("ts", ""))


def mark_matched(token: str, hit: dict) -> None:
    reg = _read_registry()
    if token in reg:
        reg[token]["matched"] = True
        reg[token]["matched_hit"] = {
            "ts": hit.get("ts"), "method": hit.get("method"),
            "path": hit.get("path"), "query": hit.get("query"),
            "client": hit.get("client"),
        }
        _write_registry(reg)


def poll_hits(since_ts: str | None = None, limit: int = 200) -> list[dict]:
    """Return inbox hits, newest last, optionally only after since_ts
    (ISO timestamp string)."""
    hits = _read_hits(limit if limit else 5000)
    if since_ts:
        hits = [h for h in hits if str(h.get("ts", "")) >= since_ts]
    return hits


def match_hits(hits: list[dict]) -> list[tuple[dict, dict]]:
    """Link inbox hits to registered tokens.

    A hit matches when a registered token appears in its path, query,
    body, or headers. Returns [(hit, registry_entry), ...]; matched
    tokens are marked once and never reported twice.
    """
    reg = _read_registry()
    if not reg:
        return []
    matches = []
    dirty = False
    for hit in hits:
        haystacks = [
            str(hit.get("path", "")),
            str(hit.get("query", "")),
            str(hit.get("body", "")),
        ]
        headers = hit.get("headers") or {}
        haystacks.extend(str(v) for v in headers.values())
        blob = "\n".join(haystacks)
        for token, entry in reg.items():
            if token and token in blob and not entry.get("matched"):
                matches.append((hit, dict(entry)))
                entry["matched"] = True
                entry["matched_hit"] = {
                    "ts": hit.get("ts"), "method": hit.get("method"),
                    "path": hit.get("path"), "query": hit.get("query"),
                    "client": hit.get("client"),
                }
                dirty = True
    if dirty:
        _write_registry(reg)
    return matches


def tokens_pending() -> int:
    return len(list_tokens(only_unmatched=True))
