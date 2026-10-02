"""WEB UI + READ-ONLY REST API for PENTRIX ARSENAL.

`arsenal serve [--port 8080] [--host 127.0.0.1]`

Standard library http.server only. No authentication is implemented, so the
server binds to 127.0.0.1 by default; use --host to listen on another
interface at your own risk.

Endpoints:
    GET /api/targets                -> ["target-a", "target-b"]
    GET /api/target/<t>/findings    -> findings.json list
    GET /api/target/<t>/summary     -> {"target": t, "counts": {...}, "total": n}
    GET /                          -> HTML dashboard (inline CSS/JS)

Library functions never print; the CLI entry point below may.
"""

from __future__ import annotations

import html
import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer


# --------------------------------------------------------------------------
# workspace readers (defensive; the workspace implementation is owned elsewhere)
# --------------------------------------------------------------------------

def _ws(ctx):
    return getattr(ctx, "workspace", None)


def list_targets(ctx):
    ws = _ws(ctx)
    if ws is None:
        return []
    for method in ("list_targets", "get_targets", "targets"):
        attr = getattr(ws, method, None)
        if callable(attr):
            try:
                t = attr()
            except Exception:
                continue
        elif isinstance(attr, (list, tuple, set, dict)):
            t = attr
        else:
            continue
        if t:
            return [str(x) for x in t]
    # Fallback: targets known via an in-memory findings mapping.
    findings_map = getattr(ws, "findings", None)
    if isinstance(findings_map, dict) and findings_map:
        return sorted(str(k) for k in findings_map.keys())
    # Fallback: subdirectories of a workspace root, if discoverable.
    root = None
    for attr in ("root", "base", "workspace_dir", "dir"):
        v = getattr(ws, attr, None)
        if isinstance(v, str) and os.path.isdir(v):
            root = v
            break
    if root is None:
        return []
    try:
        return sorted(d for d in os.listdir(root)
                      if os.path.isdir(os.path.join(root, d)) and not d.startswith("."))
    except Exception:
        return []


def get_findings(ctx, target):
    ws = _ws(ctx)
    if ws is None:
        return []
    for method in ("get_findings", "all_findings"):
        fn = getattr(ws, method, None)
        if callable(fn):
            try:
                f = fn(target)
                break
            except Exception:
                f = None
        else:
            f = None
    else:
        f = None
    if f is None:
        f = getattr(ws, "findings", None)
    if isinstance(f, dict):
        f = f.get(target, [])
    return [x for x in (f or []) if isinstance(x, dict)]


def target_summary(ctx, target):
    findings = get_findings(ctx, target)
    counts = {}
    for f in findings:
        sev = str(f.get("severity", "unknown")).lower()
        counts[sev] = counts.get(sev, 0) + 1
    return {"target": target, "counts": counts, "total": len(findings)}


# --------------------------------------------------------------------------
# dashboard page (self-contained HTML)
# --------------------------------------------------------------------------

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PENTRIX ARSENAL</title>
<style>
  :root { color-scheme: dark; }
  body { font-family: system-ui, sans-serif; background: #0d1117; color: #e6edf3; margin: 0; }
  header { padding: 16px 24px; background: #161b22; border-bottom: 1px solid #30363d; }
  header h1 { margin: 0; font-size: 20px; letter-spacing: 1px; }
  header h1 span { color: #58a6ff; }
  main { padding: 24px; max-width: 1200px; margin: 0 auto; }
  table { width: 100%; border-collapse: collapse; margin-top: 12px; }
  th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #30363d; }
  th { color: #8b949e; font-size: 12px; text-transform: uppercase; }
  tr[data-target] { cursor: pointer; }
  tr[data-target]:hover { background: #161b22; }
  .sev-critical { color: #ff7b72; font-weight: bold; }
  .sev-high { color: #ffa657; font-weight: bold; }
  .sev-medium { color: #d2a8ff; }
  .sev-low, .sev-info { color: #8b949e; }
  #findings { margin-top: 24px; display: none; }
  #findings h2 { font-size: 16px; }
  .muted { color: #8b949e; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
</style>
</head>
<body>
<header><h1>PENTRIX <span>ARSENAL</span> <span class="muted" style="font-size:12px">read-only dashboard</span></h1></header>
<main>
  <div class="card">
    <h2 style="margin-top:0">Targets</h2>
    <div id="targets"><span class="muted">Loading...</span></div>
  </div>
  <div id="findings" class="card">
    <h2 id="findings-title"></h2>
    <table id="findings-table">
      <thead><tr><th>Severity</th><th>Title</th><th>Module</th><th>Host</th></tr></thead>
      <tbody></tbody>
    </table>
  </div>
</main>
<script>
async function load() {
  const res = await fetch('/api/targets');
  const targets = await res.json();
  const box = document.getElementById('targets');
  if (!targets.length) { box.innerHTML = '<span class="muted">No targets yet.</span>'; return; }
  let rows = '';
  for (const t of targets) {
    const s = await (await fetch('/api/target/' + encodeURIComponent(t) + '/summary')).json();
    const c = s.counts || {};
    rows += '<tr data-target="' + t.replace(/"/g, '&quot;') + '">' +
      '<td>' + t.replace(/</g, '&lt;') + '</td>' +
      '<td class="sev-critical">' + (c.critical || 0) + '</td>' +
      '<td class="sev-high">' + (c.high || 0) + '</td>' +
      '<td class="sev-medium">' + (c.medium || 0) + '</td>' +
      '<td>' + (s.total || 0) + '</td></tr>';
  }
  box.innerHTML = '<table><thead><tr><th>Target</th><th>Critical</th><th>High</th><th>Medium</th><th>Total</th></tr></thead><tbody>' + rows + '</tbody></table>';
  box.querySelectorAll('tr[data-target]').forEach(tr => tr.addEventListener('click', () => showFindings(tr.dataset.target)));
}
async function showFindings(t) {
  const res = await fetch('/api/target/' + encodeURIComponent(t) + '/findings');
  const findings = await res.json();
  const box = document.getElementById('findings');
  document.getElementById('findings-title').textContent = 'Findings: ' + t;
  const tb = document.querySelector('#findings-table tbody');
  tb.innerHTML = findings.map(f => '<tr><td class="sev-' + String(f.severity || 'info').toLowerCase() + '">' +
    String(f.severity || 'info').replace(/</g, '&lt;') + '</td><td>' +
    String(f.title || '').replace(/</g, '&lt;') + '</td><td>' +
    String(f.module || '').replace(/</g, '&lt;') + '</td><td>' +
    String(f.host || '').replace(/</g, '&lt;') + '</td></tr>').join('');
  box.style.display = 'block';
  box.scrollIntoView();
}
load();
</script>
</body>
</html>
"""


# --------------------------------------------------------------------------
# HTTP server
# --------------------------------------------------------------------------

class ArsenalHandler(BaseHTTPRequestHandler):
    """Request handler; the active ctx is attached as self.server.arsenal_ctx."""

    server_version = "ArsenalServe/1.0"

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, text, status=200):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # keep the server quiet
        return

    def do_GET(self):
        ctx = getattr(self.server, "arsenal_ctx", None)
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/":
            self._send_html(DASHBOARD_HTML)
            return
        if path == "/api/targets":
            self._send_json(list_targets(ctx))
            return
        m = None
        if path.startswith("/api/target/"):
            rest = path[len("/api/target/"):]
            parts = rest.split("/", 1)
            if len(parts) == 2:
                name, action = urllib.parse.unquote(parts[0]), parts[1]
                if action == "findings":
                    self._send_json(get_findings(ctx, name))
                    return
                if action == "summary":
                    self._send_json(target_summary(ctx, name))
                    return
        self._send_json({"error": "not found"}, status=404)


def build_server(ctx, host="127.0.0.1", port=8080):
    """Create (but do not start) the HTTP server. Used by tests."""
    server = HTTPServer((host, port), ArsenalHandler)
    server.arsenal_ctx = ctx
    return server


def cmd_serve(args, ctx):
    server = build_server(ctx, host=args.host, port=args.port)
    addr = server.server_address
    print("PENTRIX ARSENAL dashboard at http://%s:%d/ (read-only, no auth)" % addr)
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("Warning: listening on a non-loopback interface with no authentication.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def add_parsers(sub):
    p = sub.add_parser("serve", help="Serve the read-only web dashboard and REST API")
    p.add_argument("--port", type=int, default=8080, help="Port to listen on (default 8080)")
    p.add_argument("--host", default="127.0.0.1",
                   help="Interface to bind (default 127.0.0.1; override at own risk)")
    p.set_defaults(func=cmd_serve)
    return p


def dispatch(args, ctx):
    func = getattr(args, "func", None)
    if callable(func):
        return func(args, ctx)
    raise ValueError("no command dispatch configured for serve")
