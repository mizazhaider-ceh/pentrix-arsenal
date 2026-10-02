"""WEB UI + READ-ONLY REST API for PENTRIX ARSENAL.

`arsenal serve [--port 8080] [--host 127.0.0.1]`

Standard library http.server only. No authentication is implemented, so the
server binds to 127.0.0.1 by default; use --host to listen on another
interface at your own risk.

Endpoints:
    GET /api/targets                -> ["target-a", "target-b"]
    GET /api/target/<t>/findings    -> findings.json list
    GET /api/target/<t>/summary     -> {"target": t, "counts": {...}, "total": n}
    GET /api/target/<t>/crm        -> findings with id/status/program/payout
    GET /api/pipeline/<t>           -> live pipeline_state.json (hunt view)
    GET /api/trends                 -> {"labels": [...], "series": {...}}
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


def _target_dir(ctx, target):
    ws = _ws(ctx)
    if ws is not None and hasattr(ws, "path"):
        try:
            return ws.path(target)
        except Exception:
            pass
    return os.path.join(os.path.expanduser("~"), ".arsenal", "workspace",
                        str(target))


def pipeline_state(ctx, target):
    """Live hunt view data: the pipeline's persisted state for a target."""
    path = os.path.join(_target_dir(ctx, target), "pipeline_state.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return {
                "target": data.get("target", target),
                "ts": data.get("ts"),
                "completed": len(data.get("completed", [])),
                "queued": len(data.get("queue", [])),
                "hosts": data.get("hosts", []),
                "findings": len(data.get("findings", [])),
                "queue": data.get("queue", [])[:50],
            }
    except (OSError, ValueError):
        pass
    return {"target": target, "ts": None, "completed": 0, "queued": 0,
            "hosts": [], "findings": 0, "queue": []}


def crm_board(ctx, target):
    """CRM board data: findings with lifecycle fields."""
    out = []
    for f in get_findings(ctx, target):
        out.append({
            "id": f.get("id", "-"),
            "severity": str(f.get("severity", "info")),
            "status": str(f.get("status", "found")),
            "program": str(f.get("program", "-") or "-"),
            "payout": f.get("payout"),
            "title": str(f.get("title", "")),
            "module": str(f.get("module", "")),
        })
    return {"target": target, "findings": out}


def trends_data(ctx):
    """Cross-hunt trend series for the dashboard chart."""
    try:
        from arsenal import report as report_mod
        labels, series = report_mod._trend_data(ctx)
        return {"labels": labels, "series": series}
    except Exception:
        return {"labels": [], "series": {}}


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
  nav.tabs { display: flex; gap: 4px; padding: 0 24px; background: #161b22; border-bottom: 1px solid #30363d; }
  nav.tabs button { background: none; border: none; color: #8b949e; padding: 12px 16px; cursor: pointer; font-size: 14px; }
  nav.tabs button.active { color: #58a6ff; border-bottom: 2px solid #58a6ff; }
  main { padding: 24px; max-width: 1200px; margin: 0 auto; }
  .tab { display: none; } .tab.active { display: block; }
  table { width: 100%; border-collapse: collapse; margin-top: 12px; }
  th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #30363d; font-size: 14px; }
  th { color: #8b949e; font-size: 12px; text-transform: uppercase; }
  tr[data-target] { cursor: pointer; }
  tr[data-target]:hover { background: #161b22; }
  .sev-critical { color: #ff7b72; font-weight: bold; }
  .sev-high { color: #ffa657; font-weight: bold; }
  .sev-medium { color: #d2a8ff; }
  .sev-low, .sev-info { color: #8b949e; }
  .muted { color: #8b949e; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
  .filters { margin: 12px 0; display: flex; gap: 8px; flex-wrap: wrap; }
  .filters button { background: #21262d; border: 1px solid #30363d; color: #e6edf3; border-radius: 20px; padding: 6px 14px; cursor: pointer; }
  .filters button.active { background: #1f6feb; border-color: #1f6feb; }
  .pill { display: inline-block; font-size: 11px; padding: 2px 10px; border-radius: 12px; background: #21262d; border: 1px solid #30363d; }
  .st-paid { background: #0f3d2e; border-color: #1f6f4a; color: #7ee2b0; }
  .st-accepted { background: #1c2f5e; border-color: #2f5fc0; color: #a8c5ff; }
  .st-reported { background: #3d2f10; border-color: #8a6d1f; color: #ffd98a; }
  .st-duplicate { background: #2d2d2d; color: #9a9a9a; }
  select, input { background: #0d1117; color: #e6edf3; border: 1px solid #30363d; border-radius: 6px; padding: 8px; }
  .live-dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; background: #3fb950; margin-right: 6px; animation: pulse 1.5s infinite; }
  @keyframes pulse { 50% { opacity: 0.4; } }
  #trend-chart { width: 100%; }
</style>
</head>
<body>
<header><h1>PENTRIX <span>ARSENAL</span> <span class="muted" style="font-size:12px">read-only dashboard</span></h1></header>
<nav class="tabs">
  <button class="active" data-tab="targets">Targets</button>
  <button data-tab="live">Live hunt</button>
  <button data-tab="findings">Findings</button>
  <button data-tab="crm">CRM board</button>
  <button data-tab="trends">Trends</button>
</nav>
<main>
  <div id="tab-targets" class="tab active">
    <div class="card"><h2 style="margin-top:0">Targets</h2><div id="targets"><span class="muted">Loading...</span></div></div>
  </div>
  <div id="tab-live" class="tab">
    <div class="card">
      <h2 style="margin-top:0"><span class="live-dot"></span>Live hunt</h2>
      <div><select id="live-target"><option value="">select a target</option></select>
      <span class="muted" style="margin-left:8px">polls pipeline state every 3s</span></div>
      <div id="live-view" style="margin-top:12px"><span class="muted">No target selected.</span></div>
    </div>
  </div>
  <div id="tab-findings" class="tab">
    <div class="card">
      <h2 style="margin-top:0">Findings browser</h2>
      <div><select id="findings-target"><option value="">select a target</option></select></div>
      <div class="filters" id="sev-filters">
        <button data-sev="all" class="active">all</button>
        <button data-sev="critical">critical</button>
        <button data-sev="high">high</button>
        <button data-sev="medium">medium</button>
        <button data-sev="low">low</button>
        <button data-sev="info">info</button>
      </div>
      <div><input id="findings-search" placeholder="filter by title/module..." style="width:100%"></div>
      <table id="findings-table"><thead><tr><th>Severity</th><th>Title</th><th>Module</th><th>Host</th><th>Verdict</th></tr></thead><tbody></tbody></table>
    </div>
  </div>
  <div id="tab-crm" class="tab">
    <div class="card">
      <h2 style="margin-top:0">CRM board</h2>
      <div><select id="crm-target"><option value="">select a target</option></select></div>
      <table id="crm-table"><thead><tr><th>ID</th><th>Severity</th><th>Status</th><th>Program</th><th>Payout</th><th>Title</th></tr></thead><tbody></tbody></table>
    </div>
  </div>
  <div id="tab-trends" class="tab">
    <div class="card"><h2 style="margin-top:0">Hunt trends</h2><div id="trend-chart"><span class="muted">Loading...</span></div></div>
  </div>
</main>
<script>
const $ = id => document.getElementById(id);
const esc = s => String(s == null ? '' : s).replace(/</g, '&lt;').replace(/>/g, '&gt;');
let allFindings = [], sevFilter = 'all', searchFilter = '';

document.querySelectorAll('nav.tabs button').forEach(b => b.addEventListener('click', () => {
  document.querySelectorAll('nav.tabs button').forEach(x => x.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  b.classList.add('active');
  $('tab-' + b.dataset.tab).classList.add('active');
  if (b.dataset.tab === 'trends') loadTrends();
}));

async function load() {
  const targets = await (await fetch('/api/targets')).json();
  for (const sel of ['live-target', 'findings-target', 'crm-target']) {
    const el = $(sel);
    el.innerHTML = '<option value="">select a target</option>' +
      targets.map(t => '<option value="' + esc(t) + '">' + esc(t) + '</option>').join('');
  }
  const box = $('targets');
  if (!targets.length) { box.innerHTML = '<span class="muted">No targets yet.</span>'; return; }
  let rows = '';
  for (const t of targets) {
    const s = await (await fetch('/api/target/' + encodeURIComponent(t) + '/summary')).json();
    const c = s.counts || {};
    rows += '<tr data-target="' + esc(t) + '"><td>' + esc(t) + '</td>' +
      '<td class="sev-critical">' + (c.critical || 0) + '</td>' +
      '<td class="sev-high">' + (c.high || 0) + '</td>' +
      '<td class="sev-medium">' + (c.medium || 0) + '</td>' +
      '<td>' + (s.total || 0) + '</td></tr>';
  }
  box.innerHTML = '<table><thead><tr><th>Target</th><th>Critical</th><th>High</th><th>Medium</th><th>Total</th></tr></thead><tbody>' + rows + '</tbody></table>';
}

async function pollLive() {
  const t = $('live-target').value;
  if (!t) return;
  const s = await (await fetch('/api/pipeline/' + encodeURIComponent(t))).json();
  const active = s.queued > 0;
  $('live-view').innerHTML =
    '<p>' + (active ? '<span class="live-dot"></span><strong>hunt running</strong>' : '<strong>hunt idle</strong>') +
    ' <span class="muted">last update: ' + esc(s.ts || 'never') + '</span></p>' +
    '<p>Events completed: <strong>' + s.completed + '</strong> &nbsp; queued: <strong>' + s.queued + '</strong>' +
    ' &nbsp; hosts: <strong>' + s.hosts.length + '</strong> &nbsp; findings: <strong>' + s.findings + '</strong></p>' +
    (s.queue.length ? '<p class="muted">Next up:</p><ul>' +
      s.queue.slice(0, 8).map(e => '<li>' + esc(e.kind) + ' ' + esc(JSON.stringify(e.value)).slice(0, 80) + '</li>').join('') + '</ul>' : '');
}
setInterval(pollLive, 3000);
$('live-target').addEventListener('change', pollLive);

function renderFindings() {
  const tb = document.querySelector('#findings-table tbody');
  const q = searchFilter.toLowerCase();
  const rows = allFindings.filter(f =>
    (sevFilter === 'all' || String(f.severity || 'info').toLowerCase() === sevFilter) &&
    (!q || (String(f.title || '') + ' ' + String(f.module || '')).toLowerCase().includes(q))
  );
  tb.innerHTML = rows.map(f => '<tr><td class="sev-' + esc(String(f.severity || 'info').toLowerCase()) + '">' +
    esc(f.severity || 'info') + '</td><td>' + esc(f.title || '') + '</td><td>' + esc(f.module || '') + '</td><td>' +
    esc(f.host || f.target || '') + '</td><td><span class="pill">' + esc(f.verdict || 'unreviewed') + '</span></td></tr>').join('') ||
    '<tr><td colspan="5" class="muted">No findings match the filters.</td></tr>';
}
document.querySelectorAll('#sev-filters button').forEach(b => b.addEventListener('click', () => {
  document.querySelectorAll('#sev-filters button').forEach(x => x.classList.remove('active'));
  b.classList.add('active'); sevFilter = b.dataset.sev; renderFindings();
}));
$('findings-search').addEventListener('input', e => { searchFilter = e.target.value; renderFindings(); });
$('findings-target').addEventListener('change', async e => {
  const t = e.target.value;
  allFindings = t ? await (await fetch('/api/target/' + encodeURIComponent(t) + '/findings')).json() : [];
  renderFindings();
});

$('crm-target').addEventListener('change', async e => {
  const t = e.target.value;
  const tb = document.querySelector('#crm-table tbody');
  if (!t) { tb.innerHTML = ''; return; }
  const data = await (await fetch('/api/target/' + encodeURIComponent(t) + '/crm')).json();
  tb.innerHTML = (data.findings || []).map(f =>
    '<tr><td>' + esc(f.id) + '</td><td class="sev-' + esc(String(f.severity).toLowerCase()) + '">' + esc(f.severity) +
    '</td><td><span class="pill st-' + esc(f.status) + '">' + esc(f.status) + '</span></td><td>' + esc(f.program) +
    '</td><td>' + (f.payout == null ? '-' : esc(f.payout)) + '</td><td>' + esc(f.title) + '</td></tr>').join('') ||
    '<tr><td colspan="6" class="muted">No findings.</td></tr>';
});

async function loadTrends() {
  const data = await (await fetch('/api/trends')).json();
  const box = $('trend-chart');
  const labels = data.labels || [], series = data.series || {};
  if (!labels.length) { box.innerHTML = '<span class="muted">No trend data yet.</span>'; return; }
  const colors = {critical: '#ff5d5d', high: '#ff8a5c', medium: '#ffb020', low: '#4cc38a', info: '#58a6ff'};
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const bw = 34, gap = 14, left = 50, top = 16, height = 200;
  const width = left + labels.length * (bw + gap) + 20;
  const peak = Math.max(...labels.map((_, i) => order.reduce((a, s) => a + (series[s] ? series[s][i] : 0), 0)), 1);
  let svg = '<svg viewBox="0 0 ' + width + ' ' + (height + top + 60) + '" id="trend-svg">';
  for (const frac of [0.25, 0.5, 0.75, 1]) {
    const y = top + height - frac * height;
    svg += '<line x1="' + left + '" y1="' + y + '" x2="' + (width - 20) + '" y2="' + y + '" stroke="#30363d"/>';
    svg += '<text x="' + (left - 6) + '" y="' + (y + 4) + '" fill="#8b949e" font-size="10" text-anchor="end">' + Math.round(frac * peak) + '</text>';
  }
  labels.forEach((label, i) => {
    const x = left + i * (bw + gap);
    let y0 = top + height;
    for (const s of order) {
      const v = series[s] ? series[s][i] : 0;
      const h = v / peak * height;
      if (h > 0) {
        svg += '<rect x="' + x + '" y="' + (y0 - h).toFixed(1) + '" width="' + bw + '" height="' + h.toFixed(1) +
          '" fill="' + colors[s] + '"><title>' + esc(label) + ' ' + s + ': ' + v + '</title></rect>';
        y0 -= h;
      }
    }
    svg += '<text x="' + (x + bw / 2) + '" y="' + (height + top + 24) + '" fill="#8b949e" font-size="10" text-anchor="middle" transform="rotate(-30 ' + (x + bw / 2) + ' ' + (height + top + 24) + ')">' + esc(label) + '</text>';
  });
  let lx = left;
  for (const s of order) {
    svg += '<rect x="' + lx + '" y="' + (height + top + 34) + '" width="10" height="10" fill="' + colors[s] + '"/>' +
      '<text x="' + (lx + 14) + '" y="' + (height + top + 43) + '" fill="#8b949e" font-size="11">' + s + '</text>';
    lx += 78;
  }
  box.innerHTML = svg + '</svg>';
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
        if path == "/api/trends":
            self._send_json(trends_data(ctx))
            return
        if path.startswith("/api/pipeline/"):
            name = urllib.parse.unquote(path[len("/api/pipeline/"):])
            self._send_json(pipeline_state(ctx, name))
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
                if action == "crm":
                    self._send_json(crm_board(ctx, name))
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
