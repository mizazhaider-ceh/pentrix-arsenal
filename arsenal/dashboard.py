"""Live TUI dashboard for PENTRIX ARSENAL.

run_dashboard(target, ctx, pipeline_fn) renders a rich Live dashboard
while pipeline_fn(target, ctx, progress_cb) runs. pipeline_fn reports
progress through progress_cb(stage, detail, done) where detail is a
string or a dict with optional keys: detail (str), finding (finding
dict), error (str).

Layout:
  header : target + profile + elapsed
  left   : stages table (stage, status icon, detail)
  right  : live findings feed (latest 12, colored by severity)
  footer : START HERE priority list (top 5 findings after pipeline)
           plus counters

After completion a summary panel shows counts by severity and elapsed
time. On non-tty output a plain rich Progress fallback is used instead
of the Live layout. Never crashes on missing data.
"""

import json
import os
import re
import sys
import time

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

STAGES = ["recon", "portscan", "tech", "vuln", "secrets", "visual", "report"]

SEV_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "info": "cyan",
}

STAGE_ICON = {
    "pending": ("...", "dim"),
    "running": ("[*]", "cyan"),
    "done": ("[+]", "green"),
    "error": ("[!]", "red"),
}

# Pipeline v2 emits live finding events as "<title> [<severity>]".
_FINDING_EVENT_RE = re.compile(r"^(.*)\s+\[([a-zA-Z]+)\]\s*$")


def _profile(ctx) -> str:
    cfg = getattr(ctx, "config", None)
    if isinstance(cfg, dict):
        return str(cfg.get("profile", "default"))
    get = getattr(cfg, "get", None)
    if callable(get):
        try:
            return str(get("profile", "default"))
        except Exception:
            pass
    return "default"


def _ws_findings(ctx, target) -> list:
    ws = getattr(ctx, "workspace", None)
    path = None
    if ws is not None and hasattr(ws, "path"):
        try:
            path = os.path.join(ws.path(target), "findings.json")
        except Exception:
            path = None
    if not path:
        path = os.path.expanduser(os.path.join("~", ".arsenal", "workspace", str(target), "findings.json"))
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _sev(finding) -> str:
    try:
        return str(finding.get("severity", "info")).lower()
    except Exception:
        return "info"


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sort_key(finding):
    sev = _SEV_RANK.get(_sev(finding), 4)
    conf = str(finding.get("confidence", "")).lower()
    conf_rank = {"high": 0, "medium": 1, "low": 2}.get(conf, 3)
    return (sev, conf_rank)


class _State:
    def __init__(self, target, profile):
        self.target = target
        self.profile = profile
        self.start = time.time()
        self.stages = {s: {"status": "pending", "detail": ""} for s in STAGES}
        self.findings = []
        self.error = None
        self.finished = False
        self.pipe_summary = None

    @property
    def elapsed(self) -> float:
        return time.time() - self.start


def _register_finding(state: _State, finding) -> None:
    if not isinstance(finding, dict):
        return
    finding.setdefault("severity", "info")
    state.findings.append(finding)


def _absorb_pipe_result(state: _State, pipe_result) -> None:
    """Merge findings from the pipeline's return value into the dashboard."""
    if not isinstance(pipe_result, dict):
        return
    state.pipe_summary = pipe_result
    for finding in pipe_result.get("findings") or []:
        _register_finding(state, finding)


def _progress(state: _State, stage, detail=None, done=False) -> None:
    stage = str(stage or "unknown")
    if stage not in state.stages:
        state.stages[stage] = {"status": "pending", "detail": ""}
    text = ""
    if isinstance(detail, dict):
        text = str(detail.get("detail", "") or "")
        if detail.get("finding") is not None:
            _register_finding(state, detail.get("finding"))
        if detail.get("error"):
            state.stages[stage]["status"] = "error"
            state.stages[stage]["detail"] = str(detail.get("error"))[:80]
            return
    elif detail is not None:
        text = str(detail)
    # Pipeline v2 live finding stream: "finding" events arrive as
    # "<title> [<severity>]" strings; feed them into the live feed.
    if stage == "finding" and text:
        match = _FINDING_EVENT_RE.match(text)
        if match:
            _register_finding(state, {
                "title": match.group(1).strip(),
                "severity": match.group(2).strip().lower(),
            })
        state.stages[stage]["status"] = "running"
        state.stages[stage]["detail"] = "%d finding(s) so far" % len(state.findings)
        return
    if done:
        state.stages[stage]["status"] = "done"
    else:
        state.stages[stage]["status"] = "running"
    if text:
        state.stages[stage]["detail"] = text[:80]


def _counts(findings) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[_sev(f)] = counts.get(_sev(f), 0) + 1
    return counts


def _all_findings(state: _State, ctx) -> list:
    merged = list(state.findings)
    seen = set()
    for f in merged:
        try:
            seen.add((str(f.get("title")), str(f.get("target"))))
        except Exception:
            pass
    for f in _ws_findings(ctx, state.target):
        try:
            key = (str(f.get("title")), str(f.get("target")))
        except Exception:
            continue
        if key not in seen:
            merged.append(f)
            seen.add(key)
    return merged


def _stages_table(state: _State) -> Table:
    table = Table(title="Pipeline stages", expand=True)
    table.add_column("Stage", style="bold")
    table.add_column("Status", width=10)
    table.add_column("Detail", overflow="fold")
    for name, info in state.stages.items():
        icon, color = STAGE_ICON.get(info["status"], ("?", "dim"))
        table.add_row(name, Text(icon, style=color), info["detail"] or "-")
    return table


def _feed_table(state: _State) -> Table:
    table = Table(title="Live findings feed", expand=True)
    table.add_column("Sev", width=9)
    table.add_column("Title", overflow="fold")
    for f in state.findings[-12:]:
        sev = _sev(f)
        table.add_row(Text(sev.upper(), style=SEV_STYLE.get(sev, "white")),
                      str(f.get("title", "(untitled)"))[:70])
    if not state.findings:
        table.add_row("-", "no findings yet")
    return table


def _start_here(state: _State, ctx) -> Panel:
    findings = sorted(_all_findings(state, ctx), key=_sort_key)[:5]
    table = Table(show_header=False, expand=True, box=None)
    table.add_column("n", width=4)
    table.add_column("item", overflow="fold")
    for i, f in enumerate(findings, 1):
        sev = _sev(f)
        table.add_row(
            Text(str(i), style="bold yellow"),
            Text("%s  %s" % (sev.upper(), str(f.get("title", "(untitled)"))[:80]),
                 style=SEV_STYLE.get(sev, "white")),
        )
    if not findings:
        table.add_row("-", "no findings recorded")
    return Panel(table, title="START HERE (top priority)", border_style="yellow")


def _counters_line(state: _State, ctx) -> Text:
    counts = _counts(_all_findings(state, ctx))
    parts = ["%s: %d" % (k.capitalize(), v) for k, v in counts.items() if v]
    line = "Findings: %d" % sum(counts.values())
    if parts:
        line += "  (" + ", ".join(parts) + ")"
    line += "  |  Elapsed: %ds" % int(state.elapsed)
    return Text(line, style="bold")


def _summary_panel(state: _State, ctx) -> Panel:
    findings = _all_findings(state, ctx)
    counts = _counts(findings)
    table = Table(title="Scan summary", expand=True)
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev in ("critical", "high", "medium", "low", "info"):
        table.add_row(Text(sev.upper(), style=SEV_STYLE[sev]), str(counts[sev]))
    table.add_row("[bold]TOTAL[/bold]", "[bold]%d[/bold]" % len(findings))
    extra = "Elapsed: %ds" % int(state.elapsed)
    if state.error:
        extra += "  |  ERROR: %s" % str(state.error)[:100]
    return Panel(table, title="Complete: %s (%s)" % (state.target, extra), border_style="green")


def _render(state: _State, ctx, final=False) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(Panel(
            Text("PENTRIX ARSENAL  |  target: %s  |  profile: %s  |  elapsed: %ds"
                 % (state.target, state.profile, int(state.elapsed)), style="bold white"),
            style="blue",
        ), size=3),
        Layout(name="body"),
        Layout(name="footer", size=12),
    )
    layout["body"].split_row(
        Layout(_stages_table(state)),
        Layout(_feed_table(state)),
    )
    if final:
        layout["footer"].split_column(
            Layout(_summary_panel(state, ctx)),
            Layout(_start_here(state, ctx)),
        )
    else:
        layout["footer"].split_column(
            Layout(_start_here(state, ctx)),
            Layout(Panel(_counters_line(state, ctx), border_style="dim"), size=3),
        )
    return layout


def _run_plain(target, ctx, pipeline_fn, cb, state: _State, console: Console) -> dict:
    """Non-tty fallback: simple rich progress, then printed summary."""
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console) as progress:
        tasks = {s: progress.add_task(s, total=None) for s in STAGES}

        def plain_cb(stage, detail=None, done=False):
            _progress(state, stage, detail, done)
            text = str(stage)
            if isinstance(detail, dict):
                d = detail.get("detail") or detail.get("error") or ""
                if d:
                    text += ": %s" % str(d)[:60]
            elif detail:
                text += ": %s" % str(detail)[:60]
            if str(stage) in tasks:
                progress.update(tasks[str(stage)], description=text)
                if done:
                    progress.stop_task(tasks[str(stage)])

        try:
            pipe_result = pipeline_fn(target, ctx, plain_cb)
            _absorb_pipe_result(state, pipe_result)
        except Exception as exc:
            state.error = str(exc)
    state.finished = True
    console.print(_summary_panel(state, ctx))
    console.print(_start_here(state, ctx))
    all_findings = _all_findings(state, ctx)
    return {"findings": all_findings, "summary": _counts(all_findings),
            "error": state.error}


def run_dashboard(target, ctx, pipeline_fn) -> dict:
    """Run the pipeline with a live rich dashboard. Returns result dict."""
    state = _State(target, _profile(ctx))
    console = Console()

    def cb(stage, detail=None, done=False):
        _progress(state, stage, detail, done)

    if not sys.stdout.isatty():
        return _run_plain(target, ctx, pipeline_fn, cb, state, console)

    try:
        with Live(_render(state, ctx), console=console, refresh_per_second=4) as live:
            try:
                pipe_result = pipeline_fn(target, ctx, cb)
                _absorb_pipe_result(state, pipe_result)
            except Exception as exc:  # never let the pipeline kill the dashboard
                state.error = str(exc)
                for info in state.stages.values():
                    if info["status"] == "running":
                        info["status"] = "error"
            state.finished = True
            live.update(_render(state, ctx, final=True))
    except Exception:
        # Live rendering failed (odd terminal); fall back to plain mode
        return _run_plain(target, ctx, pipeline_fn, cb, _State(target, _profile(ctx)), console)

    findings = _all_findings(state, ctx)
    return {"findings": findings, "summary": _counts(findings),
            "pipeline_summary": state.pipe_summary,
            "error": state.error}
