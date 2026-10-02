"""CLI UX helpers for PENTRIX ARSENAL (rich-based, optional).

progress_bar()  - a rich Progress context manager for module/scan loops.
print_finding() - one finding as a colored one-liner (severity-colored).
finding_stream  - a progress callback factory: prints live findings as they
                  arrive from pipeline.run_pipeline(progress=...).
severity_style  - rich style name per severity.

Everything degrades to plain text when rich is unavailable. Library
functions never raise for display failures.
"""

from __future__ import annotations

import sys

SEVERITY_STYLES = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "info": "cyan",
}

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def severity_style(severity: str) -> str:
    return SEVERITY_STYLES.get(str(severity or "info").lower(), "white")


def _console():
    try:
        from rich.console import Console
        return Console()
    except Exception:
        return None


def print_finding(finding, console=None) -> None:
    """Print one finding as a colored one-liner. Never raises."""
    try:
        sev = str(finding.get("severity", "info"))
        title = str(finding.get("title", "(untitled)"))[:100]
        module = str(finding.get("module", "?"))
        host = str(finding.get("host") or finding.get("target") or "")
        line = "[%s] %s (%s%s)" % (sev.upper(), title, module,
                                   " on " + host if host else "")
        con = console or _console()
        if con is not None:
            con.print(line, style=severity_style(sev))
        else:
            print(line)
    except Exception:
        try:
            print(str(finding.get("title", finding))[:120])
        except Exception:
            pass


def print_findings(findings, console=None, min_severity="info") -> None:
    """Print findings sorted by severity, filtered below min_severity."""
    rank = _SEV_RANK.get(str(min_severity).lower(), 4)
    ordered = sorted((f for f in (findings or []) if isinstance(f, dict)),
                     key=lambda f: _SEV_RANK.get(str(f.get("severity", "info")).lower(), 4))
    for f in ordered:
        if _SEV_RANK.get(str(f.get("severity", "info")).lower(), 4) <= rank:
            print_finding(f, console=console)


def progress_bar(description="working", total=None):
    """Return a (progress, task_id, console) triple for a rich Progress bar.

    Usage:
        progress, task, console = ux.progress_bar("scanning modules", total=24)
        with progress:
            for ...:
                progress.update(task, advance=1)
    Falls back to a no-op shim when rich is missing.
    """
    try:
        from rich.progress import (BarColumn, Progress, SpinnerColumn,
                                    TextColumn, TimeElapsedColumn)
        from rich.console import Console
        console = Console()
        progress = Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(), console=console,
        )
        task = progress.add_task(description, total=total)
        return progress, task, console
    except Exception:
        class _Shim:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def update(self, *a, **k): pass
            def add_task(self, *a, **k): return 0
        shim = _Shim()
        return shim, 0, None


def finding_stream(min_severity="info", show_stages=True):
    """Build a pipeline progress callback with a live colored finding stream.

    pipeline.run_pipeline(target, ctx, progress=ux.finding_stream())
    prints each finding as it lands (colored by severity) plus stage
    transitions on a TTY.
    """
    rank = _SEV_RANK.get(str(min_severity).lower(), 4)
    console = _console()
    tty = bool(console and sys.stdout.isatty())

    def _cb(stage, detail, done=False):
        try:
            if stage == "finding" and isinstance(detail, str):
                import re as _re
                m = _re.match(r"^(.*)\s+\[([a-zA-Z]+)\]\s*$", detail)
                title, sev = (m.group(1), m.group(2)) if m else (detail, "info")
                if _SEV_RANK.get(sev.lower(), 4) <= rank:
                    print_finding({"title": title.strip(), "severity": sev},
                                  console=console)
                return
            if show_stages and tty and console is not None:
                mark = " [green]done[/green]" if done else ""
                console.print("[cyan]%s[/cyan] %s%s"
                              % (stage, str(detail)[:100], mark))
            elif show_stages:
                print("[%s] %s%s" % (stage, str(detail)[:100],
                                     " [done]" if done else ""))
        except Exception:
            pass

    return _cb
