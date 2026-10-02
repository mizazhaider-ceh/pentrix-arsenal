"""PIPELINE GRAPH for PENTRIX ARSENAL.

`arsenal pipeline-graph [--out dag.html]`

Generates a self-contained HTML page with an inline SVG diagram of the
pipeline stages: recon -> alive -> portscan -> tech -> jsintel ->
web modules -> verify -> triage -> report. No JavaScript is required.
Library functions never print; the CLI entry point below may.
"""

from __future__ import annotations

STAGES = [
    ("recon", "Enumerate attack surface"),
    ("alive", "Host liveness probing"),
    ("portscan", "Open port discovery"),
    ("tech", "Technology fingerprinting"),
    ("jsintel", "JS and API endpoint intel"),
    ("web modules", "Web vulnerability checks"),
    ("verify", "Finding verification"),
    ("triage", "Triage and prioritization"),
    ("report", "Report generation"),
]


def pipeline_dag_svg(width=640):
    """Build the pipeline DAG as an SVG string. Never raises."""
    try:
        box_w, box_h, gap, x = 320, 52, 44, (width - 320) / 2
        y = 30
        parts = []
        for i, (name, desc) in enumerate(STAGES):
            rect = (
                '<rect x="%.0f" y="%.0f" width="%d" height="%d" rx="10" '
                'fill="#161b22" stroke="#58a6ff" stroke-width="2"/>' % (x, y, box_w, box_h)
            )
            label = (
                '<text x="%.0f" y="%.0f" text-anchor="middle" fill="#e6edf3" '
                'font-family="system-ui,sans-serif" font-size="16" font-weight="bold">%s</text>'
                % (x + box_w / 2, y + 23, name)
            )
            sub = (
                '<text x="%.0f" y="%.0f" text-anchor="middle" fill="#8b949e" '
                'font-family="system-ui,sans-serif" font-size="12">%s</text>'
                % (x + box_w / 2, y + 41, desc)
            )
            parts.append(rect + label + sub)
            if i < len(STAGES) - 1:
                arrow = (
                    '<line x1="%.0f" y1="%.0f" x2="%.0f" y2="%.0f" '
                    'stroke="#58a6ff" stroke-width="2" marker-end="url(#arrowhead)"/>'
                    % (x + box_w / 2, y + box_h, x + box_w / 2, y + box_h + gap)
                )
                parts.append(arrow)
            y += box_h + gap
        height = y - gap + 40
        svg = (
            '<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%.0f" '
            'viewBox="0 0 %d %.0f" role="img" aria-label="Arsenal pipeline DAG">'
            '<defs><marker id="arrowhead" markerWidth="10" markerHeight="8" '
            'refX="9" refY="4" orient="auto">'
            '<polygon points="0 0, 9 4, 0 8" fill="#58a6ff"/></marker></defs>'
            '<rect x="0" y="0" width="%d" height="%.0f" fill="#0d1117"/>'
            '<text x="%d" y="20" text-anchor="middle" fill="#e6edf3" '
            'font-family="system-ui,sans-serif" font-size="18" font-weight="bold">'
            'PENTRIX ARSENAL pipeline</text>'
            % (width, height, width, height, width, height, width / 2)
        )
        svg += "".join(parts) + "</svg>"
        return svg
    except Exception:
        return '<svg xmlns="http://www.w3.org/2000/svg"><text x="10" y="20">DAG unavailable</text></svg>'


def pipeline_dag_html():
    """Self-contained HTML page embedding the DAG. Never raises."""
    svg = pipeline_dag_svg()
    return (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "<title>Arsenal pipeline graph</title>\n"
        "<style>body{background:#0d1117;display:flex;justify-content:center;"
        "padding:24px;margin:0}</style>\n</head>\n<body>\n"
        + svg + "\n</body>\n</html>\n"
    )


# --------------------------------------------------------------------------
# CLI: arsenal pipeline-graph [--out dag.html]
# --------------------------------------------------------------------------

def cmd_pipeline_graph(args, ctx):
    try:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(pipeline_dag_html())
    except Exception as e:
        print("Error: could not write %s: %s" % (args.out, e))
        return 1
    print("Pipeline graph written to %s" % args.out)
    return 0


def add_parsers(sub):
    p = sub.add_parser("pipeline-graph",
                       help="Generate a self-contained SVG diagram of the pipeline")
    p.add_argument("--out", default="dag.html", help="Output HTML file (default dag.html)")
    p.set_defaults(func=cmd_pipeline_graph)
    return p


def dispatch(args, ctx):
    func = getattr(args, "func", None)
    if callable(func):
        return func(args, ctx)
    raise ValueError("no command dispatch configured for pipeline-graph")
