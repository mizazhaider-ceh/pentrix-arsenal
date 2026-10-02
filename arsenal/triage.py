"""AI TRIAGE ANALYST for PENTRIX ARSENAL.

triage_finding() enriches a finding dict with an analyst verdict, reasoning,
concrete next steps and a draft report section. It uses the LLM provider when
an API key is configured and falls back to a rule-based analyst otherwise.
Library functions never print; the CLI entry points below may.
"""

from __future__ import annotations

import json
import re

from arsenal import llm

try:  # optional normalizer provided by another builder; never required here
    from arsenal.findings import make_finding  # noqa: F401
except Exception:  # findings module not present yet
    make_finding = None


VALID_VERDICTS = ("exploitable", "needs_manual_review", "likely_false_positive")

# Modules whose detections are classic, directly exploitable vulnerability classes.
_EXPLOITABLE_CLASSES = {"xss", "sqli", "ssrf", "rce", "lfi", "idor", "auth-bypass"}
# Recon-style modules whose raw output is frequently benign in isolation.
_RECON_MODULES = {"wordlist", "tech"}


# --------------------------------------------------------------------------
# internal helpers
# --------------------------------------------------------------------------

def _log(ctx, level: str, msg: str) -> None:
    log = getattr(ctx, "log", None)
    if log is None:
        return
    fn = getattr(log, level, None)
    if callable(fn):
        try:
            fn(msg)
        except Exception:
            pass


def _s(value) -> str:
    return str(value or "").strip().lower()


def _ws_get(ws, name: str, default=None):
    """Read an attribute (or call a zero-arg method) from a workspace object."""
    if ws is None:
        return default
    try:
        attr = getattr(ws, name, default)
    except Exception:
        return default
    if callable(attr):
        try:
            return attr()
        except TypeError:
            return default
        except Exception:
            return default
    return attr if attr is not None else default


_WS_ALIASES = {
    # requested name -> real Workspace method names to try, in order
    "get_findings": ("all_findings",),
    "save_findings": ("write_findings",),
    "set_findings": ("write_findings",),
}

def _ws_call(ws, method: str, target, default=None):
    """Call ws.<method>(target), tolerating missing methods."""
    if ws is None:
        return default
    fn = getattr(ws, method, None)
    if not callable(fn):
        for alt in _WS_ALIASES.get(method, ()): 
            fn = getattr(ws, alt, None)
            if callable(fn):
                break
        else:
            return default
    try:
        return fn(target)
    except TypeError:
        try:
            return fn()
        except Exception:
            return default
    except Exception:
        return default


# --------------------------------------------------------------------------
# rule-based triage (used directly, or as LLM fallback)
# --------------------------------------------------------------------------

_MODULE_CLASS_NAMES = {
    "xss": "Cross-Site Scripting (XSS)",
    "sqli": "SQL Injection",
    "ssrf": "Server-Side Request Forgery (SSRF)",
    "rce": "Remote Code Execution (RCE)",
    "lfi": "Local File Inclusion (LFI)",
    "idor": "Insecure Direct Object Reference (IDOR)",
    "wordlist": "Content Discovery",
    "tech": "Technology Fingerprinting",
}

_MODULE_STEPS = {
    "xss": [
        "Reproduce the reflection in a private/incognito window with a clean session to rule out session-specific behavior.",
        "Determine the injection context with a benign probe such as <img src=x onerror=alert(1)> and note whether the payload lands in an HTML body, attribute, or script context.",
        "Inspect the Content-Security-Policy response header; a missing or permissive policy materially raises real-world impact.",
        "Confirm the finding is reachable by an unauthenticated visitor (or the lowest-privilege in-scope role) before assigning final severity.",
    ],
    "sqli": [
        "Confirm the injection point manually with a benign boolean probe (e.g. ' AND '1'='1 vs ' AND '1'='2) and compare responses.",
        "Check for database error messages in the response; verbose errors both confirm the flaw and leak the backend type.",
        "Test a time-based probe to distinguish a real injection from coincidental response differences.",
        "Verify the query runs in a security-relevant context (authentication, authorization, or data access) before escalating.",
    ],
    "ssrf": [
        "Point the suspect parameter at a collaborator URL you control and confirm an outbound request arrives.",
        "Probe cloud metadata endpoints (e.g. 169.254.169.254) only where in scope and stop at confirmation of reachability.",
        "Check whether the response leaks fetched content, which separates blind SSRF from full-response SSRF.",
        "Test available URL schemes and redirect behavior to map the filter, if any.",
    ],
    "idor": [
        "Swap the object identifier for one belonging to a second test account and confirm unauthorized access.",
        "Test both sequential and UUID-style identifiers to map the authorization check coverage.",
        "Verify whether read access, write access, or both are affected; write impact raises severity.",
        "Check that no additional server-side check (signature, ownership token) blocks the request in some paths.",
    ],
    "wordlist": [
        "Manually request the discovered path and record the exact status code, content length, and content type.",
        "Compare against a known-missing path baseline to rule out wildcard/soft-404 responses.",
        "Check whether the path exposes anything sensitive; a bare 200 on a login page is not a vulnerability by itself.",
        "If authenticated content is found, verify which roles can reach it.",
    ],
    "tech": [
        "Confirm the detected technology and version from at least two independent signals (headers, body markers, favicon hash).",
        "Look up the exact version for known CVEs and check whether the instance is actually reachable/exploitable.",
        "Verify the version is not a backported or patched build before claiming a CVE applies.",
        "Note the technology in the report as context even when no vulnerability is confirmed.",
    ],
}

_DEFAULT_STEPS = [
    "Reproduce the finding manually outside the scanner to confirm it is real.",
    "Capture the full request and response as evidence for the report.",
    "Test with the lowest-privilege account in scope to assess real impact.",
    "Re-run the module with adjusted settings if the evidence looks ambiguous.",
]

_MODULE_IMPACT = {
    "xss": ("An attacker can execute arbitrary JavaScript in a victim's browser session on the affected page. "
            "This typically enables session theft, account takeover, or defacement depending on the application's trust model."),
    "sqli": ("An attacker can manipulate backend database queries through the vulnerable parameter. "
             "Depending on the database privileges this can lead to data exfiltration, authentication bypass, or full host compromise."),
    "ssrf": ("The server can be made to issue requests to internal or external resources on the attacker's behalf. "
             "This can expose internal services and cloud metadata, and may enable further pivoting."),
    "idor": ("An attacker can access or modify objects belonging to other users by manipulating identifiers. "
             "Impact ranges from privacy violations to data tampering depending on the object's sensitivity."),
    "wordlist": ("The discovered path may expose functionality or files not linked from the main application. "
                 "On its own this is usually informational, but it can reveal an enlarged attack surface worth investigating."),
    "tech": ("Knowing the exact technology stack helps an attacker select targeted exploits. "
              "Fingerprinting alone is not a vulnerability, but outdated components identified this way may be."),
}


def _rule_verdict(finding: dict):
    sev = _s(finding.get("severity"))
    conf = _s(finding.get("confidence"))
    module = _s(finding.get("module"))

    if sev == "high" and module in _EXPLOITABLE_CLASSES:
        return (
            "exploitable",
            "High severity %s finding with %s confidence. This module detects a classic directly-exploitable "
            "vulnerability class; confirm manually, then treat as a reportable issue." % (module.upper(), conf or "reported"),
        )
    if sev == "high" and conf in ("proven", "strong"):
        return (
            "exploitable",
            "High severity with %s confidence. The evidence indicates a real, demonstrable security issue; "
            "a short manual confirmation is enough before reporting." % conf,
        )
    if sev == "medium" and conf == "strong":
        probe = {
            "xss": "confirm the reflection context with a benign payload",
            "sqli": "confirm with a boolean-based probe and compare responses",
            "ssrf": "confirm with a collaborator callback URL",
            "idor": "confirm with a second test account's object identifier",
        }.get(module, "reproduce the finding manually and capture full request/response evidence")
        return (
            "needs_manual_review",
            "Medium severity with strong confidence. Likely real, but a targeted manual probe is required: %s." % probe,
        )
    if sev == "info":
        if module in _RECON_MODULES:
            return (
                "likely_false_positive",
                "Informational reconnaissance output from the %s module. On its own this is normal application "
                "behavior, not a vulnerability; keep it as context only." % module,
            )
        return (
            "needs_manual_review",
            "Informational finding outside the usual recon modules. Review manually to decide whether it "
            "supports a larger attack chain.",
        )
    return (
        "needs_manual_review",
        "Default triage for %s/%s from the %s module. Reproduce manually and reassess before reporting."
        % (sev or "unknown severity", conf or "unknown confidence", module or "unknown"),
    )


def _report_section(finding: dict, verdict: str) -> dict:
    title = str(finding.get("title") or "Untitled finding").strip()
    module = _s(finding.get("module"))
    class_name = _MODULE_CLASS_NAMES.get(module, module.upper() if module else "Security Finding")
    host = str(finding.get("host") or finding.get("target") or "the target").strip()
    location = str(finding.get("location") or finding.get("url") or finding.get("path") or "").strip()

    report_title = "%s: %s" % (class_name, title) if title.lower() not in class_name.lower() else title
    if location:
        report_title = "%s (%s)" % (report_title, location)

    impact = _MODULE_IMPACT.get(
        module,
        "The finding indicates a potential weakness on %s that requires manual assessment. "
        "Confirm exploitability before assigning business impact." % host,
    )

    reproduction = []
    step_no = 1

    def add(step):
        nonlocal step_no
        reproduction.append("%d. %s" % (step_no, step))
        step_no += 1

    if location:
        add("Navigate to %s on %s." % (location, host))
    else:
        add("Open the affected area on %s." % host)
    payload = str(finding.get("payload") or "").strip()
    if payload:
        add("Submit the probe payload: %s" % payload[:200])
    add("Observe the application response and compare it against the baseline captured in the evidence below.")
    evidence = str(finding.get("evidence") or "").strip()
    if evidence:
        add("Evidence: %s" % (evidence[:300] + ("..." if len(evidence) > 300 else "")))
    add("Repeat in a clean session (private window, logged out) to confirm the behavior is reproducible.")
    if verdict == "exploitable":
        add("Document the confirmed impact with screenshots and the full request/response pair for the report.")

    return {"title": report_title, "impact": impact, "reproduction": reproduction}


def _rule_triage(finding: dict) -> dict:
    verdict, reason = _rule_verdict(finding)
    module = _s(finding.get("module"))
    next_steps = list(_MODULE_STEPS.get(module, _DEFAULT_STEPS))[:4]
    if verdict == "exploitable":
        next_steps.append("Draft the report section and submit once evidence is captured.")
    return {
        "verdict": verdict,
        "triage_reason": reason,
        "next_steps": next_steps,
        "report_section": _report_section(finding, verdict),
    }


# --------------------------------------------------------------------------
# LLM-based triage
# --------------------------------------------------------------------------

_TRIAGE_SYSTEM = (
    "You are a senior bug bounty triage analyst. Given a scanner finding as JSON, "
    "assess it like a human analyst. Respond with STRICT JSON only, no markdown, "
    "no commentary, with exactly these keys: "
    '{"verdict": "exploitable|needs_manual_review|likely_false_positive", '
    '"triage_reason": "2-3 sentence analyst reasoning", '
    '"next_steps": ["2-4 concrete manual verification commands or checks"], '
    '"report_section": {"title": "professional report title", '
    '"impact": "two-sentence business impact", '
    '"reproduction": ["numbered reproduction steps"]}}'
)


def _extract_json(raw: str) -> dict:
    """Tolerant JSON extraction: pull the {...} substring and parse it."""
    if not raw:
        raise ValueError("empty LLM response")
    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("no JSON object found in LLM response")
    return json.loads(raw[start : end + 1])


def _normalize_llm_result(data: dict, finding: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError("LLM triage result is not an object")
    verdict = str(data.get("verdict") or "").strip().lower()
    if verdict not in VALID_VERDICTS:
        raise ValueError("LLM returned invalid verdict: %r" % data.get("verdict"))
    next_steps = data.get("next_steps")
    if isinstance(next_steps, str):
        next_steps = [next_steps]
    if not isinstance(next_steps, list) or not next_steps:
        raise ValueError("LLM triage missing next_steps")
    section = data.get("report_section")
    if not isinstance(section, dict):
        raise ValueError("LLM triage missing report_section")
    for key in ("title", "impact", "reproduction"):
        if key not in section:
            raise ValueError("LLM report_section missing %r" % key)
    repro = section["reproduction"]
    if isinstance(repro, str):
        section["reproduction"] = [repro]
    return {
        "verdict": verdict,
        "triage_reason": str(data.get("triage_reason") or "LLM triage provided no reasoning."),
        "next_steps": [str(s) for s in next_steps][:6],
        "report_section": {
            "title": str(section["title"]),
            "impact": str(section["impact"]),
            "reproduction": [str(s) for s in section["reproduction"]],
        },
    }


def _llm_triage(finding: dict, ctx) -> dict:
    messages = [
        {"role": "system", "content": _TRIAGE_SYSTEM},
        {"role": "user", "content": json.dumps(finding, indent=2, default=str)[:6000]},
    ]
    raw = llm.chat(messages, max_tokens=800, timeout=30, ctx=ctx)
    return _normalize_llm_result(_extract_json(raw), finding)


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------

def triage_finding(finding: dict, ctx) -> dict:
    """Triage one finding; returns a copy enriched with verdict, triage_reason,
    next_steps and report_section. Uses the LLM when available, rules otherwise.
    Never raises for a single finding: LLM failures fall back to rules."""
    finding = dict(finding) if isinstance(finding, dict) else {"raw": str(finding)}
    result = None
    if llm.llm_available():
        try:
            result = _llm_triage(finding, ctx)
        except Exception as e:
            _log(ctx, "warning", "LLM triage failed (%s); falling back to rules." % e)
            result = None
    if result is None:
        result = _rule_triage(finding)
    finding.update(result)
    finding["triaged"] = True
    return finding


def triage_all(findings, ctx):
    """Triage every finding; per-finding errors are caught and logged so one
    bad record never aborts the run."""
    out = []
    for f in findings or []:
        try:
            out.append(triage_finding(f, ctx))
        except Exception as e:  # defensive: triage_finding should not raise
            title = f.get("title") if isinstance(f, dict) else f
            _log(ctx, "error", "Triage failed for %r: %s" % (title, e))
            fb = dict(f) if isinstance(f, dict) else {"raw": str(f)}
            fb.update(
                {
                    "verdict": "needs_manual_review",
                    "triage_reason": "Automated triage raised an error; manual review required.",
                    "next_steps": ["Reproduce the finding manually and re-run triage."],
                    "report_section": {
                        "title": str(title or "Untriaged finding"),
                        "impact": "Impact could not be assessed automatically; determine it during manual review.",
                        "reproduction": ["1. Reproduce the finding manually and capture full evidence."],
                    },
                    "triaged": True,
                }
            )
            out.append(fb)
    return out


# --------------------------------------------------------------------------
# CLI: arsenal triage <target>
# --------------------------------------------------------------------------

def _stored_findings(ws, target):
    findings = _ws_call(ws, "get_findings", target, None)
    if findings is None:
        findings = _ws_get(ws, "findings", None)
    if isinstance(findings, dict):
        findings = findings.get(target, [])
    return list(findings or [])


def _store_findings(ws, target, findings):
    if ws is None:
        return False
    saver = getattr(ws, "save_findings", None)
    if callable(saver):
        try:
            saver(target, findings)
            return True
        except TypeError:
            try:
                saver(findings)
                return True
            except Exception:
                return False
        except Exception:
            return False
    setter = getattr(ws, "set_findings", None)
    if callable(setter):
        try:
            setter(target, findings)
            return True
        except Exception:
            return False
    return False


def cmd_triage(args, ctx):
    """Re-triage stored workspace findings for a target."""
    ws = getattr(ctx, "workspace", None)
    findings = _stored_findings(ws, args.target)
    if not findings:
        print("No stored findings for target %r." % args.target)
        return 0
    triaged = triage_all(findings, ctx)
    saved = _store_findings(ws, args.target, triaged)
    counts = {}
    for f in triaged:
        v = f.get("verdict", "needs_manual_review")
        counts[v] = counts.get(v, 0) + 1
    try:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        table = Table(title="Triage results for %s" % args.target)
        table.add_column("Verdict")
        table.add_column("Count", justify="right")
        for v in VALID_VERDICTS:
            table.add_row(v, str(counts.get(v, 0)))
        console.print(table)
    except Exception:
        print("Triage results for %s:" % args.target)
        for v in VALID_VERDICTS:
            print("  %s: %d" % (v, counts.get(v, 0)))
    if not saved:
        print("Note: workspace did not persist the triaged findings (no save method).")
    return 0


def add_parsers(sub):
    p = sub.add_parser("triage", help="AI-triage the stored findings for a target")
    p.add_argument("target", help="Target identifier (as stored in the workspace)")
    p.set_defaults(func=cmd_triage)
    return p


def dispatch(args, ctx):
    func = getattr(args, "func", None)
    if callable(func):
        return func(args, ctx)
    raise ValueError("no command dispatch configured for triage")
