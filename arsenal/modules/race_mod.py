"""PENTRIX ARSENAL module: race condition tester.

Caido explicitly lacks this; Burp needs extensions. This module is a
parallel request engine with a precise launch barrier for coupon,
payment, vote and redemption flows, plus outcome verification hooks.

How it works: N threads block on a threading.Barrier, then fire at the
same instant. A verify hook compares outcomes (e.g. "coupon applied
twice", "balance went negative", "vote counted twice"). The engine
returns per-request timings so the hunter can see the race window.

Provider API::

    from arsenal.modules import race_mod
    result = race_mod.race(url, method="POST", data=..., count=20,
                           verify_fn=my_check, ctx=ctx)

Intrusive: fires N near-simultaneous state-changing requests.
Authorized engagements only; races can double-charge real accounts in
labs that mirror production data, so default count is conservative.
"""

import threading
import time
import urllib.parse
import urllib.request
import urllib.error

from arsenal.findings import make_finding

NAME = "race"
DESCRIPTION = (
    "Race condition tester: parallel request engine with a precise "
    "launch barrier for coupon/payment/vote flows, with outcome "
    "verification hooks."
)
TARGET_KIND = "url"
INTRUSIVE = True

DEFAULT_COUNT = 10
DEFAULT_TIMEOUT = 15


def _single_request(method, url, data, headers, timeout):
    """Fire one request; return a result dict (never raises)."""
    body = data.encode() if isinstance(data, str) else data
    req = urllib.request.Request(url, data=body,
                                 headers=dict(headers or {}),
                                 method=method.upper())
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read()
            status = resp.status
            err = None
    except urllib.error.HTTPError as exc:
        try:
            payload = exc.read()
        except Exception:
            payload = b""
        status, err = exc.code, None
    except Exception as exc:  # noqa: BLE001 - per-thread result, not fatal
        payload, status, err = b"", None, "%s: %s" % (
            type(exc).__name__, exc)
    dt = (time.perf_counter() - t0) * 1000.0
    return {"status": status, "body": payload, "ms": dt, "error": err}


def race(url, method="POST", data=None, headers=None, count=DEFAULT_COUNT,
         timeout=DEFAULT_TIMEOUT, verify_fn=None, stagger_ms=0.0):
    """Fire `count` requests at (near-)the same instant.

    verify_fn(responses) -> (verdict_bool, detail_str): hunter-supplied
    outcome check, e.g. "coupon discount applied more than once".
    stagger_ms>0 spaces launches (for last-byte-sync style tuning).

    Returns a report dict with per-request timings and the verdict.
    """
    barrier = threading.Barrier(count)
    results = [None] * count

    def worker(i):
        try:
            barrier.wait(timeout=30)
        except threading.BrokenBarrierError:
            results[i] = {"status": None, "body": b"", "ms": 0.0,
                          "error": "barrier broken"}
            return
        if stagger_ms:
            time.sleep(stagger_ms * i / 1000.0)
        results[i] = _single_request(method, url, data, headers, timeout)

    threads = [threading.Thread(target=worker, args=(i,), daemon=True)
               for i in range(count)]
    t0 = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout + 30)
    wall_ms = (time.perf_counter() - t0) * 1000.0

    ok = [r for r in results if r and r["status"] is not None]
    launched = sum(1 for r in results if r)
    spread = (max((r["ms"] for r in ok), default=0.0)
              - min((r["ms"] for r in ok), default=0.0))
    verdict, detail = (None, "no verify_fn supplied")
    if verify_fn is not None:
        try:
            verdict, detail = verify_fn([r for r in results if r])
        except Exception as exc:
            verdict, detail = False, "verify_fn raised: %s" % exc
    return {
        "url": url, "method": method, "count": count, "launched": launched,
        "wall_ms": wall_ms, "spread_ms": spread,
        "statuses": sorted({r["status"] for r in ok}),
        "results": results,
        "race_won": verdict, "verdict_detail": detail,
    }


# ---------------------------------------------------------------------------
# Ready-made verification hooks for common flows
# ---------------------------------------------------------------------------

def verify_double_spend(keyword: bytes | str):
    """Build a verify_fn: True when `keyword` appears in 2+ responses.

    Example: a coupon endpoint echoing b"discount applied" twice means
    the single-use coupon was consumed twice.
    """
    needle = keyword.encode() if isinstance(keyword, str) else keyword

    def check(responses):
        hits = sum(1 for r in responses if needle in (r["body"] or b""))
        return (hits >= 2,
                "keyword %r in %d/%d responses" % (needle, hits, len(responses)))
    return check


def verify_status_split():
    """True when responses disagree on status (some won, some lost)."""
    def check(responses):
        statuses = {r["status"] for r in responses if r["status"] is not None}
        return (len(statuses) > 1,
                "statuses seen: %s" % sorted(statuses))
    return check


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(target, ctx):
    try:
        return _run(target, ctx)
    except Exception as exc:
        _log(ctx, "warning", "%s failed on %s: %s" % (NAME, target, exc))
        return []


def _log(ctx, level, msg):
    log = getattr(ctx, "log", None)
    if log:
        getattr(log, level, log.info)(msg)


def _run(target, ctx):
    if INTRUSIVE and getattr(ctx, "safe_mode", False) \
            and not getattr(ctx, "allow_intrusive", False):
        _log(ctx, "warning", "%s skipped: safe mode blocks intrusive modules" % NAME)
        return []
    cfg = getattr(ctx, "config", {}) or {}
    count = int(cfg.get("race_count", DEFAULT_COUNT))
    keyword = cfg.get("race_keyword")  # e.g. "discount applied"
    method = cfg.get("race_method", "POST")
    data = cfg.get("race_data")
    headers = cfg.get("race_headers") or {}
    verify_fn = verify_double_spend(keyword) if keyword else verify_status_split()

    report = race(target, method=method, data=data, headers=headers,
                  count=count, verify_fn=verify_fn)
    findings = []
    detail = ("fired %d/%d requests in %.0fms wall time (spread %.1fms); "
              "statuses %s; verdict: %s" % (
                  report["launched"], report["count"], report["wall_ms"],
                  report["spread_ms"], report["statuses"],
                  report["verdict_detail"]))
    if report["race_won"]:
        findings.append(make_finding(
            NAME, target, "high",
            "Race condition won: %s" % report["verdict_detail"],
            "Parallel-request engine fired %d requests through a launch "
            "barrier at %s. Outcome verification says the race was won: "
            "%s. Re-verify manually (single-use resources must not be "
            "consumable twice)." % (report["count"], target,
                                    report["verdict_detail"]),
            evidence=detail, confidence="strong",
            remediation="Serialize the critical section (DB transaction "
                        "with row lock / atomic decrement); enforce "
                        "single-use server-side, never by client timing."))
    else:
        findings.append(make_finding(
            NAME, target, "info",
            "Race test completed, no win: %s" % report["verdict_detail"],
            "Engine detail: " + detail + " Tune count/stagger or aim the "
            "race at the exact state-changing endpoint (coupon redeem, "
            "not coupon validate).",
            evidence=detail, confidence="review"))
    return findings
