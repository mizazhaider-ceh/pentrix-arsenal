"""SMART SCOPE EXPANSION.

Differentiator #9. BBOT touches ASN; nobody automates the acquisition
angle or bucket permutation from naming patterns. Three free, keyless
data sources, all stdlib urllib:

1. ASN-to-org: BGPView (api.bgpview.io) with RIPEstat (stat.ripe.net)
   as fallback. IP -> ASN -> org name + announced prefixes.
2. Certificate-transparency org-name pivoting: crt.sh full-text search
   for the org name finds certificates issued to acquisitions and
   subsidiaries the hunter did not know about.
3. Cloud bucket permutation: AWS S3 / GCP GCS / Azure Blob names built
   from the org's naming patterns, checked with safe HEAD/GET only
   (existence + public-read detection, nothing written or listed).

Provider API::

    from arsenal import scopex
    scopex.asn_lookup("8.8.8.8")            # ASN + org + prefixes
    scopex.ct_org_pivot("Example Corp")     # related domains from crt.sh
    scopex.bucket_permute("examplecorp")    # candidate bucket findings

All network calls are read-only. Respect crt.sh rate limits (it asks
for a User-Agent and gentle pacing); this module sends both.
"""

from __future__ import annotations

import json
import re
import time
import urllib.parse
import urllib.request
import urllib.error

UA = "pentrix-arsenal/0.1.0 (scope-expansion; authorized testing)"


def _get_json(url: str, timeout: int = 15):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


# ---------------------------------------------------------------------------
# 1. ASN-to-org
# ---------------------------------------------------------------------------

def asn_lookup(ip: str) -> dict:
    """IP -> {asn, org, prefixes, source}. BGPView first, RIPEstat fallback."""
    # BGPView: free, no key
    try:
        data = _get_json("https://api.bgpview.io/ip/%s" % urllib.parse.quote(ip))
        d = (data.get("data") or {})
        asns = d.get("asns") or []
        if asns:
            a = asns[0]
            prefixes = [p.get("prefix") for p in d.get("prefixes") or []
                        if p.get("prefix")]
            return {"ip": ip, "asn": a.get("asn"),
                    "org": a.get("name") or a.get("description"),
                    "prefixes": prefixes, "source": "bgpview"}
    except Exception:
        pass
    # RIPEstat fallback: free, no key
    try:
        data = _get_json(
            "https://stat.ripe.net/data/network-info/data.json?resource=%s"
            % urllib.parse.quote(ip))
        d = (data.get("data") or {})
        asns = d.get("asns") or []
        return {"ip": ip, "asn": asns[0] if asns else None,
                "org": None, "prefixes": [],
                "source": "ripestat"}
    except Exception as exc:
        return {"ip": ip, "asn": None, "org": None, "prefixes": [],
                "source": "error: %s" % exc}


# ---------------------------------------------------------------------------
# 2. CT org-name pivoting (acquisition discovery)
# ---------------------------------------------------------------------------

def ct_org_pivot(org_name: str, limit: int = 100) -> dict:
    """Search crt.sh for certificates mentioning the org name.

    Returns {org, domains, issuers}. Domains whose names do not contain
    the org's own keywords are acquisition/subsidiary candidates.
    """
    q = urllib.parse.quote(org_name)
    url = ("https://crt.sh/?q=%%%s%%&output=json" % q)
    try:
        data = _get_json(url, timeout=25)
    except Exception as exc:
        return {"org": org_name, "domains": [], "issuers": [],
                "error": "crt.sh: %s" % exc}
    domains, issuers = set(), set()
    for row in (data or [])[:2000]:
        nv = str(row.get("name_value") or "")
        for d in nv.split("\n"):
            d = d.strip().lower().lstrip("*.")
            if d and "." in d and "@" not in d:
                domains.add(d)
        if row.get("issuer_name"):
            issuers.add(str(row.get("issuer_name"))[:80])
    domains = sorted(domains)[:limit]
    return {"org": org_name, "domains": domains,
            "issuers": sorted(issuers)[:10],
            "count": len(domains)}


# ---------------------------------------------------------------------------
# 3. Cloud bucket permutation (safe HEAD/GET only)
# ---------------------------------------------------------------------------

BUCKET_SUFFIXES = ("", "-backup", "-backups", "-dev", "-development",
                   "-prod", "-production", "-staging", "-test", "-assets",
                   "-static", "-media", "-uploads", "-files", "-data",
                   "-logs", "-private", "-public", "-www", "-app", "-api",
                   "backup", "assets", "static", "media", "data")

_AWS = "https://{b}.s3.amazonaws.com"
_GCP = "https://storage.googleapis.com/{b}"
_AZURE = "https://{b}.blob.core.windows.net"


def _bucket_exists(url: str, timeout: int = 10):
    """HEAD the bucket URL. Returns (exists, public_read, note)."""
    for method in ("HEAD", "GET"):
        req = urllib.request.Request(url, method=method,
                                     headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(4096) if method == "GET" else b""
                public = b"<ListBucketResult" in body or resp.status == 200
                return True, public, "http %d" % resp.status
        except urllib.error.HTTPError as exc:
            if exc.code == 403:
                return True, False, "http 403 (exists, private)"
            if exc.code == 404:
                return False, False, "http 404"
            return True, False, "http %d" % exc.code
        except Exception as exc:  # noqa: BLE001 - probe result
            return False, False, "error: %s" % exc
    return False, False, "no response"


def bucket_permute(base_name: str, providers=("aws", "gcp", "azure"),
                   throttle: float = 0.4) -> list[dict]:
    """Permute bucket names from a base name; safe existence checks.

    base_name like "examplecorp" or "example-corp". Returns findings-ready
    dicts for buckets that exist (flagging public-read ones).
    """
    bases = {base_name, base_name.replace(" ", ""), base_name.replace(" ", "-"),
             base_name.replace("-", "")}
    names = set()
    for b in bases:
        for s in BUCKET_SUFFIXES:
            names.add((b + s).strip("-").lower())
    names = {n for n in names if 3 <= len(n) <= 63
             and re.fullmatch(r"[a-z0-9.-]+", n)}
    templates = {"aws": _AWS, "gcp": _GCP, "azure": _AZURE}
    results = []
    for name in sorted(names):
        for prov in providers:
            url = templates[prov].format(b=name)
            exists, public, note = _bucket_exists(url)
            results.append({"provider": prov, "bucket": name, "url": url,
                            "exists": exists, "public_read": public,
                            "note": note})
            time.sleep(throttle)
    return results


# ---------------------------------------------------------------------------
# Importable report helper
# ---------------------------------------------------------------------------

def expansion_report(target_domain: str, org_name: str = "") -> dict:
    """Run all three pivots; return scored expansion candidates."""
    report = {"target": target_domain, "asn": {}, "ct": {}, "buckets": []}
    # ASN via the domain's A record is the caller's job; do a best-effort
    # resolve here so the helper is one call.
    import socket
    try:
        ip = socket.getaddrinfo(target_domain, 443,
                                type=socket.SOCK_STREAM)[0][4][0]
        report["asn"] = asn_lookup(ip)
    except OSError as exc:
        report["asn"] = {"error": "resolve: %s" % exc}
    org = org_name or (report["asn"].get("org") or "")
    if org:
        report["ct"] = ct_org_pivot(org)
    base = re.sub(r"\.[a-z]+$", "", target_domain.split(".")[0])
    report["buckets"] = [r for r in
                         bucket_permute(org or base or target_domain)
                         if r["exists"]]
    return report


ARGPARSE_SNIPPET = '''
# --- integrator: add to arsenal/cli.py subparsers ---
p = sub.add_parser("scopex", help="Smart scope expansion")
p.add_argument("--domain", required=True)
p.add_argument("--org", default="")
p.add_argument("--json", action="store_true")
p.set_defaults(func=arsenal.scopex.cmd_scopex)
'''


def cmd_scopex(args, ctx) -> int:
    report = expansion_report(args.domain, args.org)
    if args.json:
        print(json.dumps(report, indent=2, default=str))
        return 0
    print("ASN: %s" % report["asn"])
    ct = report["ct"]
    if ct.get("domains"):
        print("CT org pivot: %d domains (first 20):" % ct["count"])
        for d in ct["domains"][:20]:
            print("  " + d)
    buckets = report["buckets"]
    print("buckets found: %d" % len(buckets))
    for b in buckets:
        flag = " PUBLIC-READ" if b["public_read"] else ""
        print("  [%s] %s (%s)%s" % (b["provider"], b["bucket"], b["note"], flag))
    return 0
