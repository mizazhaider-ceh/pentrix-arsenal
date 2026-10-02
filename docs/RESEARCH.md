# PENTRIX ARSENAL v2 — Research Report

Research date: 2026-10-02. Method: read-only audit of every module and core
file in this repo (24 modules, 38 core files, with file/line references),
plus live 2026 research on the top GitHub bug bounty tools. No code was
changed during research. This document drives the v2 build: every build item
below is justified by a gap found here.

Full detail: `codebase-audit.md` and `competitive-research.md` (build working
papers, not shipped).

---

## Part 1 — Codebase audit: top 10 gaps (ranked by impact)

1. **Stealth is dead + no proxy support.** Zero modules pass `ctx` to
   `fetch()`, so stealth sleeps and UA rotation never fire; every request
   carries `pentrix-arsenal/0.1.0`. No proxy support either, so traffic
   cannot go through Burp. Highest operational risk.
2. **Scope firewall rejects all URL targets when a scope file is set.**
   `Scope(['example.com']).contains('https://example.com/page')` is False.
   `arsenal scan <url> --scope-file` always exits 2.
3. **`scan --all` ignores TARGET_KIND.** jwt/secrets/hashid/phish/cve/wordlist
   run against mistyped targets (jwt parses the literal string
   "example.com" as a token). The pipeline orphans whole modules.
4. **Module-extras contract is fiction.** No module returns the documented
   extras dict, so recursive discovery depends on `_derive_*` functions
   parsing finding titles as strings. Rename a title, break discovery.
5. **Zero tests.** No tests/, no pytest, no config. Lab fixtures cover 10/24
   modules and assert nothing. Import check is the only automated signal.
6. **Injection modules only test GET query params.** xss (4 payloads), sqli
   (6 payloads, error-based only, no blind), ssti (3 payloads). No
   POST/JSON/cookie/header/path coverage.
7. **Entire vuln classes missing:** SSRF, LFI/RFI, XXE, IDOR/BOLA, broken
   auth, CSRF, request smuggling, WebSocket. Triage references
   ssrf/lfi/idor/rce/auth-bypass modules that do not exist.
8. **headers_mod CSP check is presence-only.** `default-src *
   'unsafe-inline'` returns PASS. Referrer-Policy passes any value
   including `unsafe-url`.
9. **jsintel false-positive factory.** Any public JSON 200 becomes an
   "unauthenticated API" finding. oauth implicit-flow check FPs on
   login-page redirects.
10. **Dead/duplicated code.** `cvss.py` imported nowhere; `ctx.tech_hint`
    written nowhere; `TECH_MODULE_MAP` untriggerable; ~1,400 lines of
    duplicated module helpers; secret rules and JS discovery each
    implemented twice.

Also: report markdown silently truncates to 10 findings; nuclei export is
skeletons with TODOs; triage calls the LLM once per finding with no
batching or cost guard; pipeline treats graphql/oauth/hostheader as
intrusive while the modules declare INTRUSIVE = False.

**ROADMAP re-verdict:** 13 of the 24 deferred ideas are now buildable with
stdlib/local techniques (request smuggling, blind XXE via the existing
inbox, cloud bucket discovery, ASN expansion via free APIs, new-program
radar, scope-change alerts, OSINT fusion, methodology templates, report
template library, personal hunting profile, GitHub code search with a user
PAT, WebSocket checks via raw Upgrade, AI triage upgrades with a user key).
6 partially buildable. 5 still genuinely blocked: DNS history, breach-data
API, video proof capture, fleet VPS infra, Censys-grade paid intel.

---

## Part 2 — Competitive landscape: where the big tools fall short

| Capability | nuclei | BBOT | Osmedeus | ZAP | Burp | Arsenal v1 |
|---|---|---|---|---|---|---|
| WAF-adaptive payload mutation | missing | missing | missing | missing | missing | missing |
| JS bundle / schema diffing across runs | missing | missing | missing | missing | missing | missing |
| Auth sessions with token refresh | missing | missing | missing | partial | partial | missing |
| OOB testing with callback correlation | partial | missing | missing | missing | well (Pro) | missing |
| Business-logic flaw workflows | missing | missing | missing | missing | missing | missing |
| Cache deception/poisoning matrices | missing | missing | missing | missing | partial | missing |
| FP learning from user feedback | missing | missing | missing | missing | missing | missing |
| HTTP/3 + gRPC recon | missing | missing | missing | missing | partial | missing |
| Smart scope expansion | missing | partial | missing | missing | missing | missing |
| Continuous takeover monitoring w/ diffs | missing | missing | partial | missing | missing | partial |
| XS-Leaks detection | missing | missing | missing | missing | missing | missing |
| Collaborative multi-user hunts | missing | missing | partial | missing | missing | missing |
| Cross-tool finding dedup | missing | missing | missing | missing | missing | missing |
| Recursive recon | missing | well | missing | missing | missing | missing |
| Free full API + automation | well | well | well | well | missing | well |

Key structural gaps per tool: nuclei is stateless by design with primitive
auth; BBOT is recon-only with no exploitation; Osmedeus is an orchestrator
with zero built-in capability; ZAP findings are noisy with no learning
loop; Burp is $449/yr with deliberately crippled Community and no
collaboration; the recon stack (subfinder/httpx/katana) has no shared data
model and no memory between runs; dalfox/sqlmap/ffuf are best-in-class but
know nothing about the target or session; interactsh correlation is manual;
agentic AI tools burn tokens on real targets with no persistent recon
memory. Business logic is 45% of bounty awards (Intigriti 2026) and zero
tools automate it.

---

## Part 3 — Top 15 buildable differentiators (ranked)

1. WAF-adaptive payload mutation engine (closed-loop: fire, read block
   signal, mutate, retry). Nobody does this.
2. JS bundle + GraphQL schema diffing across runs.
3. Shared auth session manager with token refresh.
4. OOB correlation engine (unique token per payload, auto-link callbacks
   to the exact request, promote to findings).
5. Business-logic workflow packs (two-session differential testing, ID
   swap matrices, price tampering, step-skip/replay).
6. Cache deception/poisoning matrix runner.
7. Cross-tool dedup with FP feedback learning.
8. HTTP/3 + gRPC recon probes.
9. Smart scope expansion (ASN-to-org, CT org pivoting, bucket permutation).
10. Continuous takeover monitoring with diff alerts.
11. Race condition tester (parallel request engine, Caido lacks this).
12. Recon diff reports scored by bounty priority.
13. XS-Leaks PoC generator (zero hunter tooling exists).
14. Collaborative hunt mode (shared findings store, git-synced).
15. Evidence-chained AI triage with Burp-advisory-quality remediation.

Honestly not buildable without paid APIs/browsers: true DOM XSS (needs
headless browser), subfinder-grade passive recon (needs API keys), private
Collaborator-grade OOB (needs owned DNS infra), WAF bypass at scale (needs
IP diversity), LLM features at volume (needs inference budget).

---

## Part 4 — v2 build plan (maps to crews)

- **Crew A (foundations):** fix gaps 1-5, 8-10 (stealth+proxy, scope bug,
  TARGET_KIND filtering, extras contract, shared module base, CSP grading,
  jsintel/oauth FP fixes, pytest + lab harness wiring, report truncation).
- **Crew B (missing vuln classes):** gap 7 — SSRF, LFI/RFI, blind XXE,
  request smuggling, WebSocket, IDOR/BOLA, broken auth, CSRF, LDAP/XPath
  injection, deserialization probes, blind SQLi, injection harness across
  all locations (query/body/JSON/cookie/header/path), JWT deeper attacks,
  GraphQL POST + deeper checks.
- **Crew C (differentiators):** items 1-4, 6-14 from Part 3 — WAF mutation
  engine, JS/GraphQL diffing, OOB correlation, auth session manager, cache
  matrix, XS-Leaks, HTTP/3/gRPC, race tester, takeover monitoring, smart
  scope expansion, recon diff reports.
- **Crew D (engine + AI + UX):** async pipeline with rate limiting, YAML
  workflow v2, service-aware auto-enum (wire TECH_MODULE_MAP for real),
  proxy export flag, nuclei writer v2, CRM v2, reporting v2 (PDF, executive
  summary, remediation), autopilot v2, plugin SDK + 5 examples, AI triage
  v2 (dedup, FP learning, ask-arsenal NL planning), CLI UX (progress bars,
  completions, doctor), serve dashboard upgrade, business-logic packs
  (item 5), collaborative hunts (item 14), lab fixtures for all new modules.

Every new module must genuinely work against lab fixtures or local test
targets. Never claim unverified detections.
