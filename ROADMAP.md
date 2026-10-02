# PENTRIX ARSENAL Roadmap

70 ideas tracked in the open: what shipped in v0.1.0 and what is planned.
Status key: **SHIPPED** (in this release) / **PLANNED** (on the list).

## Recon

| # | Idea | Status |
|---|---|---|
| 1 | Certificate transparency monitoring (new certs = early subdomain discovery) | SHIPPED |
| 2 | Cloud asset discovery (buckets derived from target names) | SHIPPED (v2.0.0: scopex.py) |
| 3 | GitHub code search for org leaks | PLANNED |
| 4 | Shodan/Censys integration for exposed services | PLANNED |
| 5 | ASN and IP range expansion from known assets | SHIPPED (v2.0.0: scopex.py, BGPView/RIPEstat) |
| 6 | Reverse WHOIS infrastructure mapping | PLANNED |
| 7 | DNS history lookup (old A records to forgotten servers) | PLANNED |
| 8 | Subdomain takeover detection (dangling CNAME auto-check) | SHIPPED |
| 9 | Favicon hash tech identification | SHIPPED |
| 10 | WAF/CDN detection and fingerprinting | SHIPPED |

## Scanning

| # | Idea | Status |
|---|---|---|
| 11 | Nuclei template integration (run community templates through arsenal) | PLANNED |
| 12 | Tech-aware smart fuzzing (payloads matched to detected stack) | SHIPPED |
| 13 | Hidden parameter discovery | SHIPPED |
| 14 | HTTP request smuggling checks | SHIPPED (v2.0.0: smuggle_mod, raw-socket CL.TE/TE.CL) |
| 15 | GraphQL introspection and exploitation helpers | SHIPPED |
| 16 | WebSocket security testing | SHIPPED (v2.0.0: ws_mod, raw Upgrade handshake) |
| 17 | JWT attack automation (none alg, weak secrets, jku/x5u) | SHIPPED |
| 18 | OAuth/OIDC misconfiguration tester | SHIPPED |
| 19 | Self-hosted SSRF callback listener (interactsh-style) | SHIPPED |
| 20 | Blind XXE with out-of-band listener | SHIPPED (v2.0.0: xxe_mod + oob correlation engine) |
| 21 | SSTI detection across template engines | SHIPPED |
| 22 | Prototype pollution scanner | SHIPPED |
| 23 | Cache poisoning and web cache deception checks | SHIPPED |
| 24 | Host header injection tester | SHIPPED |
| 25 | AI-generated business logic test scenarios per app type | SHIPPED (v2.0.0: business-logic.yaml workflow pack + ask-arsenal) |

## AI

| # | Idea | Status |
|---|---|---|
| 26 | AI false-positive killer (re-examines findings with fresh eyes) | SHIPPED (v2.0.0: FP feedback learning, rule-based + LLM) |
| 27 | AI payload mutator (adapts payloads to observed WAF behavior) | SHIPPED (v2.0.0: mutate.py adaptive engine, 10 strategies) |
| 28 | Platform-specific report writer (YesWeHack and HackerOne formats) | SHIPPED |
| 29 | Natural language hunt queries over workspace data (`arsenal ask`) | SHIPPED |
| 30 | Personal hunting profile (learns your best bug classes) | PLANNED |

## Monitoring

| # | Idea | Status |
|---|---|---|
| 31 | Technology change radar | SHIPPED |
| 32 | JavaScript file change monitoring with smart diffs | SHIPPED |
| 33 | Exposed .git/.env watch across all targets | SHIPPED |
| 34 | Pastebin and leak monitoring for the target domain | PLANNED |
| 35 | Breach-data mention check for target credentials | PLANNED |

## Workflow

| # | Idea | Status |
|---|---|---|
| 36 | Lab mode (local vulnerable targets to practice each module) | SHIPPED |
| 37 | Methodology checklists per vuln class | SHIPPED |
| 38 | Session replay (every command logged, replay hunts) | SHIPPED |
| 39 | Team workspaces (shared findings) | PLANNED |
| 40 | Time tracker (hours per target vs payout) | SHIPPED |
| 41 | Goal tracker (monthly bounty targets) | SHIPPED |
| 42 | Methodology templates (API testing, web app, mobile backend) | SHIPPED (v2.0.0: workflows + docs) |

## Reporting

| # | Idea | Status |
|---|---|---|
| 43 | Executive summary generator | SHIPPED |
| 44 | Cross-target finding comparison | SHIPPED |
| 45 | Video proof capture for confirmed exploits | PLANNED |
| 46 | CVSS calculator with severity auto-scoring | SHIPPED |

## Stealth and safety

| # | Idea | Status |
|---|---|---|
| 47 | Stealth mode (rate limits, jitter, rotating user agents) | SHIPPED |
| 48 | Safe-mode guardrails (intrusive checks need an explicit flag) | SHIPPED |
| 49 | Scope firewall (hard block on out-of-scope, even on typos) | SHIPPED |

## Ecosystem

| # | Idea | Status |
|---|---|---|
| 50 | Crowdsourced report template library per bug class | SHIPPED (v2.0.0: arsenal templates) |

## Distilled from the community's best bounty tooling

Twenty ideas researched from the most-starred GitHub bug bounty projects,
with inspiration credited. What fits the framework's architecture shipped in
v0.1.0; what needs external infrastructure is planned.

| # | Idea | Inspiration | Status |
|---|---|---|---|
| 1 | Passive-only mode (`--passive`: zero active scanning, OSINT only) | BBOT (9.6k stars, BlackLanternSecurity) | SHIPPED |
| 2 | Recursive event-driven discovery (findings trigger new scans automatically) | BBOT | SHIPPED |
| 3 | Declarative YAML workflows, shareable like nuclei templates | Osmedeos / Axiom (distributed era, 6.2k stars) | SHIPPED |
| 4 | Fleet mode (split scans across multiple VPS machines) | Osmedeos / Axiom | PLANNED |
| 5 | Web UI + REST API for results and integrations | Osmedeos / Axiom | SHIPPED |
| 6 | Agentic autopilot mode (plan, scan, analyze, re-target loop) | 2026 agentic wave (e.g. Agentic-Bug-Hunter) | SHIPPED |
| 7 | Persistent hunt memory, queryable across sessions | 2026 agentic wave | SHIPPED |
| 8 | Visual pipeline view (see the workflow as a graph) | reconftw / coli / bounty-stack | SHIPPED |
| 9 | Scan resume (`--resume` continues interrupted scans) | reconftw / coli / bounty-stack | SHIPPED |
| 10 | Self-hosted blind callback inbox for OOB testing | interactsh / XSS Hunter / BXSS | SHIPPED |
| 11 | Built-in offline payload vault, searchable | ARS3NAL by inflictx (payload cheatsheet app) | SHIPPED |
| 12 | One-command reverse shell generator | ARS3NAL by inflictx | SHIPPED |
| 13 | New program radar (ingest platform scope dumps) | bounty-targets-data / BBRF | PLANNED |
| 14 | Scope-change alerts (auto-recon newly added assets) | bounty-targets-data / BBRF | PLANNED |
| 15 | Multi-channel notifications (Discord/Slack/Telegram/webhooks) | notify by projectdiscovery | SHIPPED |
| 16 | Service-aware auto-enumeration (service dictates next checks) | autorecon / spiderfoot | SHIPPED |
| 17 | OSINT fusion (emails, people, tech feeding wordlists) | autorecon / spiderfoot | PLANNED |
| 18 | Nuclei template writer (confirmed finding to regression template) | pro integrations | SHIPPED |
| 19 | Proxy export (Burp Suite site-map import) | pro integrations | SHIPPED |
| 20 | Duplicate prediction across programs | pro integrations | SHIPPED |

Note on positioning: ARS3NAL (inflictx) is a payload cheatsheet web app;
PENTRIX ARSENAL is an automation framework. The names resemble each other,
but the positioning is distinct: automation and orchestration, not
cheatsheets. The payload vault here exists to serve the automation.
