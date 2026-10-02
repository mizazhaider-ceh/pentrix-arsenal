# Module Reference

All 24 scan modules registered in `arsenal.modules.REGISTRY`, generated from the live registry.

## Module-extras contract

`run(target, ctx)` returns either a plain list of findings or a dict:

```
{"findings": [...], "subdomains": [...], "alive": [...],
 "open_ports": [{"port": 80, "service": "http"}], "urls": [...],
 "tech": [...]}
```

Extras feed the pipeline's recursive discovery directly. Modules that only return finding lists
still work: the pipeline falls back to parsing finding titles (backward compatible).

`INTRUSIVE` is the single source of truth for gating: modules declaring `INTRUSIVE = True`
require `--intrusive` (or `ctx.allow_intrusive`); the pipeline reads the declaration at runtime.

## Catalog

| Module | Kind | Intrusive | Description |
|--------|------|-----------|-------------|
| `cachepoison` | url | yes | Probes for web cache poisoning by reflecting X-Forwarded-Host and checking for cache indicators in the respons |
| `cors` | url | no | Tests for CORS misconfiguration by sending a foreign Origin and checking whether Access-Control-Allow-Origin r |
| `cve` | keyword | no | Search NVD for CVEs matching a keyword. |
| `fuzz` | url | yes | Technology-aware parameter fuzzing: injects canary payloads chosen from ctx.tech_hint into each query paramete |
| `graphql` | url | no | Detects GraphQL endpoints with introspection enabled by sending a schema query to common GraphQL paths. |
| `hashid` | hash | no | Identify the algorithm of one or more hash strings by format. |
| `headers` | url | no | Checks HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) and reports |
| `hostheader` | url | no | Tests for Host header injection by overriding Host and sending X-Forwarded-Host, then checking for reflection  |
| `jsintel` | url | yes | JavaScript intelligence engine: extracts hidden API endpoints and parameter names from client-side JavaScript, |
| `jssecrets` | url | no | Discovers JavaScript files served by the target page and scans them for hard-coded secrets (API keys, tokens,  |
| `jwt` | token | no | Decodes JSON Web Tokens and reports common weaknesses: alg=none, weak HMAC secrets, weak algorithms, exp claim |
| `oauth` | url | no | Tests OAuth/OIDC authorization endpoints for unvalidated redirect_uri values and for acceptance of the implici |
| `paramminer` | url | yes | Discovers hidden query parameters by appending common parameter names with a canary value and flagging ones th |
| `phish` | url | no | Analyze a URL for phishing indicators (one finding per check). |
| `portscan` | ip | no | Async TCP port scan over common ports with banner grabbing |
| `ppollution` | url | yes | Tests for client/server-side prototype pollution sinks by injecting __proto__ and constructor[prototype] keys  |
| `recon` | domain | no | Passive subdomain enumeration (crt.sh, CertSpotter, hackertarget) with HTTP alive checks and subdomain-takeove |
| `redirect` | url | no | Detects open redirects by pointing redirect-style query parameters at an external host and checking whether th |
| `secrets` | path | no | Scans a local file or directory for exposed secrets (API keys, tokens, private keys) using rules adapted from  |
| `sqli` | url | yes | Probes URL query parameters for error-based SQL injection by sending break-out payloads and matching responses |
| `ssti` | url | yes | Probes for server-side template injection by injecting template expressions into parameters and the path and w |
| `tech` | url | no | Technology fingerprinting from headers, HTML markers and favicon hash |
| `wordlist` | url | no | Builds a targeted password wordlist from words found on the target site, with year, suffix and leet mutations  |
| `xss` | url | yes | Detects reflected cross-site scripting by injecting inert canary payloads into each query parameter and classi |

## Details

### `cachepoison`

- **TARGET_KIND:** `url`
- **INTRUSIVE:** True
- **Description:** Probes for web cache poisoning by reflecting X-Forwarded-Host and checking for cache indicators in the response.

### `cors`

- **TARGET_KIND:** `url`
- **INTRUSIVE:** False
- **Description:** Tests for CORS misconfiguration by sending a foreign Origin and checking whether Access-Control-Allow-Origin reflects it or uses a wildcard.

### `cve`

- **TARGET_KIND:** `keyword`
- **INTRUSIVE:** False
- **Description:** Search NVD for CVEs matching a keyword.

### `fuzz`

- **TARGET_KIND:** `url`
- **INTRUSIVE:** True
- **Description:** Technology-aware parameter fuzzing: injects canary payloads chosen from ctx.tech_hint into each query parameter and flags anomalous responses versus the baseline.

### `graphql`

- **TARGET_KIND:** `url`
- **INTRUSIVE:** False
- **Description:** Detects GraphQL endpoints with introspection enabled by sending a schema query to common GraphQL paths.

### `hashid`

- **TARGET_KIND:** `hash`
- **INTRUSIVE:** False
- **Description:** Identify the algorithm of one or more hash strings by format.

### `headers`

- **TARGET_KIND:** `url`
- **INTRUSIVE:** False
- **Description:** Checks HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) and reports each missing or weak header as a finding.

### `hostheader`

- **TARGET_KIND:** `url`
- **INTRUSIVE:** False
- **Description:** Tests for Host header injection by overriding Host and sending X-Forwarded-Host, then checking for reflection of the evil host.

### `jsintel`

- **TARGET_KIND:** `url`
- **INTRUSIVE:** True
- **Description:** JavaScript intelligence engine: extracts hidden API endpoints and parameter names from client-side JavaScript, then probes the discovered endpoints for unauthenticated access, verbose errors, and exposed debug or admin interfaces.

### `jssecrets`

- **TARGET_KIND:** `url`
- **INTRUSIVE:** False
- **Description:** Discovers JavaScript files served by the target page and scans them for hard-coded secrets (API keys, tokens, private keys) using rules adapted from pentrix-secrets.

### `jwt`

- **TARGET_KIND:** `token`
- **INTRUSIVE:** False
- **Description:** Decodes JSON Web Tokens and reports common weaknesses: alg=none, weak HMAC secrets, weak algorithms, exp claim problems, untrusted jku/x5u URLs, and suspicious kid values.

### `oauth`

- **TARGET_KIND:** `url`
- **INTRUSIVE:** False
- **Description:** Tests OAuth/OIDC authorization endpoints for unvalidated redirect_uri values and for acceptance of the implicit flow (response_type=token).

### `paramminer`

- **TARGET_KIND:** `url`
- **INTRUSIVE:** True
- **Description:** Discovers hidden query parameters by appending common parameter names with a canary value and flagging ones that change the response.

### `phish`

- **TARGET_KIND:** `url`
- **INTRUSIVE:** False
- **Description:** Analyze a URL for phishing indicators (one finding per check).

### `portscan`

- **TARGET_KIND:** `ip`
- **INTRUSIVE:** False
- **Description:** Async TCP port scan over common ports with banner grabbing

### `ppollution`

- **TARGET_KIND:** `url`
- **INTRUSIVE:** True
- **Description:** Tests for client/server-side prototype pollution sinks by injecting __proto__ and constructor[prototype] keys and checking for echo.

### `recon`

- **TARGET_KIND:** `domain`
- **INTRUSIVE:** False
- **Description:** Passive subdomain enumeration (crt.sh, CertSpotter, hackertarget) with HTTP alive checks and subdomain-takeover triage

### `redirect`

- **TARGET_KIND:** `url`
- **INTRUSIVE:** False
- **Description:** Detects open redirects by pointing redirect-style query parameters at an external host and checking whether the Location header follows it.

### `secrets`

- **TARGET_KIND:** `path`
- **INTRUSIVE:** False
- **Description:** Scans a local file or directory for exposed secrets (API keys, tokens, private keys) using rules adapted from pentrix-secrets, with redacted evidence.

### `sqli`

- **TARGET_KIND:** `url`
- **INTRUSIVE:** True
- **Description:** Probes URL query parameters for error-based SQL injection by sending break-out payloads and matching responses against DBMS error signatures.

### `ssti`

- **TARGET_KIND:** `url`
- **INTRUSIVE:** True
- **Description:** Probes for server-side template injection by injecting template expressions into parameters and the path and watching for evaluated output.

### `tech`

- **TARGET_KIND:** `url`
- **INTRUSIVE:** False
- **Description:** Technology fingerprinting from headers, HTML markers and favicon hash

### `wordlist`

- **TARGET_KIND:** `url`
- **INTRUSIVE:** False
- **Description:** Builds a targeted password wordlist from words found on the target site, with year, suffix and leet mutations for authorized testing.

### `xss`

- **TARGET_KIND:** `url`
- **INTRUSIVE:** True
- **Description:** Detects reflected cross-site scripting by injecting inert canary payloads into each query parameter and classifying the reflection context (script, attribute, tag, text).

