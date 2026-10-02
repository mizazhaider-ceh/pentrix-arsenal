"""OOB CORRELATION ENGINE.

Differentiator #4. Burp Collaborator is the only good version of this and
it is paywalled plus manual; interactsh + nuclei leaves correlation to the
hunter by hand. This engine closes the loop:

    mint unique token per payload -> register it with the exact request
    (target, param, method, payload) -> poll the inbox -> auto-link each
    callback to the request that triggered it -> promote to findings.

Works against two inbox backends:

* "selfhost" (default, honest): the local arsenal inbox listener
  (`arsenal inbox --port 8888`). Polls the local registry + inbox.jsonl.
  The hunter must expose the listener to the target (VPS with a public
  IP, ngrok-style tunnel, or an in-scope callback host). No fake
  "private OOB service" is claimed: self-hosting the listener is ops
  work, documented below.

* "interactsh-public": mint token-style URLs under a public interactsh
  server for payload placement convenience. Polling a public server
  requires the interactsh client protocol (correlation-id registration
  + RSA-encrypted poll), which this client does NOT implement; use the
  official interactsh-client to poll and paste hits back, or self-host.
  The tradeoff is documented, not hidden.

Provider API::

    from arsenal import oob
    client = oob.OOBClient(base_url="http://my-vps:8888")
    token, cb_url = client.mint("ssrf", target=url, param="url",
                                payload=payload)
    ... fire payload containing cb_url ...
    matches = client.poll()          # [(hit, entry), ...]
    findings = client.promote(matches)  # finding dicts
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from arsenal import inbox as inbox_mod

SELFHOSTED_DOC = """
Self-hosting the OOB listener (honest ops notes):

1. Run `arsenal inbox --port 8888` on a box the target can reach
   (a cheap VPS with a public IP, or your lab VM when the target is
   local). Note the printed callback base URL.
2. Build the client with that base URL:
       client = oob.OOBClient(base_url="http://<vps-ip>:8888")
3. Mint tokens per payload; every token is unique per request, so a
   callback proves exactly which parameter fired.
4. Keep the listener running while you test, then client.poll().

Tradeoffs vs public interactsh servers (oast.pro / oast.live):
- Public servers are free and need no infra, BUT callbacks (target
  hostnames, payload context) transit third-party infrastructure, which
  many programs' rules forbid, and public correlation IDs are
  guessable/pollable by others. Self-hosted keeps everything on your
  box and works offline in a lab.
- interactsh-client remains the right tool for polling public servers;
  this engine's value is the token registry + auto-linking, which works
  with any inbox backend that can feed hits into poll_hits().
""".strip()


class OOBClient:
    """Mint tokens, register request context, poll, promote to findings."""

    def __init__(self, base_url: str, backend: str = "selfhost",
                 default_timeout: int = 20):
        self.base_url = str(base_url).rstrip("/")
        if backend not in ("selfhost", "interactsh-public"):
            raise ValueError("backend must be 'selfhost' or 'interactsh-public'")
        self.backend = backend
        self.default_timeout = default_timeout

    # -- minting ---------------------------------------------------------
    def callback_url(self, token: str) -> str:
        if self.backend == "interactsh-public":
            # token is embedded as a subdomain label under the public server
            return "http://%s.%s/" % (token.replace("_", "-"),
                                      self.base_url.split("://", 1)[-1].rstrip("/"))
        return inbox_mod.blind_url(self.base_url, token)

    def mint(self, vuln_class: str, target: str, param: str = "",
             method: str = "GET", payload: str = "",
             note: str = "") -> tuple[str, str]:
        """Mint a token, register it, return (token, callback_url)."""
        token = inbox_mod.mint_token(prefix=vuln_class[:4] or "ax")
        inbox_mod.register_token(token, {
            "vuln_class": vuln_class,
            "target": target,
            "param": param,
            "method": method,
            "payload": payload,
            "note": note,
            "backend": self.backend,
            "callback_url": self.callback_url(token),
        })
        return token, self.callback_url(token)

    # -- polling ----------------------------------------------------------
    def poll(self, since_ts: str | None = None,
             wait_seconds: float = 0.0) -> list[tuple[dict, dict]]:
        """Poll the inbox and auto-link hits to registered tokens.

        wait_seconds>0 polls repeatedly (blind payloads like XXE often
        take seconds to fire server-side).
        """
        deadline = time.time() + max(0.0, wait_seconds)
        matches: list[tuple[dict, dict]] = []
        seen_ids = set()
        while True:
            hits = inbox_mod.poll_hits(since_ts=since_ts)
            for hit, entry in inbox_mod.match_hits(hits):
                key = (entry.get("token"), hit.get("ts"))
                if key not in seen_ids:
                    seen_ids.add(key)
                    matches.append((hit, entry))
            if time.time() >= deadline:
                break
            time.sleep(1.0)
        return matches

    # -- promotion ---------------------------------------------------------
    def promote(self, matches) -> list[dict]:
        """Turn linked callbacks into findings with full evidence."""
        from arsenal.findings import make_finding
        findings = []
        for hit, entry in matches:
            vuln = entry.get("vuln_class", "oob")
            target = entry.get("target", "")
            param = entry.get("param", "")
            title = "Blind %s confirmed via OOB callback (param: %s)" % (
                vuln.upper(), param or "unknown")
            evidence = (
                "token=%s\ncallback_url=%s\n"
                "request: %s %s (param %r, payload %r)\n"
                "callback: %s %s%s from %s at %s\n"
                "callback matched the minted token, proving the target "
                "fetched the attacker-controlled URL." % (
                    entry.get("token"), entry.get("callback_url"),
                    entry.get("method"), target, param,
                    (entry.get("payload") or "")[:200],
                    hit.get("method"), hit.get("path"),
                    ("?" + hit["query"]) if hit.get("query") else "",
                    hit.get("client"), hit.get("ts")))
            findings.append(make_finding(
                "oob", target, "high", title,
                "An out-of-band interaction was observed for a %s payload "
                "placed in parameter %r. The callback carried the unique "
                "token minted for that exact request, which confirms the "
                "server-side request / code execution path." % (
                    vuln, param),
                evidence=evidence, confidence="strong",
                cwe=_CWE_FOR.get(vuln, ""),
                remediation="Validate and allowlist outbound fetch targets; "
                            "block server-side requests to untrusted hosts "
                            "at the egress layer."))
        return findings

    def pending(self) -> list[dict]:
        return inbox_mod.list_tokens(only_unmatched=True)


_CWE_FOR = {
    "ssrf": "CWE-918", "xxe": "CWE-611", "sqli": "CWE-89",
    "ssti": "CWE-94", "rce": "CWE-78", "lfi": "CWE-98",
    "redirect": "CWE-601", "xss": "CWE-79",
}


def selfhost_doc() -> str:
    return SELFHOSTED_DOC


ARGPARSE_SNIPPET = '''
# --- integrator: add to arsenal/cli.py subparsers ---
p = sub.add_parser("oob", help="OOB callback correlation engine")
osub = p.add_subparsers(dest="oob_cmd", required=True)
m = osub.add_parser("mint", help="Mint a token + callback URL for a payload")
m.add_argument("--class", dest="vuln_class", required=True,
               help="ssrf|xxe|sqli|ssti|rce|...")
m.add_argument("--target", required=True)
m.add_argument("--param", default="")
m.add_argument("--method", default="GET")
m.add_argument("--base-url", required=True,
               help="Inbox base URL, e.g. http://<vps-ip>:8888")
m.set_defaults(func=arsenal.oob.cmd_mint)
pl = osub.add_parser("poll", help="Poll inbox and link callbacks to requests")
pl.add_argument("--base-url", default="")
pl.add_argument("--wait", type=float, default=0.0)
pl.set_defaults(func=arsenal.oob.cmd_poll)
'''


def cmd_mint(args, ctx) -> int:
    client = OOBClient(base_url=args.base_url)
    token, url = client.mint(args.vuln_class, args.target,
                             param=args.param, method=args.method)
    print("token:        %s" % token)
    print("callback URL: %s" % url)
    print("Place the callback URL in the payload, then run: arsenal oob poll")
    return 0


def cmd_poll(args, ctx) -> int:
    client = OOBClient(base_url=args.base_url or "http://127.0.0.1:8888")
    matches = client.poll(wait_seconds=args.wait)
    if not matches:
        print("no callbacks linked to registered tokens yet "
              "(%d tokens pending)" % len(client.pending()))
        return 0
    for finding in client.promote(matches):
        print("[%s] %s" % (finding["severity"].upper(), finding["title"]))
        print(finding["evidence"])
        print("---")
    return 0
