"""OUTBOUND ALERTS (Discord / Slack / Telegram / generic webhook).

Configuration lives in ctx.config["notifications"]:
    {
        "discord_webhook": "https://discord.com/api/webhooks/...",
        "slack_webhook": "https://hooks.slack.com/services/...",
        "telegram_bot_token": "...",
        "telegram_chat_id": "...",
        "generic_webhook": "https://example.com/hook",
    }

send_alert(title, body, ctx) POSTs to every configured channel.
Best effort: it never raises; per-channel results are returned and a
configured ctx.log is informed of failures.

    arsenal notify --test   send a test alert to all configured channels
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from rich.console import Console

console = Console()

_TIMEOUT = 10


def _post(url: str, payload: dict, data: bytes | None = None) -> str:
    """POST and return a short status string. Raises on failure."""
    body = data if data is not None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "pentrix-arsenal"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return f"HTTP {resp.status}"


def send_alert(title, body, ctx):
    """POST title/body to every configured channel. Never raises.

    Returns a list of (channel, ok, detail) tuples.
    """
    cfg = getattr(ctx, "config", None)
    notif = {}
    if isinstance(cfg, dict):
        notif = cfg.get("notifications") or {}
    if not isinstance(notif, dict):
        notif = {}

    channels = []
    discord = notif.get("discord_webhook")
    slack = notif.get("slack_webhook")
    tg_token = notif.get("telegram_bot_token")
    tg_chat = notif.get("telegram_chat_id")
    generic = notif.get("generic_webhook")

    if discord:
        channels.append(("discord", discord,
                         {"content": f"**{title}**\n{body}"}))
    if slack:
        channels.append(("slack", slack,
                         {"text": f"*{title}*\n{body}"}))
    if tg_token and tg_chat:
        channels.append(("telegram",
                         f"https://api.telegram.org/bot{tg_token}/sendMessage",
                         {"chat_id": tg_chat, "text": f"{title}\n{body}"}))
    if generic:
        channels.append(("generic", generic,
                         {"title": title, "body": body, "source": "pentrix-arsenal"}))

    results = []
    log = getattr(ctx, "log", None)
    for name, url, payload in channels:
        try:
            detail = _post(url, payload)
            results.append((name, True, detail))
        except Exception as exc:  # best effort: never raise
            detail = f"{type(exc).__name__}: {exc}"
            results.append((name, False, detail))
            if log is not None and hasattr(log, "warning"):
                try:
                    log.warning("notify: %s failed: %s", name, detail)
                except Exception:
                    pass
    return results


def cmd_notify(args, ctx) -> int:
    if args.test:
        results = send_alert(
            "Arsenal notify test",
            "This is a test alert from pentrix-arsenal. No action needed.",
            ctx,
        )
        if not results:
            console.print("[yellow]No notification channels configured.[/]")
            console.print("Set ctx.config['notifications'] with discord_webhook, "
                          "slack_webhook, telegram_bot_token + telegram_chat_id, "
                          "and/or generic_webhook.")
            return 0
        for name, ok, detail in results:
            mark = "[green]OK[/]" if ok else "[red]FAIL[/]"
            console.print(f"  {name}: {mark} ({detail})")
        return 0
    console.print("[red]Nothing to do. Use --test to send a test alert.[/]")
    return 1


def add_parsers(sub):
    p = sub.add_parser(
        "notify",
        help="Send alerts to configured notification channels",
        description=(
            "POST alerts to Discord, Slack, Telegram and/or a generic "
            "webhook from ctx.config['notifications']. Best effort: "
            "failures are reported, never raised."
        ),
    )
    p.add_argument("--test", action="store_true",
                   help="Send a test alert to all configured channels")
    p.set_defaults(func=cmd_notify)
    return p


def dispatch(args, ctx):
    func = getattr(args, "func", None)
    if callable(func):
        return func(args, ctx)
    raise ValueError("no command dispatch configured for notify")
