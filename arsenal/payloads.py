"""OFFLINE PAYLOAD VAULT CLI.

Reads probe payloads from arsenal/payloads/*.txt (one payload per line,
lines starting with # are comments).

    arsenal payloads --list        list payload classes with counts
    arsenal payloads --class xss   print numbered payloads of a class
    arsenal payloads --search Q    search all classes for Q
    arsenal payloads --copy N      print just payload N (from --class, default xss)

Missing vault files are tolerated gracefully: a class with no file is
simply skipped and an empty vault produces a clean message, not a crash.

Authorized engagements only: probe payloads are for targets you have
written permission to test.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

console = Console()

VAULT_DIR = Path(__file__).with_name("payloads")


def _load_vault():
    """Return {class_name: [payload, ...]}, tolerating a missing vault."""
    result = {}
    if not VAULT_DIR.is_dir():
        return result
    for path in sorted(VAULT_DIR.glob("*.txt")):
        payloads = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                payloads.append(line)
        result[path.stem] = payloads
    return result


def cmd_payloads(args, ctx) -> int:
    vault = _load_vault()
    if not vault:
        console.print(f"[yellow]Payload vault is empty or missing: {VAULT_DIR}[/]")
        return 0

    if args.list:
        console.print("[bold]Payload vault classes[/]:")
        total = 0
        for cls in sorted(vault):
            n = len(vault[cls])
            total += n
            console.print(f"  [cyan]{cls}[/]: {n} payloads")
        console.print(f"Total: {total} payloads in {len(vault)} classes.")
        return 0

    if args.search:
        query = args.search.lower()
        hits = 0
        for cls in sorted(vault):
            for i, payload in enumerate(vault[cls], 1):
                if query in payload.lower():
                    console.print(f"[cyan]{cls}[/] #{i}: {payload}")
                    hits += 1
        console.print(f"{hits} match(es) for '{args.search}'.")
        return 0

    if args.copy is not None:
        cls = args.cls or "xss"
        if cls not in vault:
            console.print(f"[red]Unknown class '{cls}'. Use --list to see classes.[/]")
            return 1
        payloads = vault[cls]
        n = args.copy
        if n < 1 or n > len(payloads):
            console.print(f"[red]Payload #{n} out of range for class '{cls}' (1-{len(payloads)}).[/]")
            return 1
        print(payloads[n - 1])  # just the payload, nothing else
        return 0

    cls = args.cls
    if not cls:
        console.print("[red]Specify --class NAME, or use --list / --search / --copy.[/]")
        return 1
    if cls not in vault:
        console.print(f"[red]Unknown class '{cls}'. Use --list to see classes.[/]")
        return 1
    console.print(f"[bold]Payloads in class[/] [cyan]{cls}[/]:")
    for i, payload in enumerate(vault[cls], 1):
        console.print(f"  [dim]{i:>3}[/] {payload}")
    return 0


def add_parsers(sub):
    p = sub.add_parser(
        "payloads",
        help="Offline probe-payload vault (xss, sqli, ssti, ...)",
        description=(
            "Browse the offline payload vault in arsenal/payloads/*.txt. "
            "Authorized engagements only."
        ),
    )
    p.add_argument("--list", action="store_true",
                   help="List payload classes with payload counts")
    p.add_argument("--class", dest="cls", metavar="NAME",
                   help="Payload class to show (e.g. xss, sqli)")
    p.add_argument("--search", metavar="QUERY",
                   help="Search all classes for payloads containing QUERY")
    p.add_argument("--copy", type=int, metavar="N",
                   help="Print just payload N from --class (default xss), nothing else")
    p.set_defaults(func=cmd_payloads)
    return p


def dispatch(args, ctx):
    func = getattr(args, "func", None)
    if callable(func):
        return func(args, ctx)
    raise ValueError("no command dispatch configured for payloads")
