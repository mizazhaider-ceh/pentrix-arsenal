"""Scope management: in-scope domains, membership checks, coverage.

The Scope class parses .txt (one domain per line, # comments) or .csv
files (domain column: a "domain"/"target" header, else the first column).

CLI wiring (owned by arsenal.cli, which provides add_parsers/dispatch):
    arsenal scope <target> --import FILE | --show
"""

import csv
import json
import os

_SCOPE_FILE = "scope.json"


class Scope:
    """A set of in-scope domains with membership and coverage helpers."""

    def __init__(self, domains=None):
        seen = set()
        ordered = []
        for d in domains or []:
            d = _valid_domain(d)
            if d and d not in seen:
                seen.add(d)
                ordered.append(d)
        self._domains = ordered

    @staticmethod
    def load(path):
        """Parse path (.txt, .csv, or .json) into a Scope. Raises OSError."""
        path = os.path.expanduser(path)
        ext = os.path.splitext(path)[1].lower()
        if ext == ".csv":
            return Scope(_parse_csv(path))
        if ext == ".json":
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                data = data.get("domains", [])
            return Scope(data if isinstance(data, list) else [])
        return Scope(_parse_txt(path))

    def domains(self):
        """Return the in-scope domains as a list, in import order."""
        return list(self._domains)

    def contains(self, host):
        """True when host is exactly in scope or a subdomain of a scope domain.

        Case-insensitive; ports are stripped; trailing dots ignored.
        """
        host = _normalize_host(host)
        if not host:
            return False
        for domain in self._domains:
            if host == domain or host.endswith("." + domain):
                return True
        return False

    def save(self, path):
        """Write the scope as JSON ({"domains": [...]}) to path."""
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"domains": self._domains}, fh, indent=2)

    def coverage(self, report_data):
        """Coverage stats from report_data: domain -> {"reconned", "scanned", "reviewed"}.

        Returns {"total", "reconned", "scanned", "reviewed", "pct": {...}}.
        """
        report_data = report_data or {}
        scoped = [d for d in self._domains if d in report_data]
        total = len(scoped)
        reconned = sum(1 for d in scoped if report_data[d].get("reconned"))
        scanned = sum(1 for d in scoped if report_data[d].get("scanned"))
        reviewed = sum(1 for d in scoped if report_data[d].get("reviewed"))

        def pct(n):
            return round(100.0 * n / total, 1) if total else 0.0

        return {
            "total": total,
            "reconned": reconned,
            "scanned": scanned,
            "reviewed": reviewed,
            "pct": {
                "reconned": pct(reconned),
                "scanned": pct(scanned),
                "reviewed": pct(reviewed),
            },
        }


def _valid_domain(value):
    value = (value or "").strip().lower()
    if not value or any(ch.isspace() for ch in value):
        return None
    # Strip an explicit port (host:port) so stored domains are bare hosts.
    if value.startswith("["):
        value = value.split("]", 1)[0][1:]
    elif value.count(":") == 1:
        value = value.rsplit(":", 1)[0]
    value = value.rstrip(".")
    return value or None


def _parse_txt(path):
    domains = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if " #" in line:  # allow trailing inline comments
                line = line.split(" #", 1)[0].strip()
            domain = _valid_domain(line)
            if domain:
                domains.append(domain)
    return domains


def _parse_csv(path):
    domains = []
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.reader(fh)
        rows = [row for row in reader if any(cell.strip() for cell in row)]
    if not rows:
        return domains
    header = [cell.strip().lower() for cell in rows[0]]
    if "domain" in header:
        idx = header.index("domain")
        data_rows = rows[1:]
    elif "target" in header:
        idx = header.index("target")
        data_rows = rows[1:]
    else:
        idx = 0
        data_rows = rows
    for row in data_rows:
        if idx < len(row):
            domain = _valid_domain(row[idx])
            if domain:
                domains.append(domain)
    return domains


def _normalize_host(host):
    """Lowercase, strip port and trailing dot from a host string."""
    host = (host or "").strip().lower()
    if not host:
        return ""
    if host.startswith("["):  # [ipv6]:port
        host = host.split("]", 1)[0][1:]
    elif host.count(":") == 1:  # host:port
        host = host.rsplit(":", 1)[0]
    return host.rstrip(".")


# ------------------------------------------------------------------
# CLI wiring
# ------------------------------------------------------------------

def add_parsers(sub):
    """Register `arsenal scope <target> --import FILE | --show`."""
    parser = sub.add_parser("scope", help="Manage the in-scope domain list.")
    parser.add_argument("target", help="Workspace directory holding scope.json.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--import", dest="import_file", metavar="FILE",
                       help="Import scope from a .txt/.csv/.json file.")
    group.add_argument("--show", action="store_true",
                       help="Show the current scope domains.")
    parser.set_defaults(func=dispatch)
    return parser


def _workspace_dir(args, ctx):
    target = getattr(args, "target", None)
    if target and os.path.isdir(target):
        return target
    ws = getattr(ctx, "workspace", None)
    if ws is not None and hasattr(ws, "path"):
        try:
            return ws.path(target or "default")
        except Exception:
            pass
    if isinstance(ctx, dict):
        return ctx.get("workspace") or "."
    return "."


def dispatch(args, ctx):
    """Run the scope subcommand. Returns an exit code int.

    Stores/reads scope.json in the workspace directory.
    """
    workspace = _workspace_dir(args, ctx)
    scope_file = os.path.join(workspace, _SCOPE_FILE)

    import_file = getattr(args, "import_file", None)
    if import_file:
        try:
            scope = Scope.load(import_file)
        except OSError as exc:
            print("error: cannot read %r: %s" % (import_file, exc))
            return 1
        try:
            scope.save(scope_file)
        except OSError as exc:
            print("error: cannot write %r: %s" % (scope_file, exc))
            return 1
        print("Imported %d domain(s) into %s." % (len(scope.domains()), scope_file))
        return 0

    if getattr(args, "show", False):
        if not os.path.isfile(scope_file):
            print("No scope defined yet (missing %s). Use --import FILE first."
                  % scope_file)
            return 1
        try:
            scope = Scope.load(scope_file)
        except (OSError, ValueError) as exc:
            print("error: cannot read %r: %s" % (scope_file, exc))
            return 1
        for domain in scope.domains():
            print(domain)
        return 0

    return 2
