"""User plugin loader for PENTRIX ARSENAL.

Plugins are plain .py files dropped into ~/.arsenal/plugins/. Each one
must expose NAME, DESCRIPTION, TARGET_KIND and a run(target, ctx)
callable. Broken plugins are skipped with no effect on the rest.
"""

import importlib.util
import os

PLUGIN_DIR = os.path.expanduser("~/.arsenal/plugins")

# The 4-attribute contract every plugin must satisfy. INTRUSIVE is
# optional (defaults to False) but strongly recommended.
_REQUIRED_ATTRS = ("NAME", "DESCRIPTION", "TARGET_KIND", "run")
_OPTIONAL_ATTRS = ("INTRUSIVE", "VERSION", "AUTHOR")


def load_plugins():
    """Import every valid plugin file; returns {NAME: module}."""
    plugins = {}
    try:
        files = sorted(os.listdir(PLUGIN_DIR))
    except OSError:
        return plugins
    for fname in files:
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        path = os.path.join(PLUGIN_DIR, fname)
        modname = "arsenal_plugin_" + fname[:-3]
        try:
            spec = importlib.util.spec_from_file_location(modname, path)
            if spec is None or spec.loader is None:
                continue
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        except Exception:
            continue
        if not all(hasattr(mod, attr) for attr in _REQUIRED_ATTRS):
            continue
        if not callable(getattr(mod, "run", None)):
            continue
        # Normalize the optional INTRUSIVE flag so the pipeline can read it.
        if not hasattr(mod, "INTRUSIVE"):
            mod.INTRUSIVE = False
        mod.__plugin_path__ = path
        plugins[mod.NAME] = mod
    return plugins


def plugins_for_kind(kind):
    """Return {NAME: module} for plugins with the given TARGET_KIND."""
    wanted = str(kind or "").lower()
    return {name: mod for name, mod in load_plugins().items()
            if str(getattr(mod, "TARGET_KIND", "")).lower() == wanted}


def validate_plugin(mod):
    """Check a plugin module against the contract. Returns [problems]."""
    problems = []
    for attr in _REQUIRED_ATTRS:
        if not hasattr(mod, attr):
            problems.append("missing required attribute: %s" % attr)
    if hasattr(mod, "run") and not callable(mod.run):
        problems.append("run is not callable")
    kind = str(getattr(mod, "TARGET_KIND", "")).lower()
    if kind and kind not in ("domain", "url", "ip", "hash", "path",
                             "keyword", "token"):
        problems.append("unknown TARGET_KIND %r" % kind)
    return problems


def add_parsers(subparsers):
    """Register `arsenal plugins` (list loaded plugins)."""
    p = subparsers.add_parser("plugins", help="List loaded user plugins")
    p.set_defaults(func=dispatch)


def dispatch(args, ctx):
    """Print loaded plugins including their source path."""
    plugins = load_plugins()
    if not plugins:
        print("no plugins loaded (drop .py files into %s)" % PLUGIN_DIR)
        return 0
    print("%-20s %-10s %s" % ("NAME", "TARGET", "DESCRIPTION / PATH"))
    print("-" * 70)
    for name in sorted(plugins):
        mod = plugins[name]
        print("%-20s %-10s %s" % (name, mod.TARGET_KIND, mod.DESCRIPTION))
        print("%-20s %-10s %s" % ("", "", getattr(mod, "__plugin_path__", "?")))
    return 0
