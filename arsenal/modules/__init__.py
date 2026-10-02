"""Module registry for PENTRIX ARSENAL.

Every recon/scan module lives in this package and exposes NAME,
DESCRIPTION, TARGET_KIND and run(target, ctx). Registration is
defensive: one broken module file never prevents the rest from loading.
"""

import importlib

REGISTRY = {}


def register(mod):
    """Register a module object under its NAME; returns the module."""
    name = getattr(mod, "NAME", None) or getattr(mod, "__name__", "unknown")
    REGISTRY[name] = mod
    return mod


_MODULE_FILES = [
    "recon_mod", "portscan_mod", "tech_mod", "jssecrets_mod", "jsintel_mod",
    "headers_mod", "xss_mod", "sqli_mod", "jwt_mod", "cors_mod",
    "redirect_mod", "fuzz_mod", "paramminer_mod", "graphql_mod", "oauth_mod",
    "ssti_mod", "ppollution_mod", "cachepoison_mod", "hostheader_mod",
    "wordlist_mod", "hashid_mod", "phish_mod", "secrets_mod", "cve_mod",
]


def _load_all():
    for filename in _MODULE_FILES:
        try:
            mod = importlib.import_module("arsenal.modules." + filename)
        except Exception:
            continue
        try:
            register(mod)
        except Exception:
            continue


_load_all()
