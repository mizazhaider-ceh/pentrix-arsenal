"""Module registry smoke tests + shared-base sanity."""

import glob
import os

import arsenal.modules as modules_pkg
from arsenal.modules import base as base_mod
from arsenal.modules import jscrawl, secret_rules


def test_all_module_files_import():
    root = os.path.dirname(modules_pkg.__file__)
    files = sorted(os.path.basename(p)[:-3]
                   for p in glob.glob(os.path.join(root, "*_mod.py")))
    assert len(files) == 43  # 24 v1 + 19 v2 modules
    for name in files:
        __import__("arsenal.modules." + name, fromlist=["*"])


def test_registry_contract():
    assert len(modules_pkg.REGISTRY) == 43  # 24 v1 + 19 v2 modules
    for name, mod in modules_pkg.REGISTRY.items():
        assert getattr(mod, "NAME", None) == name
        assert getattr(mod, "DESCRIPTION", "")
        assert getattr(mod, "TARGET_KIND", None) in (
            "url", "domain", "ip", "host", "token", "hash", "keyword", "path")
        assert isinstance(getattr(mod, "INTRUSIVE", None), bool)
        assert callable(getattr(mod, "run", None))


def test_base_module_helpers():
    mod = base_mod.BaseModule("demo", 7)
    assert mod.timeout(None) == 7
    assert mod.timeout(object()) == 7
    assert mod.is_http_url("https://example.com/x")
    assert not mod.is_http_url("example.com")
    assert not mod.is_http_url("ftp://example.com/")
    assert mod.host_of("https://sub.example.com:8443/a") == "sub.example.com"
    assert mod.in_scope("https://example.com/", None) is True
    f = mod.finding(target="t", severity="info", title="T",
                    description="d")
    assert f["module"] == "demo"


def test_base_guard():
    from arsenal.context import make_ctx
    mod = base_mod.BaseModule("demo", 5)
    ctx = make_ctx(config={}, safe_mode=True, allow_intrusive=False)
    assert mod.guard("https://example.com/", ctx,
                     intrusive=True) is not None  # blocked
    ctx2 = make_ctx(config={}, safe_mode=False, allow_intrusive=True)
    assert mod.guard("https://example.com/", ctx2, intrusive=True) is None
    assert mod.guard("notaurl", ctx2) is not None  # require_url


def test_shared_secret_rules_single_table():
    from arsenal.modules import jssecrets_mod, secrets_mod
    assert jssecrets_mod.RULES is secret_rules.RULES
    assert secrets_mod.RULES is secret_rules.RULES
    assert len(secret_rules.RULES) == 10
    matches = secret_rules.scan_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
    assert matches and matches[0]["rule"] == "AWS Access Key ID"
    assert secret_rules.redact("AKIAIOSFODNN7EXAMPLE").startswith("AKIA")


def test_shared_jscrawl():
    html = ('<html><head><script src="/app.js"></script>'
            '<script src="https://cdn.example.net/x.js"></script></head></html>')
    urls = jscrawl.discover_js_urls("https://example.com/page", html)
    assert "https://example.com/app.js" in urls
    assert not any("cdn.example.net" in u for u in urls)  # cross-host dropped
