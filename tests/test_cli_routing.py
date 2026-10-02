"""CLI target-shape classification and TARGET_KIND routing tests."""

from types import SimpleNamespace

from arsenal import modules as modules_pkg
from arsenal.cli import _apply_proxy_override, _route_module, _target_shape
from arsenal.context import make_ctx


def test_target_shape():
    assert _target_shape("https://example.com/a?q=1") == "url"
    assert _target_shape("http://example.com/") == "url"
    assert _target_shape("example.com") == "domain"
    assert _target_shape("sub.example.com") == "domain"
    assert _target_shape("1.2.3.4") == "ip"
    assert _target_shape("::1") == "ip"
    assert _target_shape("wordpress") == "keyword"
    assert _target_shape("5d41402abc4b2a76b9719d911017c592") == "hash"
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dummy-signature_abc"
    assert _target_shape(token) == "token"
    assert _target_shape("") == "unknown"
    assert _target_shape("ftp://example.com/x") == "unknown"


def test_target_shape_existing_path(tmp_path):
    p = tmp_path / "targets.txt"
    p.write_text("example.com\n")
    assert _target_shape(str(p)) == "path"


def _by_kind(kind):
    return [m for m in modules_pkg.REGISTRY.values()
            if getattr(m, "TARGET_KIND", None) == kind]


def test_url_modules_get_full_url_from_domain():
    for mod in _by_kind("url"):
        routed = _route_module(mod, "example.com", "domain")
        assert routed == "https://example.com", mod.NAME


def test_mistyped_targets_skipped():
    # jwt/secrets/hashid/cve must not run against a bare domain.
    for kind in ("token", "hash", "keyword", "path"):
        for mod in _by_kind(kind):
            assert _route_module(mod, "example.com", "domain") is None, mod.NAME


def test_token_target_only_runs_jwt():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dummy-signature_abc"
    ran = [m.NAME for m in modules_pkg.REGISTRY.values()
           if _route_module(m, token, "token") is not None]
    assert ran == ["jwt", "jwt_adv"]  # v2: both token modules route


def test_hash_target_only_runs_hashid():
    h = "5d41402abc4b2a76b9719d911017c592"
    ran = [m.NAME for m in modules_pkg.REGISTRY.values()
           if _route_module(m, h, "hash") is not None]
    assert ran == ["hashid"]


def test_path_target_only_runs_secrets(tmp_path):
    p = tmp_path / "code.py"
    p.write_text("x = 1\n")
    ran = [m.NAME for m in modules_pkg.REGISTRY.values()
           if _route_module(m, str(p), "path") is not None]
    assert ran == ["secrets"]


def test_ip_target_routes_portscan_and_url_modules():
    portscan = modules_pkg.REGISTRY["portscan"]
    assert _route_module(portscan, "1.2.3.4", "ip") == "1.2.3.4"
    xss = modules_pkg.REGISTRY["xss"]
    assert _route_module(xss, "1.2.3.4", "ip") == "http://1.2.3.4"


def test_domain_modules_get_bare_host_from_url():
    recon = modules_pkg.REGISTRY["recon"]
    assert _route_module(recon, "https://sub.example.com/a", "url") == \
        "sub.example.com"


def test_jwt_also_accepts_url_targets():
    jwt = modules_pkg.REGISTRY["jwt"]
    assert _route_module(jwt, "https://example.com/", "url") == \
        "https://example.com/"


def test_proxy_override_applies_to_ctx():
    ctx = make_ctx(config={"proxy": {"enabled": False, "url": "",
                                     "no_proxy": "127.0.0.1,localhost"}})
    args = SimpleNamespace(proxy="http://127.0.0.1:8080")
    _apply_proxy_override(args, ctx)
    proxy = ctx.config["proxy"]
    assert proxy["enabled"] is True
    assert proxy["url"] == "http://127.0.0.1:8080"
    assert proxy["no_proxy"] == ""  # explicit proxy bypasses no_proxy


def test_proxy_override_absent_leaves_config():
    ctx = make_ctx(config={"proxy": {"enabled": False, "url": "x"}})
    _apply_proxy_override(SimpleNamespace(proxy=None), ctx)
    assert ctx.config["proxy"] == {"enabled": False, "url": "x"}
