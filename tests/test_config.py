"""Config default knobs: proxy and http blocks exist with sane defaults."""

from arsenal import config as config_mod


def test_proxy_defaults():
    cfg = config_mod.load()
    proxy = cfg.get("proxy")
    assert isinstance(proxy, dict)
    assert proxy.get("enabled") is False
    assert "url" in proxy and "no_proxy" in proxy


def test_http_defaults():
    cfg = config_mod.load()
    http_cfg = cfg.get("http")
    assert isinstance(http_cfg, dict)
    assert http_cfg.get("retries", 0) >= 0
    assert http_cfg.get("backoff", 0) >= 0
    assert http_cfg.get("max_read_bytes", 0) > 0
    assert http_cfg.get("pool_size", 0) > 0


def test_stealth_defaults_preserved():
    cfg = config_mod.load()
    stealth = cfg.get("stealth")
    assert isinstance(stealth, dict)
    assert stealth.get("enabled") is False
