"""Scope unit tests, including the audited URL-target regression."""

import os
import tempfile

from arsenal.scope import Scope


def test_exact_and_subdomain():
    scope = Scope(["example.com"])
    assert scope.contains("example.com")
    assert scope.contains("sub.example.com")
    assert scope.contains("deep.sub.example.com")
    assert not scope.contains("example.com.evil.com")
    assert not scope.contains("evil.com")


def test_url_targets_are_normalized():
    """Regression: scope.contains() used to reject every URL target when a
    scope file was set, because it never stripped the scheme/path."""
    scope = Scope(["example.com"])
    assert scope.contains("https://example.com/page?q=1")
    assert scope.contains("http://example.com:8080/a/b?x=1#frag")
    assert scope.contains("https://user:pass@sub.example.com/")
    assert scope.contains("https://example.com./")  # trailing dot
    assert not scope.contains("https://evil.com/?x=example.com")


def test_host_port_forms():
    scope = Scope(["example.com"])
    assert scope.contains("example.com:8443")
    assert scope.contains("[::1]") is False  # not in scope, but must not crash
    ip_scope = Scope(["::1"])
    assert ip_scope.contains("[::1]:8080")


def test_case_insensitive():
    scope = Scope(["Example.COM"])
    assert scope.contains("HTTPS://SUB.EXAMPLE.COM/X")


def test_wildcard_entries():
    scope = Scope(["*.example.com"])
    assert scope.contains("a.example.com")
    assert scope.contains("https://deep.a.example.com/x")
    assert not scope.contains("example.com")  # wildcard needs a subdomain
    assert not scope.contains("example.com.evil.com")


def test_cidr_entries():
    scope = Scope(["10.0.0.0/8"])
    assert scope.contains("10.1.2.3")
    assert scope.contains("http://10.9.9.9:8080/x")
    assert not scope.contains("11.0.0.1")
    assert not scope.contains("example.com")


def test_single_ip_entry():
    scope = Scope(["203.0.113.7"])
    assert scope.contains("203.0.113.7")
    assert not scope.contains("203.0.113.8")


def test_empty_and_garbage():
    scope = Scope(["example.com"])
    assert not scope.contains("")
    assert not scope.contains(None)
    assert not scope.contains("not a host!!")


def test_load_txt_and_roundtrip():
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("# comment\n\nexample.com\n*.internal.example\n10.0.0.0/8\n")
        path = fh.name
    try:
        scope = Scope.load(path)
        assert scope.contains("https://a.internal.example/x")
        assert scope.contains("10.2.3.4")
        out = path + ".json"
        scope.save(out)
        again = Scope.load(out)
        assert again.contains("https://a.internal.example/x")
        assert again.contains("10.2.3.4")
    finally:
        os.unlink(path)
        if os.path.exists(path + ".json"):
            os.unlink(path + ".json")


def test_dedupes_entries():
    scope = Scope(["example.com", "EXAMPLE.COM ", "*.example.com",
                   "*.example.com"])
    assert scope.domains() == ["example.com"]
