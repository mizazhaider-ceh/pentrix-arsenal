"""Finding model tests: validation, CVSS wiring, dedup keys."""

from arsenal import cvss as cvss_lib
from arsenal.findings import dedup_key, make_finding, validate


def test_make_finding_defaults():
    f = make_finding("xss", "https://example.com/", "high", "XSS here",
                     "desc")
    assert validate(f)
    assert f["severity"] == "high"
    assert f["confidence"] == "review"
    assert f["module"] == "xss"
    assert f["ts"]


def test_severity_confidence_normalization():
    f = make_finding("x", "t", "CRITICAL", "t", "d", confidence="HIGH")
    assert f["severity"] == "critical"
    assert f["confidence"] == "strong"  # alias map
    f = make_finding("x", "t", "bogus", "t", "d", confidence="bogus")
    assert f["severity"] == "info"
    assert f["confidence"] == "review"


def test_validate_rejects_malformed():
    assert not validate({})
    assert not validate({"module": "x", "target": "t", "severity": "high",
                         "title": "", "description": "d"})
    assert not validate({"module": "x", "target": "t", "severity": "nope",
                         "title": "t", "description": "d"})
    assert not validate("not a dict")


def test_cvss_suggested_from_module():
    f = make_finding("xss", "https://example.com/", "high",
                     "Reflected XSS in parameter 'q'", "desc")
    assert isinstance(f["cvss"], float)
    assert 0 < f["cvss"] <= 10.0
    assert f["cvss_vector"]["AV"] == "N"
    # score matches the library computation for the suggested vector
    assert f["cvss"] == cvss_lib.cvss31(f["cvss_vector"])


def test_cvss_explicit_vector():
    vector = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
              "C": "H", "I": "H", "A": "H"}
    f = make_finding("sqli", "t", "critical", "SQLi", "d",
                     cvss_vector=vector)
    assert f["cvss"] == cvss_lib.cvss31(vector)
    assert f["cvss_vector"] == vector


def test_cvss_explicit_score():
    f = make_finding("x", "t", "high", "t", "d", cvss=7.5)
    assert f["cvss"] == 7.5


def test_cvss_opt_out():
    f = make_finding("x", "t", "info", "t", "d", cvss=False)
    assert f["cvss"] is None
    assert f["cvss_vector"] is None
    assert validate(f)


def test_dedup_key_stable():
    f1 = make_finding("xss", "https://example.com/?q=1", "high",
                      "Reflected XSS in parameter 'q'", "desc one")
    f2 = make_finding("xss", "https://example.com/?q=2", "high",
                      "Reflected XSS in parameter 'q'", "desc two")
    assert f1["dedup_key"] == f2["dedup_key"] == dedup_key(f1)
    # different parameter -> different key
    f3 = make_finding("xss", "https://example.com/", "high",
                      "Reflected XSS in parameter 'p'", "desc")
    assert f3["dedup_key"] != f1["dedup_key"]
    # different module -> different key
    f4 = make_finding("sqli", "https://example.com/", "high",
                      "Reflected XSS in parameter 'q'", "desc")
    assert f4["dedup_key"] != f1["dedup_key"]


def test_dedup_key_normalizes_target():
    f1 = make_finding("x", "https://example.com/a", "info", "T", "d")
    f2 = make_finding("x", "http://example.com:8080/b", "info", "T", "d")
    assert f1["dedup_key"] == f2["dedup_key"]
