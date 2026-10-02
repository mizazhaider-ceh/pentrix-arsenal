"""CVSS 3.1 calculator sanity checks against known vectors."""

import pytest

from arsenal import cvss as cvss_lib


def test_known_critical_vector():
    # CVE-2021-44228 (Log4Shell)-style: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
    vector = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C",
              "C": "H", "I": "H", "A": "H"}
    assert cvss_lib.cvss31(vector) == 10.0


def test_known_medium_vector():
    # AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N -> 4.2
    vector = {"AV": "N", "AC": "H", "PR": "N", "UI": "R", "S": "U",
              "C": "L", "I": "L", "A": "N"}
    assert cvss_lib.cvss31(vector) == 4.2


def test_zero_impact_scores_zero():
    vector = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C",
              "C": "N", "I": "N", "A": "N"}
    assert cvss_lib.cvss31(vector) == 0.0


def test_missing_metric_raises():
    with pytest.raises(ValueError):
        cvss_lib.cvss31({"AV": "N"})


def test_bad_value_raises():
    vector = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
              "C": "H", "I": "H", "A": "bogus"}
    with pytest.raises(ValueError):
        cvss_lib.cvss31(vector)


def test_labels():
    assert cvss_lib.label(10.0) == "Critical"
    assert cvss_lib.label(7.5) == "High"
    assert cvss_lib.label(5.0) == "Medium"
    assert cvss_lib.label(2.0) == "Low"
    assert cvss_lib.label(0.0) is None
    assert cvss_lib.label(None) is None


def test_suggest_vector_matches_module():
    v = cvss_lib.suggest_vector({"module": "xss", "title": "Reflected XSS"})
    assert v["UI"] == "R" and v["S"] == "C"
    v = cvss_lib.suggest_vector({"module": "headers", "title": "whatever"})
    assert v == cvss_lib.suggest_vector({"module": "zzz", "title": "zzz"})
