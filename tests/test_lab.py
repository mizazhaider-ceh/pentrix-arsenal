"""Lab harness tests: every wired fixture produces its expected finding."""

import pytest

from arsenal import lab


@pytest.mark.parametrize("name", sorted(lab.CHECKS))
def test_lab_check(name):
    ok, detail = lab.run_check(name)
    assert ok, "%s: %s" % (name, detail)


def test_all_fixtures_wired():
    # Every fixture in FIXTURES is exercised by a harness check, except
    # jwt: its check passes the token directly (no server needed), while
    # the fixture stays for manual `arsenal lab up` practice.
    wired = {spec.get("fixture") for spec in lab.CHECKS.values()}
    for name in lab.FIXTURES:
        assert name in wired or name == "jwt", \
            "fixture %r has no lab check" % name
