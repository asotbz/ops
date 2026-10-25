"""blackbox-exporter's http_idp_redirect module (nc8kg1101/monitoring/blackbox-exporter/blackbox.yml).

blackbox matches fail_if_header_not_matches with Go's regexp.MatchString, an unanchored search;
Python's re.search has the same semantics for this pattern.
"""
import re
from pathlib import Path

import pytest
import yaml

BLACKBOX = Path(__file__).resolve().parents[3] / "nc8kg1101/monitoring/blackbox-exporter/blackbox.yml"


def location_regexp():
    module = yaml.safe_load(BLACKBOX.read_text())["modules"]["http_idp_redirect"]
    (rule,) = [r for r in module["http"]["fail_if_header_not_matches"] if r["header"] == "Location"]
    return rule["regexp"]


def idp_host():
    """The IdP's host name, read from the regexp so no domain is written here."""
    m = re.fullmatch(r"\^https://((?:[a-z0-9-]+\\\.)+[a-z]+)/application/o/authorize/\(\\\?\|\$\)", location_regexp())
    assert m, "the regexp no longer has the expected shape; update this test with it"
    return m[1].replace("\\.", ".")


@pytest.mark.parametrize(
    "location",
    [
        "https://{idp}/application/o/authorize/?client_id=abc&redirect_uri=https%3A%2F%2Fapp.example%2Fauth%2Foidc.callback",
        "https://{idp}/application/o/authorize/",
    ],
)
def test_accepts_the_idps_authorize_endpoint(location):
    assert re.search(location_regexp(), location.format(idp=idp_host()))


@pytest.mark.parametrize(
    "location",
    [
        "https://wrong.example/application/o/authorize/?client_id=test",
        "/login?next=/application/o/authorize/",
        "https://{idp}.evil.example/application/o/authorize/?client_id=test",
        "http://{idp}/application/o/authorize/?client_id=test",
        "https://{idp}/application/o/authorize/x?client_id=test",
        "https://evil.example/?u=https://{idp}/application/o/authorize/",
        "https://x{idp}/application/o/authorize/?client_id=test",
    ],
)
def test_rejects_any_other_location(location):
    assert not re.search(location_regexp(), location.format(idp=idp_host()))
