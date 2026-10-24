"""blackbox-exporter's http_idp_redirect module (nc8kg1101/monitoring/blackbox-exporter/blackbox.yml).

blackbox matches fail_if_header_not_matches with Go's regexp.MatchString, an unanchored search;
Python's re.search has the same semantics for this pattern.
"""
import re
from pathlib import Path

import pytest
import yaml

BLACKBOX = Path(__file__).resolve().parents[3] / "nc8kg1101" / "monitoring" / "blackbox-exporter" / "blackbox.yml"


def location_regexp():
    module = yaml.safe_load(BLACKBOX.read_text())["modules"]["http_idp_redirect"]
    (rule,) = [r for r in module["http"]["fail_if_header_not_matches"] if r["header"] == "Location"]
    return rule["regexp"]


@pytest.mark.parametrize(
    "location",
    [
        "https://idp.asot.bz/application/o/authorize/?client_id=abc&redirect_uri=https%3A%2F%2Foln.asot.bz%2Fauth%2Foidc.callback",
        "https://idp.asot.bz/application/o/authorize/",
    ],
)
def test_accepts_the_idps_authorize_endpoint(location):
    assert re.search(location_regexp(), location)


@pytest.mark.parametrize(
    "location",
    [
        "https://wrong.example/application/o/authorize/?client_id=test",
        "/login?next=/application/o/authorize/",
        "https://idp.asot.bz.evil.example/application/o/authorize/?client_id=test",
        "http://idp.asot.bz/application/o/authorize/?client_id=test",
        "https://idp.asot.bz/application/o/authorize/x?client_id=test",
        "https://evil.example/?u=https://idp.asot.bz/application/o/authorize/",
    ],
)
def test_rejects_any_other_location(location):
    assert not re.search(location_regexp(), location)
