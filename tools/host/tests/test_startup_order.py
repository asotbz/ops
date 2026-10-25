"""Checks for host/: the startup-order unit nc8kg1101 runs and the release pin Renovate bumps."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
PIN = REPO / "host" / "startup-order.pin"
UNIT = REPO / "host" / "startup-order.service"
SCRIPT = "/usr/local/bin/startup-order.sh"


def js_regex(pattern):
    """Renovate's named groups (?<name>...) in Python's syntax."""
    return re.compile(re.sub(r"\(\?<(\w+)>", r"(?P<\1>", pattern))


def pin_manager():
    managers = json.loads((REPO / "renovate.json").read_text())["customManagers"]
    path = PIN.relative_to(REPO).as_posix()
    found = [m for m in managers if any(js_regex(p.strip("/")).search(path) for p in m["managerFilePatterns"])]
    assert len(found) == 1, f"one Renovate custom manager must own {path}"
    return found[0]


def test_renovate_reads_the_pinned_tag_and_its_sha256():
    manager = pin_manager()
    match = js_regex(manager["matchStrings"][0]).search(PIN.read_text())
    assert match, "Renovate's matchStrings must match host/startup-order.pin"
    assert js_regex(manager["versioningTemplate"].removeprefix("regex:")).match(match["currentValue"])
    assert re.fullmatch(r"[0-9a-f]{64}", match["currentDigest"])


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="needs systemd-analyze (Linux)")
def test_the_unit_passes_systemd_analyze_verify(tmp_path):
    # verify also checks that ExecStart/ExecStop exist, so point them at a stand-in for the installed script.
    stub = tmp_path / "startup-order.sh"
    stub.write_text("#!/bin/sh\n")
    stub.chmod(0o755)
    unit = tmp_path / UNIT.name
    unit.write_text(UNIT.read_text().replace(SCRIPT, str(stub)))
    result = subprocess.run(["systemd-analyze", "verify", str(unit)], capture_output=True, text=True)
    assert result.returncode == 0 and not result.stderr.strip(), result.stderr
