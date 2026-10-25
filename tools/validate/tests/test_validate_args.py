"""Tests for validate_args.py and the homelab-validate wrapper that uses it."""
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

TOOL_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_DIR))

import validate_args  # noqa: E402

BAD_LINES = [
    "--legacy-stack common",
    "--legacy-volume common_data",
    "--path prometheus=nc8kg1101/monitoring/prometheus --help",
    "--path prometheus=--help",
    "--path prometheus",
    "--path prometheus=",
    "--path prometheus=a\tb",
    "path prometheus=a",
    "prometheus",
]


def write(tmp_path, *lines):
    f = tmp_path / "args"
    f.write_text("# comment\n\n" + "".join(f"{line}\n" for line in lines))
    return f


def test_each_line_is_one_option_and_its_value(tmp_path):
    f = write(tmp_path, "--path loki=nc8kg1101/monitoring/loki", "--path traefik=nc8kg1101/edge/traefik/service.yaml")
    assert validate_args.load(f) == [
        "--path", "loki=nc8kg1101/monitoring/loki", "--path", "traefik=nc8kg1101/edge/traefik/service.yaml",
    ]


def test_the_repo_file_is_valid():
    validate_args.load(TOOL_DIR / "args")


@pytest.mark.parametrize("line", BAD_LINES)
def test_a_bad_line_is_refused(tmp_path, line):
    with pytest.raises(validate_args.ArgsError, match="line 3"):
        validate_args.load(write(tmp_path, line))


@pytest.mark.parametrize(
    "lines",
    [("--path prometheus=a", "--path prometheus=a"), ("--path prometheus=a", "--path prometheus=b")],
)
def test_a_repeated_entry_is_refused(tmp_path, lines):
    with pytest.raises(validate_args.ArgsError, match="line 4: .* given twice"):
        validate_args.load(write(tmp_path, *lines))


def test_ci_output_round_trips_through_shlex_split(tmp_path):
    f = write(tmp_path, "--path loki=nc8kg1101/monitoring/loki", "--path prometheus=nc8kg1101/monitoring/prometheus")
    out = subprocess.run([sys.executable, TOOL_DIR / "validate_args.py", f], capture_output=True, text=True,
                         check=True).stdout
    assert shlex.split(out) == validate_args.load(f)


@pytest.mark.parametrize("line", BAD_LINES)
def test_ci_output_fails_on_a_bad_line(tmp_path, line):
    r = subprocess.run([sys.executable, TOOL_DIR / "validate_args.py", write(tmp_path, line)],
                       capture_output=True, text=True)
    assert r.returncode != 0 and r.stdout == "" and "line 3" in r.stderr


def wrapper_repo(tmp_path, stub_script, *lines):
    repo = tmp_path / "repo"
    (repo / "tools/validate").mkdir(parents=True)
    for name in ("homelab-validate", "validate_args.py"):
        shutil.copy2(TOOL_DIR / name, repo / "tools/validate" / name)
    write(repo / "tools/validate", *lines)
    stub = tmp_path / "bin"
    stub.mkdir()
    (stub / "homelab-validate").write_text(stub_script)
    (stub / "homelab-validate").chmod(0o755)
    env = {**os.environ, "PATH": f"{stub}{os.pathsep}{os.environ['PATH']}"}
    return repo, env


@pytest.mark.parametrize("line", BAD_LINES)
def test_wrapper_fails_on_a_bad_line_without_running_homelab_validate(tmp_path, line):
    repo, env = wrapper_repo(tmp_path, "#!/bin/sh\necho ran\n", line)
    r = subprocess.run([repo / "tools/validate/homelab-validate", "secrets"], capture_output=True, text=True, env=env)
    assert r.returncode != 0 and "ran" not in r.stdout and "line 3" in r.stderr


def test_wrapper_passes_each_value_as_one_argument(tmp_path):
    repo, env = wrapper_repo(tmp_path, '#!/bin/sh\nprintf "%s\\n" "$@"\n', "--path loki=nc8kg1101/monitoring/loki")
    r = subprocess.run([repo / "tools/validate/homelab-validate", "secrets"], capture_output=True, text=True,
                       env=env, check=True)
    assert r.stdout.splitlines() == [
        "--root", str(repo.resolve()), "--path", "loki=nc8kg1101/monitoring/loki", "secrets",
    ]
