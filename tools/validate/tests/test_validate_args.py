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
    "--path prometheus=host-a/monitoring/prometheus --help",
    "--path prometheus=--help",
    "--path prometheus",
    "--path prometheus=",
    "--path prometheus=a\tb",
    "path prometheus=a",
    "prometheus",
]


def write(tmp_path, *lines, name="args"):
    f = tmp_path / name
    f.write_text("# comment\n\n" + "".join(f"{line}\n" for line in lines))
    return f


def test_each_line_is_one_option_and_its_value(tmp_path):
    f = write(tmp_path, "--path loki=host-a/monitoring/loki", "--path traefik=host-a/edge/traefik/service.yaml")
    assert validate_args.load(f) == [
        "--path", "loki=host-a/monitoring/loki", "--path", "traefik=host-a/edge/traefik/service.yaml",
    ]


def test_the_repo_files_are_valid():
    validate_args.load_all(TOOL_DIR / "args")


def test_each_privacy_allow_line_is_one_regex(tmp_path):
    f = write(tmp_path, r"host-a/", r"\.deploy\.host-a\.yml", name="privacy-allow")
    assert validate_args.load_privacy_allow(f) == ["--privacy-allow", "host-a/", "--privacy-allow", r"\.deploy\.host-a\.yml"]


@pytest.mark.parametrize(
    ("lines", "error"),
    [(("(unclosed",), "line 3: not a valid regex"), ((" host-a/",), "line 3: leading"),
     (("host-a/", "host-a/"), "line 4: given twice")],
)
def test_a_bad_privacy_allow_line_is_refused(tmp_path, lines, error):
    with pytest.raises(validate_args.ArgsError, match=error):
        validate_args.load_privacy_allow(write(tmp_path, *lines, name="privacy-allow"))


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
    f = write(tmp_path, "--path loki=host-a/monitoring/loki", "--path prometheus=host-a/monitoring/prometheus")
    write(tmp_path, r"(?<![\w@.-])host-a/", r"git\+https://\S+ 'x' \$", name="privacy-allow")
    out = subprocess.run([sys.executable, TOOL_DIR / "validate_args.py", f], capture_output=True, text=True,
                         check=True).stdout
    assert shlex.split(out) == validate_args.load_all(f)
    assert shlex.split(out)[-2:] == ["--privacy-allow", r"git\+https://\S+ 'x' \$"]


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
    write(repo / "tools/validate", "host-a/", name="privacy-allow")
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
    repo, env = wrapper_repo(tmp_path, '#!/bin/sh\nprintf "%s\\n" "$@"\n', "--path loki=host-a/monitoring/loki")
    r = subprocess.run([repo / "tools/validate/homelab-validate", "secrets"], capture_output=True, text=True,
                       env=env, check=True)
    assert r.stdout.splitlines() == [
        "--root", str(repo.resolve()), "--path", "loki=host-a/monitoring/loki", "--privacy-allow", "host-a/", "secrets",
    ]
