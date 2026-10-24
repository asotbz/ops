"""Read tools/validate/args as data: each line one homelab-validate option and its value, from a short allowlist.

Run as a script, it prints the arguments shell-quoted (`shlex.join`) for the reusable workflow's `extra-args`,
which splits them with `shlex.split`. Any malformed line fails, so the file cannot inject another option.
"""
import re
import shlex
import sys
from pathlib import Path

ARGS = Path(__file__).resolve().parent / "args"
# homelab-validate's inputs (validate README, "Inputs").
INPUTS = {
    "prometheus", "rule-tests", "alertmanager", "loki", "alloy", "grafana", "dashboards-json", "dashboards",
    "declared-containers", "blackbox", "traefik",
}
LEGACY_STACK = re.compile(r"--legacy-stack ([a-z0-9][a-z0-9-]*)")
PATH = re.compile(r"--path (([a-z][a-z0-9-]*)=([^\s-][^\s]*))")


class ArgsError(ValueError):
    pass


def parse(path: Path, n: int, line: str) -> tuple[str, str, str]:
    """One line as (option, value, key): key names what may appear only once."""
    if m := LEGACY_STACK.fullmatch(line):
        return "--legacy-stack", m[1], f"--legacy-stack {m[1]}"
    if m := PATH.fullmatch(line):
        if m[2] not in INPUTS:
            raise ArgsError(f"{path}: line {n}: unknown input {m[2]!r} (known: {', '.join(sorted(INPUTS))})")
        return "--path", m[1], f"--path {m[2]}"
    raise ArgsError(f"{path}: line {n}: want '--legacy-stack NAME' or '--path NAME=PATH': {line!r}")


def load(path: Path = ARGS) -> list[str]:
    args: list[str] = []
    seen: set[str] = set()
    for n, line in enumerate(Path(path).read_text().split("\n"), 1):
        if not line.strip() or line.startswith("#"):
            continue
        option, value, key = parse(path, n, line)
        if key in seen:
            raise ArgsError(f"{path}: line {n}: {key} given twice")
        seen.add(key)
        args += [option, value]
    return args


def main(argv: list[str]) -> int:
    try:
        args = load(Path(argv[0]) if argv else ARGS)
    except (OSError, ArgsError) as exc:
        print(f"validate_args: {exc}", file=sys.stderr)
        return 1
    print(shlex.join(args))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
