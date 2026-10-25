"""Read tools/validate/args as data: each line one homelab-validate option and its value, nothing else.

Run as a script, it prints the arguments shell-quoted (`shlex.join`) for the reusable workflow's `extra-args`,
which splits them with `shlex.split`. Any other line fails, so the file cannot inject another option;
homelab-validate itself rejects an unknown input name.
"""
import re
import shlex
import sys
from pathlib import Path

ARGS = Path(__file__).resolve().parent / "args"
PATH = re.compile(r"--path (([a-z][a-z0-9-]*)=([^\s-][^\s]*))")


class ArgsError(ValueError):
    pass


def parse(path: Path, n: int, line: str) -> tuple[str, str, str]:
    """One line as (option, value, key): key names what may appear only once."""
    if m := PATH.fullmatch(line):
        return "--path", m[1], f"--path {m[2]}"
    raise ArgsError(f"{path}: line {n}: want '--path NAME=PATH': {line!r}")


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
