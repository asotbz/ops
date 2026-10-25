"""Read tools/validate/args as data: each line one homelab-validate option and its value, nothing else.

tools/validate/privacy-allow adds one `--privacy-allow` per line: a regex for a load-bearing identifier the privacy
check may find in prose. Each must compile, and a repeated one is refused.

Run as a script, it prints both shell-quoted (`shlex.join`) for the reusable workflow's `extra-args`, which splits
them with `shlex.split`. Any other line in args fails, so the file cannot inject another option; homelab-validate
itself rejects an unknown input name.
"""
import re
import shlex
import sys
from pathlib import Path

ARGS = Path(__file__).resolve().parent / "args"
PRIVACY_ALLOW = ARGS.with_name("privacy-allow")
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


def load_privacy_allow(path: Path = PRIVACY_ALLOW) -> list[str]:
    args: list[str] = []
    seen: set[str] = set()
    for n, line in enumerate(Path(path).read_text().split("\n"), 1):
        if not line.strip() or line.startswith("#"):
            continue
        if line != line.strip():
            raise ArgsError(f"{path}: line {n}: leading or trailing whitespace")
        try:
            re.compile(line)
        except re.error as exc:
            raise ArgsError(f"{path}: line {n}: not a valid regex: {exc}") from None
        if line in seen:
            raise ArgsError(f"{path}: line {n}: given twice")
        seen.add(line)
        args += ["--privacy-allow", line]
    return args


def load_all(args: Path = ARGS, privacy_allow: Path | None = None) -> list[str]:
    """args, then privacy-allow, which sits next to args unless given."""
    return load(args) + load_privacy_allow(privacy_allow or Path(args).with_name("privacy-allow"))


def main(argv: list[str]) -> int:
    try:
        args = load_all(*(Path(a) for a in argv[:2]))
    except (OSError, ArgsError) as exc:
        print(f"validate_args: {exc}", file=sys.stderr)
        return 1
    print(shlex.join(args))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
