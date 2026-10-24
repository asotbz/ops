# Agent skills

This repo pins the agent skills it uses in `.agent-skills.lock`. `tools/agent-skills/setup-agent-skills` installs
them into the gitignored `.agents/skills/`. The wrapper runs `setup-agent-skills`, shared Repo Tooling from
jbruns/homelab-components, with `uvx`, pinned by commit
([README](https://github.com/jbruns/homelab-components/blob/agent-skills-v1.0.0/repo-tools/agent-skills/README.md)).
It is local tooling only: no Host access, Docker or secrets.

## Install and check

Needs Bash, Git 2.25+, [uv](https://docs.astral.sh/uv/) and network access on the first run. From anywhere in the
repo:

```sh
tools/agent-skills/setup-agent-skills          # install or repair
tools/agent-skills/setup-agent-skills check    # offline; exits 1 unless the installed skills match the lock
```

Start a fresh agent session after installing or changing skills so the agent discovers them. Setup overwrites
local edits to the skills it manages, so keep your own skills in other directories.

## Change the pin or the set

```sh
tools/agent-skills/setup-agent-skills pin <upstream-tag-or-commit>
tools/agent-skills/setup-agent-skills check
git diff -- .agent-skills.lock
```

Review the upstream changes first, then commit the lock. `pin` updates `ref` and `revision` only after the install
succeeds. `exclude <name|path>` and `include <path>` lines in the lock adjust the set; the README above lists the
format.

`tools/agent-skills/setup-agent-skills clean` removes only the skills it installed.

## Updates

Renovate bumps the wrapper's `tag` and `commit` together in their own PR; review the release before merging.
