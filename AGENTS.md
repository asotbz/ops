## Agent skills

Before repository work, run `tools/agent-skills/setup-agent-skills check`. If it fails,
run `tools/agent-skills/setup-agent-skills`, then start a fresh agent session to discover
the pinned skills. Invoke applicable installed skills before proceeding.
For installation, pin updates, or recovery, read `docs/agents/skills.md`.

### Issue tracker

Issues and specs live in GitHub Issues for `asotbz/ops`. Before reading or publishing tickets, read `docs/agents/issue-tracker.md`.

### Triage labels

Use the five default triage labels. Before triaging issues, read `docs/agents/triage-labels.md`.

### Domain docs

Single-context: root `GLOSSARY.md` and `docs/adr/`. Before exploring the codebase, read `docs/agents/domain.md`.

### Scope

This repo's tooling manages nc8kg1101 only, the one Host declared in `hosts.yaml`.

### Declared state

Declared state (anything under `nc8kg1101/`, `hosts.yaml`, `.sops.yaml`) changes only through a PR. doco-cd Deploys `main` (ADR 0001); never edit or deploy Stacks on the Host by hand.

### Checks

CI (`.github/workflows/validate.yaml`) must pass before a PR merges; its `validate` job is the required check on
`main`. Run the same checks locally before opening a PR (README.md, [Checks](README.md#checks)):
`tools/validate/homelab-validate`, `homelab-declared-containers --check` and `python3 -m pytest tools`.

`tools/validate/args` holds only `--path` lines. Never add a `--legacy-stack` (or any other exception) there.

### Secrets

SSH access to the Host comes from the gitignored repo-root `.env`, keyed per Host; see `.env.example` for its keys. Only @jbruns edits `.env`.

Keep every secret value out of tool output, logs and commits, whether it comes from `.env`, a decrypted SOPS file or the Host. Read a secret file by key name only: `sops -d <file> | cut -d= -f1` for a dotenv file, `sops -d --output-type json <file> | jq -r 'paths(scalars) | map(tostring) | join(".")'` for YAML or JSON. Never decrypt a file with no keys (such as a `*.sops.txt`) to output. Compare values by exit code or hash. Pipe a new secret from a script straight into `sops set` and its consumer.

### Host access

Reach the Host through `hops` from the shared Repo Tooling in jbruns/homelab-components, with
`--host nc8kg1101` and `--json` when you parse its output. It reads its connection details for
nc8kg1101 from `.env`. It changes runtime state only; declared state changes through a PR. For
anything `hops --help` lacks, use read-only `ssh … sudo -n docker …`.
