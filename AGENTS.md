## Agent skills

Pinned agent-skills setup arrives with the shared Repo Tooling
([jbruns/homelab-components#9](https://github.com/jbruns/homelab-components/issues/9)). Until this
repo adopts it, use whatever skills your session already has.

### Issue tracker

Issues and specs live in GitHub Issues for `asotbz/ops`. Before reading or publishing tickets, read `docs/agents/issue-tracker.md`.

### Triage labels

Use the five default triage labels. Before triaging issues, read `docs/agents/triage-labels.md`.

### Domain docs

Single-context: root `GLOSSARY.md` and `docs/adr/`. Before exploring the codebase, read `docs/agents/domain.md`.

### Scope

This repo's tooling manages nc8kg1101 only, the one Host declared in `hosts.yaml`. Leave `nc4kg1201/` alone.

### Declared state

Declared state (anything under `nc8kg1101/`, `hosts.yaml`, `.sops.yaml`) changes only through a PR. doco-cd Deploys `main` (ADR 0001); never edit or deploy Stacks on the Host by hand.

### Secrets

SSH access to the Host comes from the gitignored repo-root `.env`, keyed per Host; see `.env.example` for its keys. Only @jbruns edits `.env`.

Keep every secret value out of tool output, logs and commits, whether it comes from `.env`, a decrypted SOPS file or the Host. Read a secret file by key name only: `sops -d <file> | cut -d= -f1` for a dotenv file, `sops -d --output-type json <file> | jq -r 'paths(scalars) | map(tostring) | join(".")'` for YAML or JSON. Never decrypt a file with no keys (such as a `*.sops.txt`) to output. Compare values by exit code or hash. Pipe a new secret from a script straight into `sops set` and its consumer.

### Host access

Reach the Host through `hops` from the shared Repo Tooling in jbruns/homelab-components, with
`--host nc8kg1101` and `--json` when you parse its output. It reads its connection details for
nc8kg1101 from `.env`. It changes runtime state only; declared state changes through a PR. For
anything `hops --help` lacks, use read-only `ssh … sudo -n docker …`.
