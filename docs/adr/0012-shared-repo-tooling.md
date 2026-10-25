# Repo Tooling is shared across repos; Hosts are declared in hosts.yaml

This repo needs the same Repo Tooling as other repos that run Stacks under doco-cd: `hops`, the Baseline validator, declared-containers, the CI workflows, the Renovate preset and agent-skills setup. That tooling lives in the Repo Tooling repo, next to the Custom Components, and is generic across repos and Hosts. Python tools are installed by a pinned tag or commit, and CI uses reusable workflows and a Renovate preset pinned the same way. Renovate bumps every pin. Tooling written for this repo alone stays under its own `tools/`.

Every tool takes what is specific to this repo from this repo:

- **Hosts.** `hosts.yaml` at the repo root declares each Host's name, stack root, deployer and capabilities. The Host is declared with deployer `doco-cd` and no capabilities (no ZFS, no TrueNAS). A Host the file does not declare is out of the tools' reach, so another Host whose folder sits in this repo is not declared.
- **Connection details.** These stay in the gitignored `.env`, keyed by Host name (`HOPS_NC8KG1101_*`).
- **Host-specific features.** Snapshots and TrueNAS calls are gated on capabilities, so the tools never offer them here.

## Considered Options

- **Copy the tooling into this repo**: rejected; fixes diverge.
- **Find Hosts by directory convention**: rejected; it is implicit, CI cannot read it, and it cannot leave another Host's folder out deliberately.
