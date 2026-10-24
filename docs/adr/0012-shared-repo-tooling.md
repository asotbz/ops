# Repo Tooling comes from homelab-components; Hosts are declared in hosts.yaml

This repo needs the same Repo Tooling as other repos that run Stacks under doco-cd: `hops`, the Baseline validator, declared-containers, the CI workflows, the Renovate preset and agent-skills setup. That tooling lives in [jbruns/homelab-components](https://github.com/jbruns/homelab-components), next to the Custom Components, and is generic across repos and Hosts. Python tools are installed by a pinned tag or commit, and CI uses reusable workflows and a Renovate preset pinned the same way. Renovate bumps every pin. Tooling written for this repo alone stays under its own `tools/`.

Every tool takes what is specific to this repo from this repo:

- **Hosts.** `hosts.yaml` at the repo root declares each Host's name, stack root, deployer and capabilities. nc8kg1101 is declared with deployer `doco-cd` and no capabilities (no ZFS, no TrueNAS). A Host the file does not declare is out of the tools' reach, so nc4kg1201 is not declared.
- **Connection details.** These stay in the gitignored `.env`, keyed by Host name (`HOPS_NC8KG1101_*`).
- **Host-specific features.** Snapshots and TrueNAS calls are gated on capabilities, so the tools never offer them here.

## Considered Options

- **Copy the tooling into this repo**: rejected; fixes diverge.
- **Find Hosts by directory convention**: rejected; it is implicit, CI cannot read it, and it cannot leave nc4kg1201 out deliberately.
