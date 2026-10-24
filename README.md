# ops

GitOps for the self-hosted Services on nc8kg1101, a plain Linux Host. Every Stack is a Docker Compose project in this repo, and the repo is the only source of truth for what runs there.

Terms used here (Stack, Platform Stack, Service, Datastore, Deploy, Baseline, Tier, ...) are defined in [GLOSSARY.md](GLOSSARY.md). Design decisions are recorded in [docs/adr](docs/adr). Agents start at [AGENTS.md](AGENTS.md).

nc4kg1201 also lives in this repo, under `nc4kg1201/`, but this repo's tooling and docs do not manage it.

## Layout

| Path | Contents |
|---|---|
| `nc8kg1101/<stack>/compose.yaml` | One Stack per folder; the folder name is the Compose project name |
| `nc8kg1101/<stack>/<service>/service.yaml` | One Service plus the sidecars that exist only to serve it, listed in the Stack's `include:` |
| `nc8kg1101/<stack>/.sops.env` | SOPS-encrypted values for the Stack |
| `nc8kg1101/_baseline.yaml` | The Baseline every Service extends ([ADR 0006](docs/adr/0006-service-baseline-via-extends.md)) |
| `hosts.yaml` | The Hosts the shared Repo Tooling manages: only nc8kg1101 ([ADR 0012](docs/adr/0012-shared-repo-tooling.md)) |
| `.env.example` | Keys for the gitignored repo-root `.env`: SSH access to each Host |
| `.sops.yaml` | Which age keys encrypt which files |

There is one Stack per app, each with its own Datastores ([ADR 0004](docs/adr/0004-stack-per-app-with-own-datastores.md)). Platform Stacks group Services by the role they play for the others:

| Platform Stack | Services |
|---|---|
| `edge` | Traefik, CrowdSec, nginx, mitmproxy |
| `monitoring` | Prometheus, Alertmanager, Loki and their collectors and exporters |
| `ops` | doco-cd, stack-back (Backups), Apprise |

App Stacks are `authentik`, `outline`, `fuzzbin`, `ersatztv`, `dispatcharr`, `nzbhydra2` and `prowlarr`.

### Cutover in progress

Today nc8kg1101 still runs four umbrella groups (`common`, `monitoring`, `asot`, `xfer`) in `nc8kg1101/<group>/docker-compose.yaml`, deployed by a Portainer agent. They are cut over to the layout above one PR per group:

1. doco-cd and the ops Platform Stack ([#300](https://github.com/asotbz/ops/issues/300))
2. edge ([#301](https://github.com/asotbz/ops/issues/301))
3. monitoring ([#302](https://github.com/asotbz/ops/issues/302))
4. asot into authentik and outline ([#303](https://github.com/asotbz/ops/issues/303))
5. xfer into one Stack per app ([#304](https://github.com/asotbz/ops/issues/304))

Each cutover applies the Baseline, the role-based networks and the volume naming rule, and removes the group from Portainer. The Portainer agent is then removed from the Host ([#305](https://github.com/asotbz/ops/issues/305)).

## How a Deploy works

Once doco-cd lands ([ADR 0001](docs/adr/0001-doco-cd-deploys-stacks.md)):

1. Open a PR. Declared state changes only this way.
2. Merge to `main`.
3. doco-cd, running on the Host in the ops Platform Stack, polls `main`. For every Stack that changed, it decrypts the Stack's SOPS files with the Host's age key and runs `docker compose up`.
4. Deploy results go to the Digest through Apprise.

Deleting a Stack folder removes the Stack from the Host but keeps its data volumes, which are `external` ([ADR 0009](docs/adr/0009-volumes-named-for-their-stack.md)). Runtime actions on the Host, such as a forced recreate, go through `hops` from the shared Repo Tooling, never by editing the Host by hand.

## Secrets

- Every secret is SOPS-encrypted with age. `.sops.yaml` lists the recipients.
- Each Host has its own age key. nc8kg1101's private key lives only on the Host, for doco-cd, and offline with @jbruns. @jbruns holds a separate editing key. Files are moving from the old shared key to per-Host keys in [#298](https://github.com/asotbz/ops/issues/298).
- Edit a Stack's values with `sops nc8kg1101/<stack>/.sops.env`. Plaintext `*.env` files are gitignored; encrypted files are named `*.sops.*` and tracked.
- Never print a secret value; read SOPS files by key name only (see [AGENTS.md](AGENTS.md#secrets)).

## Shared Repo Tooling

`hops`, the Baseline validator, declared-containers, the CI workflows, the Renovate preset and agent-skills setup come from [jbruns/homelab-components](https://github.com/jbruns/homelab-components), pinned by tag or commit and bumped by Renovate. They read the Hosts from `hosts.yaml` and connection details from `.env` ([ADR 0012](docs/adr/0012-shared-repo-tooling.md)).
