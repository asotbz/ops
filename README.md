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
| `.doco-cd.nc8kg1101.yml` | nc8kg1101's doco-cd deploy config (see [Bootstrapping doco-cd](#bootstrapping-doco-cd)) |
| `scripts/bootstrap-nc8kg1101.sh` | The one-time bootstrap wizard for doco-cd and the ops Platform Stack |
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

nc8kg1101 still runs four umbrella groups (`common`, `monitoring`, `asot`, `xfer`) in `nc8kg1101/<group>/docker-compose.yaml`, deployed by a Portainer agent. They are cut over to the layout above one PR per group:

1. doco-cd and the ops Platform Stack ([#300](https://github.com/asotbz/ops/issues/300))
2. edge ([#301](https://github.com/asotbz/ops/issues/301))
3. monitoring ([#302](https://github.com/asotbz/ops/issues/302))
4. asot into authentik and outline ([#303](https://github.com/asotbz/ops/issues/303))
5. xfer into one Stack per app ([#304](https://github.com/asotbz/ops/issues/304))

#300 moved stack-back out of `common` and Apprise out of `xfer` into `nc8kg1101/ops`; the rest of both groups stays until their own cutover. Each cutover applies the Baseline, the role-based networks and the volume naming rule, and removes the group from Portainer. The Portainer agent is then removed from the Host ([#305](https://github.com/asotbz/ops/issues/305)).

## How a Deploy works

Once doco-cd lands ([ADR 0001](docs/adr/0001-doco-cd-deploys-stacks.md)):

1. Open a PR. Declared state changes only this way.
2. Merge to `main`.
3. doco-cd, running on the Host in the ops Platform Stack, polls `main`. For every Stack that changed, it decrypts the Stack's SOPS files with the Host's age key and runs `docker compose up`.
4. Deploy results go to the Digest through Apprise.

doco-cd deploys only `nc8kg1101/<stack>/compose.yaml`. It never deploys or removes the legacy `docker-compose.yaml` groups, which Portainer or @jbruns still deploy until their cutover.

Deleting a Stack folder removes the Stack from the Host but keeps its data volumes, which are `external` ([ADR 0009](docs/adr/0009-volumes-named-for-their-stack.md)). Runtime actions on the Host, such as a forced recreate, go through `hops` from the shared Repo Tooling, never by editing the Host by hand.

## Secrets

- Every secret is SOPS-encrypted with age. `.sops.yaml` lists the recipients.
- Each Host has its own age key. nc8kg1101's private key lives only on the Host, for doco-cd, at `/etc/doco-cd/age.key` (root, 0600, in a 0700 directory), and offline with @jbruns. @jbruns holds a separate editing key. Files are moving from the old shared key to per-Host keys in [#298](https://github.com/asotbz/ops/issues/298).
- Edit a Stack's values with `sops nc8kg1101/<stack>/.sops.env`. Plaintext `*.env` files are gitignored; encrypted files are named `*.sops.*` and tracked.
- Never print a secret value; read SOPS files by key name only (see [AGENTS.md](AGENTS.md#secrets)).

## Bootstrapping doco-cd

doco-cd is bootstrapped once per Host by hand, then deploys itself from `main` ([ADR 0001](docs/adr/0001-doco-cd-deploys-stacks.md)). For nc8kg1101, run the wizard from a checkout of `main` on @jbruns' machine, after #300 merged:

```sh
scripts/bootstrap-nc8kg1101.sh
```

It needs the repo-root `.env`, the Host's private age key at `~/.config/sops/age/nc8kg1101.txt` (override with `AGE_KEY_FILE`) and sudo as `doogie@nc8kg1101.asot.bz` (override with `OPERATOR`). It asks before every change, and re-running it skips what is done. Its stages:

1. Check the tools, the checkout and SSH access.
2. Replace the placeholder notification URL in `nc8kg1101/ops/doco-cd/apprise_urls.sops.txt`, through a PR.
3. Install the Host age key at `/etc/doco-cd/age.key`, checked by hash and never printed.
4. Create the external volume `ops_doco-cd_data` and the `metrics` network (owned by monitoring from #302).
5. Remove xfer's old `apprise` container once Portainer has redeployed xfer.
6. Copy `xfer_apprise_config` into `ops_apprise_config`. The old volume stays as the Rollback Volume ([ADR 0009](docs/adr/0009-volumes-named-for-their-stack.md)).
7. Redeploy `common` by hand from `~/ops`, which removes `common-backup` before the new stack-back starts. Avoid the 09:12 backup.
8. Run doco-cd once with `apply-self --bootstrap`. It deploys `nc8kg1101/ops`, including the long-lived doco-cd container, and exits.
9. Verify that doco-cd, stack-back and Apprise are healthy and stack-back's schedule is set. Also check that Apprise is reachable from `common_backend` and that no legacy container was touched.
10. Clean up the old stack-back cache and plaintext env, and note the Rollback Volume's release date.

How doco-cd finds Stacks: its `POLL_CONFIG` polls `https://github.com/asotbz/ops.git` on `main` with `target: nc8kg1101`, so it reads only `.doco-cd.nc8kg1101.yml`. That file sets:

- `working_dir: nc8kg1101` and `compose_files: [compose.yaml]`, with auto-discovery at depth 1. Each `nc8kg1101/<stack>/compose.yaml` is a Stack. `nc4kg1201/` and the legacy `docker-compose.yaml` groups are never matched.
- `delete: true`, which removes only projects that doco-cd itself deployed and labelled. The Portainer and hand-deployed groups are never removed.

Another Host would get its own `.doco-cd.<host>.yml` and target. A cutover that adds `compose.yaml` to a legacy group folder hands that project to doco-cd on merge.

To rotate the Host key: add the new recipient in `.sops.yaml` and run `sops updatekeys` through a PR. Then replace `/etc/doco-cd/age.key` (wizard stage 3 with `AGE_KEY_FILE`) and `sudo docker restart doco-cd`.

If the bootstrap has to be rolled back:

1. `sudo docker rm -f doco-cd stack-back apprise`.
2. Revert #300 on `main`.
3. Redeploy xfer in Portainer, which brings back `apprise` on `xfer_apprise_config`.
4. Redeploy `common` by hand.

## Shared Repo Tooling

`hops`, the Baseline validator, declared-containers, the CI workflows, the Renovate preset and agent-skills setup come from [jbruns/homelab-components](https://github.com/jbruns/homelab-components), pinned by tag or commit and bumped by Renovate. They read the Hosts from `hosts.yaml` and connection details from `.env` ([ADR 0012](docs/adr/0012-shared-repo-tooling.md)).
