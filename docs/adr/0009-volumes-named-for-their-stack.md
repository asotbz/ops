# Volumes are named for their Stack; a rename keeps a Rollback Volume

Volumes created under the umbrella groups carry names that say nothing about the Stack that owns them once the groups split. Every volume is named after its Stack, `<stack>_[<service>_]<purpose>`, leaving out `<service>` when it equals the Stack (`outline_data`, `outline_postgres_data`, `edge_traefik_le`). This is the name Compose would give the key `<service>_<purpose>` in project `<stack>`, so a volume reads the same on the Host as in the repo.

Every volume carries an explicit `name:`. A volume that holds data is `external: true`: Compose never creates or removes it, so a `docker compose down -v` or a Stack folder deleted by mistake cannot take the data with it. A volume holding only what its Service regenerates (a cache, transcode scratch) may be owned by Compose, and is labelled regenerable with what regenerates it. Datastores are named after their engine (`postgres`, `redis`), so their containers are named `<stack>-<service>` (`outline-postgres`); app Services keep `container_name` equal to their Service name.

Docker cannot rename a volume, and the Host has no ZFS to snapshot it. A rename stops the Stack, creates the new external volume, copies the contents across, and Deploys the PR that changes `name:`. The old volume stays untouched as the Rollback Volume, recorded in that PR with its release date, and is removed once the change is verified. One kept past its release date is a Stray.

## Considered Options

- **Keep the umbrella-group names**: rejected; every volume lookup would need the history of the split.
- **Move the contents without keeping the old volume**: rejected; with no snapshot, the old volume is the only fast way back.
- **Every volume external, caches included**: rejected; a Deploy could no longer create a cache, and a regenerable volume gains nothing from protection against deletion.
