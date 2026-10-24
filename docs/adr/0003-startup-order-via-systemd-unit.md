# Startup Order is enforced by a Custom Component run by a systemd unit

Compose `depends_on` only applies within one project, and dockerd ignores it when it restarts containers at boot. Within a Stack, Services still declare healthchecks and `depends_on: service_healthy`, with `restart: true` from an app to its Datastore. Across Stacks, every Service carries a `startup-order` label: 0 edge, 1 Datastores and monitoring core, 2 Exposed Services, 3 sidecars and exporters.

The startup-order Custom Component ([ADR 0007](0007-custom-components-from-homelab-components.md)) acts on those labels. The Host is a plain Linux machine, so a systemd unit declared in this repo runs it, ordered after `docker.service`. Because systemd stops units in reverse order, the unit's stop step runs while Docker is still up: it records what is running and stops it from level 3 down to 0. At boot it waits for Docker, then starts the targets level by level, waiting for each to report healthy, and warns and carries on when a level times out. The Host runs a release pinned by tag and sha256, which Renovate bumps.

doco-cd is restarted by dockerd at boot and may Deploy before the unit steps in. A Service that crash-loops while its Dependency is still down then fails that Deploy, so such a Service waits for its Dependency in its own entrypoint instead of exiting.

