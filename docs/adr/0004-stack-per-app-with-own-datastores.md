# One Stack per app, each with its own Datastores

The Host's Services were deployed as four umbrella groups (common, monitoring, asot, xfer). Network isolation, `depends_on` ordering, Deploy blast radius and Backup scope all line up with a single app and its Datastores, not with a group. Each app becomes its own Stack in `nc8kg1101/<stack>/compose.yaml`, with each Service in `<service>/service.yaml`. Datastores are never shared across Stacks: Authentik and Outline each get their own Postgres and Redis instead of sharing one pair, and their data moves by a dump and restore. (Amended by #303: Authentik 2025.10 and later keeps its cache and tasks in Postgres, so only Outline has a Redis.)

Platform Stacks are the only Stacks grouped by role rather than by app, and the only ones that may hold more than one app:

- **edge**: Traefik, CrowdSec, nginx and mitmproxy.
- **monitoring**: Prometheus, Alertmanager, Loki and their collectors and exporters.
- **ops**: doco-cd, stack-back and Apprise.

xfer splits into fuzzbin (with its gluetun sidecar), ersatztv, dispatcharr, nzbhydra2 (with its exporter) and prowlarr, so each ships on its own schedule and Deploys alone. Each group is cut over in its own PR.
