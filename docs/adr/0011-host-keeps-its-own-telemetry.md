# This Host keeps its own telemetry and alerting

The Host runs its own Prometheus, Alertmanager and Loki, and alerts on its own. Another machine's Grafana may add them as datasources and query them in place, but no data is shipped off the Host and no other machine's alerting is involved. So this Host's monitoring keeps working, and keeps alerting, when every other machine is down.

Tiers, Pages and the Heartbeat are configured here, separately from any other host:

- **Critical** Pages: edge, the IdP, Outline and its Datastores, Backups, and doco-cd.
- **Warning** goes to the Digest: the xfer Services.
- **Info** is dashboards only.

Pages and the Digest use the same providers as the other hosts, with this Host's own credentials and routes. The Heartbeat goes to its own check, so a dead Host or Alertmanager is noticed on its own.

## Considered Options

- **Remote-write or federation into another host's Prometheus**: rejected; it couples this Host's monitoring to another machine's.
- **Route this Host's alerts through another host's Alertmanager**: rejected; a failure there would silence this Host's Pages.
