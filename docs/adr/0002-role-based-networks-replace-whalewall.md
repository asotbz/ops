# Role-based networks replace Whalewall

The threat we care about is lateral movement between Services, not egress. Every Service shared one `common_backend` network, and Whalewall (label-driven nftables rules) was the only thing keeping them apart. Whalewall has had no release since February 2023 and needs a read-write Docker socket. We remove it and `common_backend`, and place Services on networks scoped to a role:

- `proxy`, owned by edge, for Traefik and the Services it exposes;
- one internal network per Stack, for its Services and Datastores;
- `metrics`, owned by monitoring, for Prometheus and the exporters it scrapes;
- `backup`, owned by ops, joined only by stack-back and the databases it dumps.

A network that lets app Stacks talk to each other is owned by a Platform Stack, so no app Stack must come up before another, and is added only when a real need appears. `proxy` is never reused for that, because it would quietly become a general network for Services to talk to each other. An exporter that needs a Service's credentials is a sidecar in that Service's Stack, so monitoring never holds every app's keys. Egress is deliberately left unfiltered.
