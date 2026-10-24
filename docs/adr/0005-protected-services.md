# Protected Services sign in at this Host's own Authentik

Authentik runs on the Host as its own Stack and is the IdP for every Protected Service here. Keeping the IdP on the same Host means no Protected Service depends on another machine to let users in. A Service is Protected by one of three mechanisms, in order of preference:

1. native OIDC, where the Service redirects to the IdP itself and needs no forward auth and no Client Path;
2. forward auth with identity handoff, where the Service trusts the identity header only from Traefik's network;
3. forward auth as a gate, where the Service keeps its own sign-in behind the IdP.

Each Service records its mechanism and the reason for it in its Compose file. Forward auth uses a role-named middleware and a shared chain with the CrowdSec bouncer, both defined by the edge Stack, so a Service never names the IdP's product or address and a missing IdP fails closed. When a required non-browser client cannot sign in at the IdP (an IPTV player, for example), a Client Path routes it past forward auth to the Service's own sign-in, behind the CrowdSec bouncer and a rate limit. A Client Path router is named `<service>-client-<protocol>`, after the protocol rather than the client product. Every forward-auth Service also has an exact-path `<service>-health` router that skips the IdP for its Probe. Every router that skips forward auth strips the identity headers, so a client cannot supply them itself.

The IdP is Critical: every Protected Service fails with it, and it runs on this Host. A Critical Service is not Protected by default, because that would make the IdP a Dependency of the Service and risk locking users out; it is decided per Service by its audience.

## Considered Options

- **An IdP on another machine**: rejected; it couples this Host's sign-in to another machine's uptime, and this Host already runs Authentik for its own users.
- **Basic auth per Service**: rejected; it gives every Service its own credentials and no single sign-out.
- **Forward auth for every Protected Service**: rejected; native OIDC keeps forward auth off the request path and lets native apps work without Client Paths.
