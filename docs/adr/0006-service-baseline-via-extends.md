# Every Service extends one Baseline; Exemptions are recorded and checked

No Service on the Host meets a full Baseline: images are not pinned by digest, and there are no memory limits and no `cap_drop`. Each Service pulls the Baseline's invariant settings from one `baseline` service in `nc8kg1101/_baseline.yaml` with `extends: file:`. The shared validator from homelab-components ([ADR 0012](0012-shared-repo-tooling.md)) owns the list of Baseline items, so "Baseline" means the same thing here as in any other repo that uses it; this Host's file holds only the values. At adoption the items are: a healthcheck declared in Compose, `no-new-privileges`, a digest-pinned image, a memory limit, `restart: unless-stopped`, bounded json-file logging, `cap_drop: [ALL]` with any needed `cap_add`, and no anonymous volumes. The validator checks the rendered model, so an item holds whether it came from `extends` or was written inline.

A Service that cannot meet an item records an Exemption as a `baseline.exempt.<item>` label whose value is the reason; where the Baseline sets the item, the Service removes it with `!reset`. The validator rejects an Exemption without a reason or for an item the Service already meets, and lists every Exemption, so the list stays auditable and shrinks as images improve. A Service meets `cap_drop: [ALL]` by running as its target user wherever the image allows, and falls back to `cap_add`, with a comment giving the reason, only where the image's init cannot run without root.

A change to the Baseline recreates every Service that extends it in one Deploy and ignores Startup Order, so it ships alone in its own PR. doco-cd does not extend the Baseline and keeps those settings inline, so a Baseline change cannot race its self-update.

## Considered Options

- **A written convention copied into every Service**: rejected; it repeats the same block everywhere, and a change means editing every Stack.
- **YAML anchors or `x-` fragments**: rejected; they do not cross `include:` files, and every Stack is split that way.
- **This repo choosing its own Baseline items**: rejected; the Baseline would stop being one enforced minimum.
