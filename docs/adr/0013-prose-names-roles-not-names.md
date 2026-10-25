# Prose names roles, not names

This repo is public, and its prose named the machine it runs on, the person who runs it, that person's logins and handles, and the other repos it works with. None of those names is needed to understand or change the repo, and each tells a reader more about the setup behind it than the repo needs to. So prose names roles instead: the Host, the Operator, the Operator's sudo account, this repo, the Repo Tooling repo, a sibling deployment repo. A public service domain in prose is written `<domain>`.

Prose is what a reader reads rather than what a tool loads: Markdown, code comments, docstrings, CLI help and output, and templates. It never names a repository, a person, a GitHub handle, a login or a hostname. A reference to an issue or PR of this repo is a bare `#N`, not a link.

Load-bearing identifiers stay, because renaming them would break something: paths (the stack root folder, cited only as a path), `hosts.yaml` keys, `.env` key names, each Host's deploy config file name, `uses:` refs and pinned install URLs, SOPS recipients, Renovate config and the license. Config values keep the real domain and names they need, and tests may keep real values as data.

The shared validator's `privacy` check enforces this in CI and fails a PR on a match. Its denylist of names is never committed: CI reads it from a repository secret, so the list does not itself publish the names. `tools/validate/privacy-allow` lists the load-bearing identifiers it allows, each as narrow as one path, key prefix, file name or pinned URL; it never allows a bare hostname, login or name. A tool's output states the rule it enforces rather than citing an ADR; comments may cite this repo's own ADRs.

Git history is not rewritten: the names stay in past commits.

## Considered Options

- **Commit the denylist**: rejected; the list would publish exactly the names it keeps out of prose.
- **Rewrite history to remove the names**: rejected; it breaks every clone and link for little gain, since the names were public before.
- **Warn only**: rejected once the repo is clean; a warning nobody must act on lets names drift back in.
