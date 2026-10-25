# Custom Components come from the Repo Tooling repo

Code we wrote that runs on the Host has lived in Stack folders, bind-mounted into stock images, untested and with no stated reason to exist or to go away. Each Custom Component now lives in the Repo Tooling repo and ships as an image consumed here by digest, so Renovate updates it like any other image and the Baseline applies unchanged. A Component that must run on the Host itself rather than in a container (startup-order, [ADR 0003](0003-startup-order-via-systemd-unit.md)) ships as a release asset that this repo pins by tag and sha256. A Component takes every site-specific value from its environment, so this Host adopts it as-is. Its README states why it exists and its Retirement Condition. Code that runs on the Host from this repo today is brought under this rule when its Stack is cut over.

## Considered Options

- **A components folder in this repo**: rejected; fixes would diverge from the copies other hosts run.
- **Keep bind-mounting source into stock images**: rejected; nothing gates the code on tests, and it cannot be versioned apart from a Stack.
