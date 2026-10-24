# doco-cd Deploys Stacks; Portainer is removed

The Host's Stacks were deployed by a Portainer agent, driven from a Portainer server on another machine, with compose-unpacker decrypting SOPS. Portainer's GitOps cannot decrypt SOPS itself, so secrets needed a workaround, and the Host's deployment depended on another machine. We Deploy every Stack with doco-cd running on the Host: it polls `main`, decrypts SOPS natively with the Host's own age key, and runs `docker compose up` for each Stack that changed. The repo is the only source of truth. Declared state changes only through a PR; runtime actions such as a forced recreate go through `hops`, which replaces the Portainer agent. The agent is removed from the Host, and no deploy history is carried over from Portainer.

doco-cd is bootstrapped once by hand and then manages itself from the ops Platform Stack.

## Considered Options

- **Keep the Portainer agent as a read-only viewer**: rejected; `hops` covers the runtime actions and diagnostics, and an agent with the Docker socket is attack surface with no remaining job.
- **Komodo**: rejected; heavier (Core, Periphery and a database), with no native SOPS support.
