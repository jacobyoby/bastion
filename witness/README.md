# witness (alpha)

**Witness** is a localhost-only UI that runs Bastion checks on SSH public keys (and optionally TLS) **on this machine**.

Design and scope: [docs/witness_design.md](../docs/witness_design.md).

## Quick start

From the repository root (with dependencies installed or `pip install .`):

```sh
PYTHONPATH=. python -m witness.web
```

Open [http://127.0.0.1:8770/](http://127.0.0.1:8770/), leave defaults or add paths, optionally enter a TLS hostname, and click **Run witness checks**.

Summary states:

- **Confirmed** — no weak SSH keys; TLS passed or was not requested.
- **Needs attention** — weak SSH key and/or TLS check failure.
- **Incomplete** — unreadable paths and/or TLS could not complete.

## Tests

```sh
PYTHONPATH=. python -m unittest witness.witness_test witness.web_test
```
