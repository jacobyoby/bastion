# witness (alpha)

**Witness** is a localhost-only UI that runs Bastion checks on SSH public keys, public certificates from browsers and installed applications, and optionally TLS **on this machine**. Private keys are skipped. The system CA bundle is counted and not fully scanned.

Design and scope: [docs/witness_design.md](../docs/witness_design.md).

## Quick start

From the repository root (with dependencies installed or `pip install .`):

```sh
PYTHONPATH=. python -m witness.web
```

Open [http://127.0.0.1:8770/](http://127.0.0.1:8770/). Leave the SSH, browser, and installed-app boxes checked, or add paths, optionally enter a TLS hostname, and click **Run witness checks**.

Summary states:

- **Confirmed** — every key that was checked is clean. Skipped rows (system roots, NSS) are not a pass.
- **Needs attention** — a scanned key is weak and/or TLS reported a check failure.
- **Incomplete** — a requested file could not be read and/or TLS could not complete. No browsers installed is not a failure.

## Tests

```sh
PYTHONPATH=. python -m unittest witness.witness_test witness.web_test
```
