# Bastion witness (alpha) — design

Witness is a **local-only** tool that helps operators **observe and confirm** SSH public keys (and optionally a TLS certificate) on **this machine** using Bastion’s existing checks—not an app’s internal trust chain or opaque summaries.

## 1. Problem

Operators need to answer: “Do the SSH keys and (optionally) the TLS identity on this host look sound under Bastion’s public-key and certificate checks?”

They should not have to trust a deployment tool’s green checkmark or paste private key material. Witness reads **public** SSH material from standard locations, runs the same **paranoid** RSA/EC checks as the library, and optionally runs **tlscheck** against a hostname the operator supplies.

## 2. Users and scenarios

| User | Scenario |
| --- | --- |
| Local admin | After provisioning, confirm `authorized_keys` / `known_hosts` on a laptop or server. |
| Security reviewer | On a review VM, collect what SSH trust material is installed and whether any key fails Bastion checks. |
| Pre-deploy sanity check | Before cutover, run witness on a staging host with optional TLS host matching production SNI. |

## 3. Scope (alpha)

**In scope**

- One-shot witness run on **localhost** (127.0.0.1 UI).
- Default scan of `~/.ssh/authorized_keys` and `~/.ssh/known_hosts`.
- Optional extra paths (textarea) and readable `*.pub` under `/etc/ssh` when the process can read them.
- SSH: parse with `ssh_keys`, check with `paranoid.CheckAllRSA` / `CheckAllEC`.
- Optional TLS: `tlscheck.run.run_check` with the same semantics as `python -m tlscheck` (Mozilla roots in certifi, not the OS store).
- Clear overall result: **Confirmed**, **Needs attention**, or **Incomplete**.
- No accounts, no persisted run history.

**Out of scope (alpha)**

- Remote fleet scanning or agents.
- Certificate Transparency.
- OS trust store for TLS (tlscheck never used it).
- Ingesting private keys or PEM files via the form.
- Signed witness receipts (see [Open questions](#10-open-questions)).

## 4. Witness checks defined

### SSH witness bundle

1. **Discover sources** — configured paths plus optional `/etc/ssh/*.pub`.
2. **Parse** — `ParseAuthorizedKeys` or `ParseKnownHosts` (or authorized_keys-style for `.pub`).
3. **Check** — all RSA keys through `CheckAllRSA`, all EC keys through `CheckAllEC`.
4. **Report** — per source (read ok / missing / unreadable), per key (fingerprint, weak flag, failing check rows with severity).

Unsupported line types (e.g. Ed25519) are listed but not run through paranoid checks.

### TLS witness bundle (optional)

When the operator supplies a hostname:

1. If `tlscheck` is importable: capture handshake, `run_check`, map `Report.exit_code` (0 pass, 1 check failure, 2 operational error).
2. If `tlscheck` is missing: **skip** with an explanatory message (not Incomplete).

TLS uses live network I/O to the given host; it is not a witness of “certs on disk.”

## 5. Confirmation model

### Overall status

| Status | Meaning |
| --- | --- |
| **Confirmed** | Zero weak SSH artifacts and no TLS exit code 1 (TLS skipped or exit 0). No blocking read/TLS operational failures. |
| **Needs attention** | At least one SSH key marked weak by paranoid, and/or TLS exit code 1 (check failure). |
| **Incomplete** | At least one configured path was unreadable (permissions), and/or TLS exit code 2 (connect/parse/capture). |

Precedence for the summary banner: **Needs attention** overrides **Confirmed** when weak keys or TLS 1 exist; **Incomplete** applies when operational/read failures occur (TLS 2 or unreadable paths). A run can show Incomplete in TLS while SSH is Confirmed.

### Per-artifact rows (SSH keys)

Each RSA/EC key shows:

- SHA256 fingerprint (OpenSSH `ssh-keygen -l` style).
- Key type (RSA / EC curve).
- Source path and line hint where available.
- **Weak** if `test_info.weak` after checks.
- Expandable **check rows**: check name, pass/fail, severity label (Critical / High / …).

### Per-check rows (TLS)

Mirror tlscheck: presented/fetched path, leaf fingerprint, and each named check with pass/fail/skip and reason.

## 6. UI/UX

Single-page flow:

1. **Witness this machine** — form defaults: scan home SSH on; optional extra paths; optional TLS host/port.
2. **Run witness checks** — show a simple progress state (form POST).
3. **Summary banner** — Confirmed (green), Needs attention (amber), or Incomplete (neutral/warning) with one plain-language sentence.
4. **Expandable sections** — SSH sources, SSH keys (grouped), TLS (if requested).
5. **Mobile-friendly** — responsive CSS, large tap targets, no horizontal scroll for summaries.

**Errors** — human messages only (permission denied, connection failed). No stack traces in the browser.

## 7. Architecture

```
scan.py     → discover + read paths, parse to SshKeys aggregates
run.py      → witness_machine(): checks + optional TLS → report dict
report.py   → WitnessReport, severity labels, check blurbs, to_dict()
web.py      → stdlib HTTP on 127.0.0.1:8770, render HTML from report
```

Reuse **paranoid**, **ssh_keys**, and **tlscheck**; do not reimplement crypto or parsing.

## 8. Security

- Bind **127.0.0.1** only; not reachable from other hosts by default.
- **No private key** upload or paste fields.
- **Content-Security-Policy** on HTML responses (default-src 'self'; inline styles allowed for alpha simplicity).
- **Form size limits** (body length cap, bounded number of extra paths).
- Witness reads only paths the OS allows the user running the process to read.

## 9. Future

- Fleet agent pushing witness receipts to a collector.
- Configurable default paths and SSH host key directories.
- Batch signature checking (authorized_keys is public keys only today).
- SPKI/certificate pinning in the witness form.
- Certificate Transparency in the TLS bundle.
- Export **JSON witness receipt** (and optional local signature) for audit trails.

## 10. Open questions

- Should witness write a **signed receipt file** to disk after each run, or stay ephemeral?
- Should unreadable `/etc/ssh` be **Incomplete** or a soft warning when home SSH succeeded?
- Should duplicate keys across files be **deduplicated** by fingerprint in the UI?
- For TLS, should witness default to **staple-only OCSP** forever or expose tlscheck flags in the form?
- Should alpha add a **`witness --json`** CLI matching the web report for automation?
