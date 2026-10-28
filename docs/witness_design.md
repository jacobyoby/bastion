# Bastion witness (alpha) — design

Witness is a **local-only** tool that helps operators **observe and confirm** SSH public keys, public certificates shipped or stored by browsers and installed applications, and (optionally) a remote TLS certificate, on **this machine** using Bastion’s existing checks—not an app’s internal trust chain or opaque summaries.

## 1. Problem

Operators need to answer: “Do the SSH keys and (optionally) the TLS identity on this host look sound under Bastion’s public-key and certificate checks?”

They should not have to trust a deployment tool’s green checkmark or paste private key material. Witness reads **public** SSH material from standard locations, runs the same **paranoid** RSA/EC checks as the library, and optionally runs **tlscheck** against a hostname the operator supplies.

## 2. Users and scenarios

| User | Scenario |
| --- | --- |
| Local admin | After provisioning, confirm SSH keys, browser public material, and app certificates on a laptop or server. |
| Security reviewer | On a review VM, collect installed public keys and whether any fail Bastion checks. |
| Pre-deploy sanity check | Before cutover, run witness on a staging host with optional TLS host matching production SNI. |

## 3. Scope (alpha)

**In scope**

- One-shot witness run on **localhost** (127.0.0.1 UI).
- Default scan of `~/.ssh/authorized_keys` and `~/.ssh/known_hosts`.
- Optional extra paths (textarea) and readable `*.pub` under `/etc/ssh` when the process can read them.
- SSH: parse with `ssh_keys`, check with `paranoid.CheckAllRSA` / `CheckAllEC`.
- Browsers on this Linux host: discover Chrome, Chromium, Edge, and Firefox; scan public PEM/CRT under the install prefix.
- Installed applications: `dpkg` package count (short sample) and a bounded search for public PEM, CRT, and OpenSSH keys.
- Optional TLS: `tlscheck.run.run_check` with the same semantics as `python -m tlscheck` (Mozilla roots in certifi, not the OS store).
- Clear overall result: **Confirmed**, **Needs attention**, or **Incomplete**.
- No accounts, no persisted run history.

**Out of scope (alpha)**

- Remote fleet scanning or agents.
- Certificate Transparency.
- OS trust store for the TLS check (tlscheck never used it).
- Uploading or pasting private keys. Local private-key files are skipped, not displayed.
- Full weakness scans of the system root bundle or NSS `cert9.db` (see [Browsers and installed applications](#11-browsers-and-installed-applications)).
- Signed witness receipts (see [Open questions](#10-open-questions)).

## 4. Witness checks defined

### SSH witness bundle

1. **Discover sources** — configured paths plus optional `/etc/ssh/*.pub`.
2. **Parse** — `ParseAuthorizedKeys` or `ParseKnownHosts` (or authorized_keys-style for `.pub`).
3. **Check** — all RSA keys through `CheckAllRSA`, all EC keys through `CheckAllEC`.
4. **Report** — per source (read ok / missing / unreadable), per key (fingerprint, weak flag, failing check rows with severity).

Unsupported line types (e.g. Ed25519) are listed but not run through paranoid checks.

### Browsers and installed applications

See [section 11](#11-browsers-and-installed-applications). Public RSA/EC keys from those scans join the same `CheckAllRSA` / `CheckAllEC` pass as SSH. System roots and NSS databases are reported as skipped and are not part of that pass.

### TLS witness bundle (optional)

When the operator supplies a hostname:

1. If `tlscheck` is importable: capture handshake, `run_check`, map `Report.exit_code` (0 pass, 1 check failure, 2 operational error).
2. If `tlscheck` is missing: **skip** with an explanatory message (not Incomplete).

TLS uses live network I/O to the given host; it is not a witness of “certs on disk.”

## 5. Confirmation model

### Overall status

| Status | Meaning |
| --- | --- |
| **Confirmed** | Every RSA/EC artifact that was actually checked is clean, and no requested source failed closed (unreadable path or TLS exit 2). TLS may be skipped or exit 0. |
| **Needs attention** | At least one scanned SSH, browser, or application key has `test_info.weak`, and/or TLS exit code 1 (check failure). |
| **Incomplete** | A requested SSH path, browser/app scan root, or matched candidate file was unreadable, and/or TLS exit code 2. |

Precedence: **Needs attention** wins over **Incomplete** when both a weak key and a read failure exist, so a weak key is not hidden. Skipped rows (system roots, NSS, file caps, missing `dpkg-query`, no browsers installed) are visible and are **not** a pass, but they do not by themselves block **Confirmed** or force **Incomplete**. Missing browsers are an informational skip. A run can show Incomplete in TLS while SSH is Confirmed.

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

The page is a confirmation screen for this machine, not a single-column path-paste form.

1. **Witness this machine** — one sentence: checks public keys and certificates on this computer, then confirms the result.
2. Three large cards, on by default: **Browsers** (Chrome, Chromium, Edge, Firefox), **Installed apps** (package list and public certs in app config), and **SSH** (`authorized_keys` and `known_hosts`). Optional TLS host is a small secondary field. Extra SSH paths stay available and are not the main control.
3. **Confirm this machine** posts the form (127.0.0.1 only).
4. After a run, the first thing on the page is a large status panel: **Confirmed** (green), **Needs attention** (amber), or **Incomplete** (blue), with one plain sentence. Examples: “No weak public keys in the browsers, apps, and SSH files we could read.” and “1 key needs attention in Installed apps.” The sentence does not treat skipped system roots as a pass.
5. Result cards for Browsers, Installed apps, and SSH show a count and a short status (clean / N need attention / skipped). Files and failed checks expand under the card. TLS appears only when a host was entered. The system CA bundle says “Public root certificates were counted, not weakness-scanned.” and is not a green pass. “No browser install found” and “No public keys in app configs” are informational, not errors.
6. **Mobile-friendly** — cards stack on a narrow screen. Large tap targets. Fingerprints wrap.

**Errors** — human messages only (permission denied, connection failed). No stack traces in the browser.

## 7. Architecture

```
scan.py      → discover + read SSH paths, parse to SshKeys aggregates
material.py  → PEM/DER/SSH public keys into protos; skip private-key files
hostscan.py  → browsers, system bundle, dpkg sample, bounded app paths
run.py       → witness_machine(): one CheckAllRSA/EC pass + optional TLS
report.py    → WitnessReport, severity labels, check blurbs, to_dict()
web.py       → stdlib HTTP on 127.0.0.1:8770, render HTML from report
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

## 11. Browsers and installed applications

Linux (Debian/Ubuntu) only in this alpha. Nothing is uploaded. The UI stays on 127.0.0.1. Private keys are not reported.

### Browsers

Witness looks for Google Chrome, Chromium, Microsoft Edge, and Firefox under common prefixes (`/opt/google/chrome`, `/usr/lib/chromium`, `/usr/lib/firefox`, `/opt/microsoft/msedge`, matching `/usr/bin` names, snap `/snap/<name>/current`, and flatpak `current/active/files` when those paths exist). It does not add a native dependency.

NSS `cert9.db` is not parsed. If `certutil` is already on `PATH` and a profile `cert9.db` exists, witness may list CA nicknames. Nicknames are not Bastion results and the row is **skipped — not a pass**. If `certutil` is absent, the database is recorded as skipped for the same reason. No `cert9.db` means there was nothing in that store to check.

PEM and CRT files under each install prefix are size-capped (1 MiB), depth-capped (6), and count-capped (40 candidate files per install prefix). RSA and EC public keys are checked. Other types are listed as not checked.

The system bundle `/etc/ssl/certs/ca-certificates.crt` is parsed only to **count** certificates. The report says: system trust bundle present, N certificates, full weakness scan not run on public roots in this alpha. That row is skipped, not a pass. Witness does not run `CheckAllRSA` on those roots.

User-added CAs in `/usr/local/share/ca-certificates` are fully checked when files are present. If that directory is missing or empty, witness says locally added roots that exist only inside the bundle were not separated and were not fully checked (skipped, not a pass).

No installed browser is not a failure. The section says no browsers were found. The rest of the run can still be Confirmed.

### Installed applications

When `dpkg-query` exists, witness stores the package **count** and up to 12 notable names (openssl, openssh, nginx, browsers, and similar). It does not print the full package list. A missing `dpkg-query` or an empty list is reported and does not crash or fail the run.

The file walk is bounded:

| Root | Depth |
| --- | --- |
| `/etc` | 4 |
| `/usr/local/share` | 5 |
| `/opt` | 5 |
| `~/.config` | 3 |

Caps: 200 candidate files, 2500 directories, 1 MiB per file. Names: `*.pem`, `*.crt`, `*.cer`, `*.pub`, `authorized_keys`, `known_hosts`. `/etc/ssl/certs` (per-root PEMs and hash links) and `/etc/ssl/private` are not walked. A PEM with more than 25 certificates is treated as a bundle: counted, full scan skipped, not a pass.

Files whose header is `PRIVATE KEY` or an OpenSSH private key are skipped. The report may show the path. It does not show the key. X.509 certificates are parsed with `cryptography`; RSA/EC public numbers are stored with `util.Int2Bytes` on `RSAKey` / `ECKey` protos and then `CheckAllRSA` / `CheckAllEC`. OpenSSH public keys use `ssh_keys`. Findings are grouped by path (`/opt/<app>`, `/etc/<app>`, `~/.config/<app>`).

Permission errors on a scan root or on a matched candidate file make the run **Incomplete**. Permission errors on unrelated directories (for example `/etc/credstore.encrypted`) are notes, not a failed closed scan. A missing optional directory is not a failure.

### Explicitly not confirmed

- Certificates inside the system trust bundle (full weakness scan is not run).
- NSS `cert9.db` contents.
- Files past the size, depth, or count caps.
- Private keys (ignored).
- Key types Bastion does not check (for example Ed25519).
- Public roots that could not be separated from `/etc/ssl/certs/ca-certificates.crt`.
