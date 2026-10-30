# tlscheck (alpha)

`tlscheck` checks the certificate a TLS server presents. It is a standalone
tool in this repository. It is not wired into Bastion's paranoid check runners.

This is an alpha. The report is meant to be read by a person, and a few checks
are deliberately incomplete. Those limits are listed below.

## What it does

Given a hostname, the tool opens TLS itself with certificate verification
turned off, so an expired, untrusted, or name-mismatched server still yields
the Certificate message. It records the peer address, the negotiated TLS
version, the SNI it sent, the certificates in the order the server sent them,
and any stapled OCSP response.

It then verifies that chain against a root bundle the tool controls: the
Mozilla roots vendored inside the `certifi` package. Nothing is downloaded to
obtain that bundle, and the OS trust store is not consulted. The report names
the bundle as `certifi` plus that package's version. A root the server sent is
trusted only when its subject public key is in the bundle, which is also how a
cross-signed root in the middle of a chain is recognized.

The server sends a bag of certificates, not a guaranteed path. The path is
built leaf-first with cryptography's X.509 verifier (`PolicyBuilder`,
`ServerVerifier`, and a `Store` filled only from the chosen bundle). Two
results are always reported:

- `presented` uses only certificates the server sent, plus trust anchors.
- `fetched` is the same check, except a missing intermediate may be retrieved
  with an HTTP GET of an AIA caIssuers URL. Retrieved certificates are labeled
  `retrieved`. Redirects are not followed. Responses are size-capped and timed
  out.

The process exits 1 when `presented` fails. Pass `--allow-fetched` to require
`fetched` instead. Both results are still computed.

On top of the library path build, a public-trust profile must pass:

- The leaf extended key usage contains serverAuth. `anyExtendedKeyUsage` is
  not enough, and a missing EKU fails.
- Certificates that are not trust anchors must not be signed with MD5 or
  SHA-1. RSA keys must be at least 2048 bits. ECDSA is accepted only on
  secp256r1, secp384r1, and secp521r1.
- The check time must fall inside the leaf's notBefore and notAfter. A leaf
  whose notBefore is on or after 2020-09-01 fails when its validity period is
  longer than 398 days.
- The hostname matches `--name`, or the host if `--name` is omitted, using
  dNSName and iPAddress only (RFC 9525). The expected name is encoded to
  A-labels first. A wildcard must be the entire leftmost label, must not match
  the bare domain, and must not be a single-label pattern such as `*.com`.
  If there is no subjectAltName, the hostname check fails. The commonName is
  not used.
- An unknown critical extension fails closed. cryptography's verifier enforces
  that.

Revocation, by default (`--ocsp staple`): if the handshake carried a stapled
OCSP response, it is verified (serial, authorized responder, thisUpdate and
nextUpdate covering the check time). A bad or expired staple fails. If the
leaf has the must-staple TLS feature (`status_request`) and no staple was
present, the run fails. No staple and no must-staple is `skipped`, and a
skipped check does not fail the run. OCSP and CRLs are not downloaded unless
`--ocsp fetch` or `--crl fetch` is set. An unanswered fetch is `skipped`,
never `pass`. `--ocsp off` skips OCSP, including must-staple.

`--pin` may be repeated. Each value is a SHA-256 hex digest of a
SubjectPublicKeyInfo. If any pins are set, the leaf or an intermediate must
match one. No pins means the pin check is skipped.

## What it does not do

- It does not enforce Certificate Transparency.
- It does not use the operating system trust store, or any application's.
- It does not download OCSP responses or CRLs unless you opt in.
- It does not follow HTTP redirects.
- It does not speak STARTTLS.
- It does not load a second bundle such as Chrome's root list.
- It does not treat the Public Suffix List as authoritative. `*.com` is
  rejected because the suffix is a single label. `*.co.uk` is not rejected.
- It does not install a system service. The web page is a process you start
  yourself. It stops when that process stops.
- Stapled OCSP is read through OpenSSL on CPython. The handshake requests the
  status_request extension, then reads the staple from the OpenSSL session.

## How to run

From a checkout, with the repository root on `PYTHONPATH` (this works without
changing how `paranoid_crypto` is installed):

```sh
PYTHONPATH=. python -m tlscheck example.com
PYTHONPATH=. python -m tlscheck example.com --json
PYTHONPATH=. python -m tlscheck example.com --port 443 --sni www.example.com
```

`pip install .` from this repository also installs the `tlscheck` package,
because setuptools is told to find it next to `paranoid_crypto`. `certifi` is
a dependency of that install. After that, `python -m tlscheck HOST` works
without setting `PYTHONPATH`.

```
python -m tlscheck HOST [--port 443] [--sni NAME] [--ip ADDR] [--name NAME]
    [--chain PEMFILE] [--at ISO8601] [--ocsp staple|fetch|off]
    [--crl off|fetch] [--pin HEX] [--allow-fetched] [--json]
```

`--chain` reads a saved presented chain (leaf first, PEM) and does not
connect. AIA and opt-in revocation fetches can still use the network.
`--ocsp` defaults to `staple`. `--at` is the check time; the default is now.

## Local web page

A page on this machine runs the same check. It calls `capture_tls` and
`run_check` in `tlscheck/run.py`. The browser does not verify certificates,
and there is no second copy of the checks.

```sh
PYTHONPATH=. python -m tlscheck.web
PYTHONPATH=. python -m tlscheck.web --listen 8765
```

Open http://127.0.0.1:8765/. The process binds to 127.0.0.1 only. `--listen`
takes a port, or `127.0.0.1:PORT` / `localhost:PORT`. Any other address is
rejected. The default port is 8765. One check runs at a time.

The form takes a hostname, a port (default 443), an optional SNI, an optional
expected name, and an optional "allow fetched chain" checkbox. Submit runs
one check and shows the report on the same page: overall pass or fail, each
check as pass, fail, or skipped with its reason, the leaf subject, SHA-256
fingerprint, notAfter, the presented and fetched chains, the bundle id, the
peer address, the TLS version, and the SNI. A connect or input failure is
shown as an error.

The page uses the command-line defaults for everything it does not ask about.
OCSP stapling is checked. OCSP and CRL downloads stay off. Pins are not set.

The page is not a service:

- It has no accounts.
- It keeps no history.
- It listens on localhost only, until you stop the process.
- It has the same alpha limits as the command line. Certificate Transparency
  is not enforced. The operating system trust store is not used. OCSP and CRL
  fetches are still opt-in, and the form does not offer them.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Every required check passed: the required path (`presented`, or `fetched` with `--allow-fetched`), the public profile, the hostname, validity, a pin when one was set, and revocation when a staple was checked or must-staple applies. |
| 1 | A required check failed. |
| 2 | The tool could not connect, parse the input, or finish the capture. |

The text report includes the leaf subject, its SHA-256 fingerprint, notAfter,
the chain, the bundle id, and each check as pass, fail, or skipped with a
reason. `--json` prints one JSON object with those facts plus the peer IP,
TLS version, and SNI.

## Tests

The tests generate their own certificates and trust a temporary root. They do
not need a public CA or the network. One live check is skipped unless
`TLSCHECK_LIVE=1`.

```sh
PYTHONPATH=. python -m unittest tlscheck.tlscheck_test tlscheck.web_test
```

`tlscheck.web_test` drives the page handler with a fake checker result. It
does not open a TLS connection.
