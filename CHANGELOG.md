# Changelog

Changes in Bastion since it forked from Google's
[Paranoid](https://github.com/google/paranoid_crypto) at version 1.1.1
(commit `bbee489`). The Python package and its version are still
`paranoid_crypto` 1.1.1.

## Unreleased

### Added

- **RSA signature checks.** `CheckRSASignatureFault` factors the signer's key
  from one faulty PKCS#1 v1.5 signature, using Lenstra's CRT fault attack and
  the RFC 8017 DigestInfo encoding for MD5 and SHA-1 through SHA-512. It is the
  first `RSASignatureCheck`. `paranoid.CheckAllRSASigs` and
  `paranoid.GetRSASignatureChecks` run it like the other artifact types. See
  [RSA signature tests](docs/rsa_signature_tests.md).
- **Short-sleeve RSA keys.** `CheckShortSleeveRSA` factors keys whose primes
  have a block of zero bits in every 32-bit limb (CompleteFTP 10.0.0 to 12.0.0)
  or 128-bit limb (seen in Yahoo, Verizon and NetApp certificates), by
  factoring a polynomial. A bit-mask pre-filter keeps the cost for other keys
  under a microsecond. See
  [RSA public key tests](docs/rsa_public_key_tests.md#checkshortsleeversa).
- **Known shared primes.** `CheckKnownPrimes` tests each key on its own against
  the product of primes that earlier scans found shared between RSA keys, so a
  single key is flagged where `CheckGCD` needs the other key in the same batch.
  The primes come from a new storage hook, `Storage.GetSharedPrimesProduct`;
  the default storage bundles the badkeys products (MIT) for 512 to 4096-bit
  moduli. See
  [RSA public key tests](docs/rsa_public_key_tests.md#checkknownprimes).
- **ECDSA nonce reuse.** `CheckNonceReuse` recovers the private key from two
  signatures of one key that share r, whether they used the nonce k or n - k.
  See [ECDSA signature tests](docs/ecdsa_signature_tests.md#checknoncereuse).
- `ec_util.ReducedPublicPoint`, the public point with coordinates reduced
  modulo p, shared by the EC and ECDSA checks.

### Fixed

- **Malformed input no longer aborts a batch.** Each of these used to raise out
  of a check and stop every other artifact in the batch from being tested:
  - an empty batch, in `CheckAllRSA` (via `ExtendedProductTree`);
  - an RSA modulus under 64 bits (`CheckKeypairDenylist`), under 4
    (`CheckUnseededRand`), or empty (`CheckLowHammingWeight`);
  - an ECDSA signature with r or s outside [1, n - 1], in the nonce checks;
  - an EC point with y = 0 (mod p), or an unreduced coordinate, in
    `EcCurve.Add`, `Double` and `BatchDouble`.
- **Import order.** `paranoid_crypto.lib.ecdsa_sig_checks` can be imported
  before `paranoid_crypto.lib.paranoid`; the two no longer import each other at
  load time.
- **CheckWeakECPrivateKey** no longer reports a point off the curve, such as
  one with y = 0, as a recovered private key with discrete log 0. A weak key
  encoded with unreduced coordinates (x + p) is now found instead of hidden.
- **CheckECKeySmallDifference** no longer reports two points off the curve as
  related private keys. The addition formulas ignore the curve coefficient b,
  so such points could show a small "difference".
- **ECDSA nonce checks** now match an issuer key encoded with unreduced
  coordinates, and group one signer's signatures across encodings.
- **CheckIssuerKey** tests the same coordinates on two curves as two keys,
  instead of testing only the first curve it saw.

### Documentation

- New per-check documentation for RSA public keys, EC public keys and RSA
  signatures, replacing upstream's placeholders; a section for
  `CheckNonceReuse` in the ECDSA documentation.
- README rewritten for Bastion, with macOS (Apple Silicon) setup and the
  differences from upstream. CONTRIBUTING describes Bastion's workflow, since
  upstream is archived and no longer accepts pull requests.
- `setup.py` names Bastion's repository and maintainer; upstream stays the
  author. The `Storage.GetOpensslDenylist` docstring now describes the SHA-1
  key the code uses.
