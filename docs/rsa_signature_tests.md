# RSA Signature tests


## Motivation

An RSA signature $s$ on a message with encoded hash $m$ satisfies
$s^e \equiv m \pmod{n}$. A correct signature reveals nothing about the private
key. A *faulty* one can reveal all of it.

Most RSA signers use the Chinese Remainder Theorem: they compute the signature
modulo $p$ and modulo $q$ separately and combine the two halves. If a hardware
or software fault corrupts only one half, the signature is still correct modulo
the other prime $q$ but wrong modulo $p$. Then $s^e - m$ is a multiple of $q$
but not of $n$, and

$$q = \gcd(s^e - m, n)$$

factors the key from that single signature [[Lenstra]]. Faulty signatures have
been found in the wild. In 2015 Weimer factored the RSA keys of faulty TLS
servers, including devices made by Hillstone Networks [[Weimer]]. A 2022 study
found nearly 2,000 non-validating signatures among 2.7 billion passively
collected TLS server signatures, and computed three RSA private keys of Baidu
from them [[Sullivan]]. Cisco ASA and FTD devices leaked RSA private keys
through [CVE-2022-20866]. A 2023 study recovered the private keys of 189 unique
RSA public keys from faulty SSH signatures [[Ryan]].

## Running the checks

`paranoid.CheckAllRSASigs(rsa_sigs)` runs the active checks on a list of
`paranoid_pb2.RSASignature` messages. Each signature needs:

*   `rsa_sig_info.s`, the signature as big-endian bytes;
*   `rsa_sig_info.algorithm`, its `SignatureAlgorithm`;
*   `rsa_sig_info.message_hash`, the full hash of the signed message;
*   `issuer_key_info.n` and `issuer_key_info.e`, the signer's public key.

`paranoid.GetRSASignatureChecks()` returns the check instances keyed by name.
Results are recorded in each signature's `test_info` in the same way as for the
other artifact types.

## Checks

### CheckRSASignatureFault

Checks whether a signature is faulty in a way that leaks a prime factor of the
issuer key. The check rebuilds the encoded message $m$ from the message hash,
computes $\gcd(s^e - m, n)$, and flags the signature at `SEVERITY_CRITICAL`
when the result is a non-trivial factor of $n$. Both factors are attached to
the signature's `test_info.attached_info` under `N_FACTORS`. A correct
signature gives $\gcd(0, n) = n$, and an unrelated invalid signature almost
always gives 1, so a flagged signature always comes with a confirmed
factorization and the check has no false positives.

The encoded message is EMSA-PKCS1-v1_5 from RFC 8017, Section 9.2 [[RFC8017]]:

$$EM = \texttt{00} \,\|\, \texttt{01} \,\|\, \texttt{ff} \ldots \texttt{ff} \,\|\, \texttt{00} \,\|\, T,$$

where $T$ is the DER encoding of the DigestInfo of the hash, with the prefixes
listed in Note 1 of that section, and $EM$ has the byte length of $n$. The
check supports `RSA_WITH_MD5`, `RSA_WITH_SHA1`, `RSA_WITH_SHA224`,
`RSA_WITH_SHA256`, `RSA_WITH_SHA384` and `RSA_WITH_SHA512`. A signature passes
without being tested when:

*   its algorithm is RSA-PSS or unknown, since PSS encoding is randomized and
    $m$ cannot be rebuilt from the hash;
*   the message hash has the wrong length for its algorithm;
*   $s$ is not in the range $[1, n - 1]$;
*   $n$ is too short to hold the encoding.

The check does not handle the raw MD5‖SHA-1 encoding of TLS 1.0 and 1.1
signatures, which has no DigestInfo, or signatures whose message hash is not
known.

<!-- Literature -->

[CVE-2022-20866]: https://nvd.nist.gov/vuln/detail/CVE-2022-20866 "NVD, CVE-2022-20866"
[Lenstra]: https://people.redhat.com/~fweimer/rsa-crt-leaks.pdf "F. Weimer, Factoring RSA Keys With TLS Perfect Forward Secrecy, 2015 (Section 1.1 summarizes Lenstra's CRT attack)"
[RFC8017]: https://www.rfc-editor.org/rfc/rfc8017.html "RFC 8017, PKCS #1: RSA Cryptography Specifications Version 2.2"
[Ryan]: https://dl.packetstormsecurity.net/papers/cryptography/passive-ssh-key-compromise-2023-1711.pdf "K. Ryan, K. He, G. A. Sullivan, N. Heninger, Passive SSH Key Compromise via Lattices, ACM CCS 2023"
[Sullivan]: https://par.nsf.gov/servlets/purl/10431823 "G. A. Sullivan, J. Sippe, N. Heninger, E. Wustrow, Open to a fault: On the passive compromise of TLS keys via transient errors, USENIX Security 2022"
[Weimer]: https://people.redhat.com/~fweimer/rsa-crt-leaks.pdf "F. Weimer, Factoring RSA Keys With TLS Perfect Forward Secrecy, 2015"
