# RSA Public Key tests


## Motivation

An RSA public key $(n, e)$ should reveal nothing about the primes $p$ and $q$
with $n = pq$. A flawed key generator can leave structure in the primes. Common
causes are a weak or unseeded random number generator, a prime search that
starts from a predictable value, primes chosen too close together, or a
programming error that repeats bit patterns. Such structure can make $n$ easy
to factor, and anyone who factors $n$ can compute the private key.

The RSA key tests look for this structure using only public keys. Most of them
try to factor $n$ under one assumption about how the primes were made. A check
that finds factors gives a confirmed result and attaches the factors to the
key. A few checks do something else:

*   Policy checks (CheckSizes, CheckExponents) test the modulus size and the
    exponent.
*   Structure checks (CheckROCA, CheckROCAVariant, CheckGCDN1) find signs of
    non-random generation without factoring.
*   CheckOpensslDenylist looks the key up in a list of known weak keys.

Throughout this page, $\ell$ is the bit length of $n$.

The [README](../README.md#preliminary-results) has the upstream Paranoid team's
September 2022 results from Certificate Transparency for the RSA checks with
high or critical severity, together with the CVEs they consider related.

## Running the checks

`paranoid.CheckAllRSA(rsa_keys)` in
[paranoid.py](../paranoid_crypto/lib/paranoid.py) runs every check in the order
of the sections below: first the single-key checks, then the aggregate checks.
Each key is a `paranoid_pb2.RSAKey` whose `rsa_info.n` and `rsa_info.e` are
big-endian byte strings, for example from `util.Int2Bytes`.
[examples/rsa_public_keys.py](../examples/rsa_public_keys.py) shows how to build
one. Pass `log_level=1` to log each check's result and running time. To run
checks one at a time, `paranoid.GetRSASingleChecks()` and
`paranoid.GetRSAAggregateChecks()` return the check instances keyed by name.

These entry points always build each check with its default settings. To change
a setting, such as `max_steps`, `bound`, `pattern_sizes`, `gcd_bound` or
`paranoid_storage`, create the class from `rsa_single_checks` or
`rsa_aggregate_checks` yourself, for example
`rsa_single_checks.CheckFermat(max_steps=10**6).Check(rsa_keys)`.

Single-key checks look at each key on its own, so a key's result does not
depend on the other keys in the list. Aggregate checks compare all keys passed
in one call, so their results depend on which keys are tested together.

Each check returns `True` if it flags at least one key. It records a
`TestResultsEntry` (check name, result, severity) in each key's
`test_info.test_results`. `test_info.weak` is set when any check flags the key
and is never reset to false. Factors are attached to `test_info.attached_info`
under `N_FACTORS`, except that CheckGCDN1 uses `N-1_FACTORS`.
`util.GetAttachedFactors(key.test_info, "N_FACTORS")` reads them back as a set
of integers.

`weak` is also set by the policy checks and by leads that need further
analysis, not only by factorizations. To triage, use the severity of each
entry, or `util.GetHighestSeverity(key.test_info)` for the highest severity
among a key's flagged entries. `SEVERITY_UNKNOWN` marks a suspicion. Its enum
value is 0, so it sorts below `SEVERITY_LOW`.

If a check runs again on the same key, a positive result is kept, and the
recorded severity is the larger enum value over all runs, negative runs
included. So if CheckLowHammingWeight passes a key in one run and only suspects
it in another, the merged entry shows a positive result at `SEVERITY_CRITICAL`.

Check                      | Input      | Severity                                                  | Attaches factors
-------------------------- | ---------- | --------------------------------------------------------- | ----------------
CheckSizes                 | single key | `SEVERITY_MEDIUM`                                         | no
CheckExponents             | single key | `SEVERITY_MEDIUM`                                         | no
CheckROCA                  | single key | `SEVERITY_HIGH`                                           | no
CheckROCAVariant           | single key | `SEVERITY_MEDIUM`                                         | no
CheckFermat                | single key | `SEVERITY_CRITICAL`                                       | yes
CheckHighAndLowBitsEqual   | single key | `SEVERITY_CRITICAL`                                       | yes
CheckOpensslDenylist       | single key | `SEVERITY_CRITICAL`                                       | no
CheckContinuedFractions    | single key | `SEVERITY_CRITICAL`                                       | when it factors
CheckBitPatterns           | single key | `SEVERITY_CRITICAL`                                       | yes
CheckPermutedBitPatterns   | single key | `SEVERITY_CRITICAL`                                       | yes
CheckPollardpm1            | single key | `SEVERITY_CRITICAL`                                       | when it factors
CheckLowHammingWeight      | single key | `SEVERITY_CRITICAL`, or `SEVERITY_UNKNOWN` when suspected | when it factors
CheckUnseededRand          | single key | `SEVERITY_CRITICAL`                                       | yes
CheckSmallUpperDifferences | single key | `SEVERITY_CRITICAL`                                       | yes
CheckKeypairDenylist       | single key | `SEVERITY_CRITICAL`                                       | yes
CheckGCD                   | aggregate  | `SEVERITY_CRITICAL`                                       | yes
CheckGCDN1                 | aggregate  | `SEVERITY_UNKNOWN`                                        | no (attaches a GCD of $n - 1$)

## Checks

### CheckSizes

Checks whether the modulus is shorter than 2048 bits. A short modulus leaves
less margin against general-purpose factoring. This is a policy check: it does
not look for a flawed generator and does not try to factor the key. The
2048-bit minimum is fixed in the code.

### CheckExponents

Checks whether the public exponent $e$ is 65537 and flags any other value,
small or large. Only `rsa_info.e` is read. The check treats 65537 as the only
expected exponent. Any other value means the key did not come from the usual
default settings, so it is worth a closer look. Keys that use another exponent
on purpose are flagged too. The check does not recover anything from the key.

### CheckROCA

Checks whether a key has the structure of the [ROCA] keys [[Nemec]]. The README
lists [CVE-2017-15361], in the Infineon RSA library, as related. ROCA keys were
generated so that each prime, reduced modulo a product of small primes, has a
discrete logarithm to the base 65537. Their product $n$ then has one too. For
each of the 39 primes $r$ from 3 to 173, the check tests whether $n \bmod r$ is
a power of $65537 \bmod r$. A key is flagged only if this holds for all 39
primes. The detector's docstring says such a key is weak with high probability.

The check reads only $n$, not the exponent. It detects the structure but does
not factor the key. It tests only the base 65537; CheckROCAVariant covers other
bases.

### CheckROCAVariant

Checks for keys built like ROCA keys but with an unknown base. Let $M$ be a
product of small primes. Suppose $p \equiv g^{r_1}$ and $q \equiv g^{r_2}
\pmod{M}$ for some base $g$, with $r_1 \equiv r_2 \pmod{2}$. Then $n$ is a
quadratic residue modulo every prime factor of $M$. The check tests whether $n$
is a quadratic residue modulo each of the 48 smallest primes above 3 (5 to
229). Keys that the CheckROCA detector flags are excluded, so that new kinds of
weak keys stand out.

The check works for any base, but it catches an affected key only about half
the time, when $r_1$ and $r_2$ have the same parity. A randomly generated key
fails with a probability of about $2^{-48}$. A flagged key is suspicious, not
factored.

### CheckFermat

Checks whether $p$ and $q$ are close enough for [Fermat's method][Fermat].
The method writes an odd $n$ as $a^2 - b^2 = (a + b)(a - b)$. When $p$ and $q$
are close, $a = (p + q)/2$ is close to $\sqrt{n}$, so a search upward from
$\lceil \sqrt{n} \rceil$ finds it quickly. The check tries up to 100000 values
of $a$. The README lists [CVE-2022-26320] as related: the Rambus SafeZone Basic
Crypto Module, used in some Fujifilm and Canon devices, generated RSA keys that
Fermat's method breaks [[FermatAttack]].

The check finds only primes for which $(p + q)/2$ is within 100000 steps of
$\lceil \sqrt{n} \rceil$; the constructor's `max_steps` sets this bound. An even
modulus is reported as factored by 2, and a perfect square as $a \cdot a$.

### CheckHighAndLowBitsEqual

Checks whether $p$ and $q$ share enough high and low bits. It factors $n$ when
the $r$ least significant bits of $p$ and $q$ are equal, the $s$ most
significant bits are equal, and $r + s$ is at least about $\ell/4$, that is,
half the bit length of each prime. For a 2048-bit modulus, 256 equal high bits
and 256 equal low bits are enough. The function docstring's example uses 32
equal high bits and 32 equal low bits in a 256-bit modulus. (The class
docstring says half the bit length of $n$, which would require $p = q$.)

The method is a variant of Fermat's. Equal high bits give the high bits of
$(p + q)/2$ from the integer square root of $n$, as in CheckFermat. Equal low
bits give its low bits from a square root of $n$ modulo a power of two, because
$p \equiv q \pmod{2^m}$ implies $n \equiv ((p + q)/2)^2 \pmod{2^{2m-2}}$. The
check combines the two and searches the few middle bits that neither part
fixes (3 by default).

Moduli with $n \bmod 8 \ne 1$ are skipped. In that case
$p \not\equiv q \pmod 8$, so fewer than three low bits are equal, and the method
can find nothing that Fermat's method would not. Moduli shorter than 6 bits are
also skipped.

### CheckOpensslDenylist

Checks whether the key is one of the keys made with the predictable random
number generator of OpenSSL on Debian-based systems. The README lists
[CVE-2008-0166] ([DSA-1571]) as related. The check builds the string
`Modulus=<n in uppercase hex>\n` and hashes it with SHA-1. It keeps the last 20
hex digits of the hash and looks up `RSA-<bit length>:<digits>` in the bundled
denylists `lib/data/weak_keylist.RSA-1024.dat`, `weak_keylist.RSA-2048.dat` and
`weak_keylist.RSA-4096.dat`, with 294912 entries each.

Only moduli of exactly 1024, 2048 or 4096 bits can match; keys of any other
size pass. A match is a lookup on 80 bits of a hash, not a factorization.

### CheckContinuedFractions

Checks, using a continued fraction, whether both primes have a repeating
pattern. Many of the weak primes in Appendix A of [[smartfacts]] (also listed
as [ePrint 2013/599][smartfactsEprint]) have a repetitive pattern. This puts
each of them close to $\frac{a}{b} 2^m$ for a small fraction $a/b$, where $m$
is the size of the prime. If both factors have this form, so does $n$. The
continued fraction of $n / 2^{\ell}$ then has an unusually large coefficient.

For each convergent with denominator $v$, the check writes $n v = a z^2 + b z +
c$ with $z = 2^{\lfloor \ell/2 \rfloor}$. If $a x^2 + b x + c$ has rational
roots, a GCD with $n$ usually gives a factor. A key is flagged when a factor is
found, or when a coefficient reaches the bound $2^{48}$.

The bound has to be large. By the
[Gauss-Kuzmin distribution][GaussKuzmin], a coefficient of at least $k$ appears
with a probability of about $1/(k \ln 2)$. The bound should therefore be well
above the number of keys tested times the length of the expansion. The default
was chosen so that testing 1 billion 2048-bit keys likely gives no false
positive; the constructor's `bound` changes it.

Both primes need the pattern. When only one prime has it, CheckBitPatterns is
the check that applies. A key with a large coefficient but no factorization is
still flagged at `SEVERITY_CRITICAL`, with no factors attached. The docstring
notes that such a key may still be weak, because the factoring attempt is
rather primitive.

### CheckBitPatterns

Checks whether one of the primes has a repeating bit pattern. A prime with a
$k$-bit repeating pattern can be written as $p = (a B + c)/d$ with
$d = 2^k - 1$ and small $a$ and $c$. For each pattern size,
`rsa_util.CheckFraction` looks for such a factor. It reduces a 3-dimensional
lattice built from $n$ and $d$ and takes a GCD with $n$. Only one prime needs
the pattern. The check still works if some of the most and least significant
bits differ from the pattern, but the longest pattern it can find is then
shorter.

The default pattern sizes come in three groups:

*   1, 3, 5, ..., 15: short patterns like those reported in [[smartfacts]].
*   31, 63, 127, 255 and 511: periods of many simple LFSRs.
*   8, 16, 32, 64, 128 and 256: patterns left by copying memory blocks.

The constructor's `pattern_sizes` replaces this list. Pattern sizes above
$\ell / 8$ are skipped, because the method cannot find them even in the best
case. A 2048-bit modulus is tested with sizes up to 256 and skips 511. A
4096-bit modulus is tested with all sizes.

### CheckPermutedBitPatterns

Checks whether one of the primes has a repeating bit pattern whose words were
swapped. Many primes listed in [[smartfacts]] contain a short repeating
pattern with adjacent words swapped. The swapping makes the period too long for
CheckBitPatterns. In the docstring's example, a 512-bit prime with a 7-bit
pattern and swapped 16-bit words repeats only every $7 \cdot 32 = 224$ bits.

Such a prime still has the form $p = (a 2^{m} + b)/d$ with small $a$ and $b$,
where

$$d = \frac{(2^{s} - 1)(2^{s w} + 1)}{2^{w} + 1}.$$

Here $s$ is the pattern size and $w$ is the word size. The formula was found
partly by experiment. The check tries word sizes 8, 16, 32 and 64, with odd
pattern sizes from 3 to $w - 1$, each with `rsa_util.CheckFraction`.

A denominator longer than $\ell / 8$ bits is not tried. A 2048-bit modulus is
tested with 14 (word size, pattern size) pairs. The largest pattern sizes are 7
for 8-bit words, 15 for 16-bit, 7 for 32-bit and 3 for 64-bit words. A 4096-bit
modulus is tested with 20 pairs.

### CheckPollardpm1

Checks, using Pollard's $p - 1$ method, whether $p - 1$ is powersmooth. For
speed, some key generators may build keys from much smaller numbers. As an
example, the docstring points to a published list of all odd 32-bit primes,
whose page offers it as a base for cryptography [[primes32]]. If $m$ is a
multiple of $p - 1$, then $a^m \equiv 1 \pmod{p}$ by Fermat's little theorem,
so $\gcd(a^m - 1, n)$ reveals $p$.

The check uses $a = 2^{n-1} \bmod n$, which also covers $p = bm + 1$ and
$q = cm + 1$ where $b$ or $c$ is smooth. By default, $m$ is the product of all
primes below $2^{20}$. The first 150 of these primes are raised to the largest
power that does not exceed $2^{64}$. The constructor's `bound` argument replaces
the default $m$ with a B-powersmooth one.

For speed, the test runs only when $\gcd(n - 1, m) \ge 2^{60}$. This rests on
the assumption that if $p - 1$ and $q - 1$ are both smooth, so is their GCD. As
a result, a key where only $p - 1$ is smooth can be skipped. When both are
smooth enough, $\gcd(a^m - 1, n)$ is $n$ itself, and the key is flagged at
`SEVERITY_CRITICAL` with no factors attached.

### CheckLowHammingWeight

Checks whether $n$ is the product of primes with a low Hamming weight, that is,
primes with few 1 bits. The search builds $p$ and $q$ from the most significant
bit down. It keeps partial guesses in a priority queue ranked by the bit length
of the remainder $n - p_0 q_0$ plus five times the combined Hamming weight of
$p_0$ and $q_0$. The docstring describes the method as loosely based on
crackpot claims, for which it names no source, that the bits of the factors can
be read from the bits of the product. That is false for general integers but
can work when both factors have few 1 bits.

The search stops after 2500 steps unless it has found a promising branch, that
is, a partial guess that scored below $\ell$. It always stops after $10^6$
steps. The docstring estimates these limits at about 100 ms and about 20
seconds; actual times depend on the hardware. In a collection of about 28000
real RSA keys, no key scored below $\ell$, so a correctly generated key very
likely stops at the first limit.

If no factorization is found but the best partial guess scored at most
$\ell - 12$, the key is flagged as suspected at `SEVERITY_UNKNOWN`. The
docstring gives these examples of keys that can be detected this way:

*   The weight is near the limit the search can factor. Two 1024-bit primes
    of Hamming weight 96 often need $10^7$ or more steps.
*   Only the high bits of the factors have a low weight. The key may still be
    weak, since [Coppersmith's method][Coppersmith] could recover the low bits.
*   The primes differ in size.
*   The search spends its steps on other low-weight partial
    factorizations.

### CheckUnseededRand

Checks whether a prime came from a random number generator that was never
seeded or was seeded with 0. Such a generator gives the same output in every
run, so its first outputs can be listed in advance. The check takes the bundled
outputs for the prime size $\lfloor (\ell + 1)/2 \rfloor$. It tries each output
$x$ as a guess for $p$, along with $x$ with its top bit set and $x$ with its
top two bits set.

Each guess goes to `special_case_factoring.FactorWithGuess`. This uses
Lehman's method [[Lehman]], which factors $n$ when the guess is close to $p$.
Close typically means $|p - p_0|$ of up to about $\ell/6$ bits, or about
$\ell/4$ bits when $p/q$ is near a fraction with a small numerator and
denominator. So the check also catches a prime taken as the next prime after a
generator output.

The data is in `lib/data/unseeded_rands.py`. For each prime size of 512, 1024,
1536, 2048 and 4096 bits it holds 80 numbers: the first 10 outputs of each of
these eight sources.

*   GMP's Mersenne Twister, unseeded.
*   GMP's Mersenne Twister, seeded with 0.
*   GMP's linear congruential generator with size 32 (the gmpy default),
    unseeded.
*   The same size-32 generator, seeded with 0.
*   GMP's linear congruential generator with size 120, unseeded.
*   The same size-120 generator, seeded with 0.
*   Java's `new BigInteger(bits, rnd)` with `rnd = new Random(0)`.
*   Java's `new BigInteger(bits, 25, rnd)` with `rnd = new Random(0)`.

Data therefore exists for moduli of 1023-1024, 2047-2048, 3071-3072, 4095-4096
and 8191-8192 bits. A key of any other size has no candidates and passes
without being tested. Only the first 10 outputs of each listed generator are
covered; a `storage.Storage` passed as the constructor's `paranoid_storage` can
supply other outputs.

### CheckSmallUpperDifferences

Checks whether $|p - q|$ is one of a few predictable values.
[FIPS 186-4][FIPS186-4] (Appendix B.3.1, criterion 2(d)) requires
$|p - q| > 2^{\ell/2 - 100}$, and its successor [FIPS 186-5][FIPS186-5] keeps
the same criterion in Appendix A.1.1. An implementer who misreads this might,
for example, choose $q$ as the next prime after $p + 2^{\ell/2 - 100}$.

With $k = \lfloor \ell/2 \rfloor$, the check tests six differences:
$2^{k-100}$, $2^{k-128}$, $2^{k-160}$, $2^{k-256}$, $2^{k-2}$ and $2^{k-3}$.
For each difference $\delta$, it computes the guess
$p_0 = \lfloor \sqrt{n + (\delta/2)^2} \rfloor + \delta/2$. It then passes the
guess to `FactorWithGuess`, as CheckUnseededRand does.

The check is skipped when the primes would be shorter than 384 bits
($\ell < 768$); CheckSizes already reports such keys. Only the six differences
above are tested.

### CheckKeypairDenylist

Checks whether the key was generated by the npm [keypair] package before
version 1.0.4, which has the weak seeding of [CVE-2021-41117]
([GHSL-2021-1012], [GHSA-3f99-hvg4-qjwj]). According to the GHSL advisory, each
byte of the generator's seed is 0 with a probability of 97% and otherwise holds
a value from 0 to 9.

The check looks up the 64 most significant bits of $n$ in a precomputed table.
In the table format of `Storage.GetKeypairData`, each entry gives the first
seed byte, which can take any value from 0 to 255, and the positions and values
(0 to 9) of the other nonzero seed bytes; all remaining bytes are zero. That is
enough to rebuild the key with `keypair_generator`, a reimplementation of the
package's [generator][keypairGenerator] that exists only for this check. The
rebuilt primes are accepted only if $pq = n$, so a match is a confirmed
factorization.

The bundled table, `lib/data/keypair_table_small.lzma`, has 768 entries. They
cover every value of the first seed byte, with all other bytes zero, for 2048-,
3072- and 4096-bit moduli. Moduli of other sizes, including 1024 bits, are not
in it. By the formula in `Storage.GetKeypairData`, a table that brute forces
only the first byte detects about 33% of the weak keys, and one that also brute
forces two more bytes detects about 90.6%. The class docstring quotes the 90.6%
figure for the default storage, but no such table is bundled. A larger table
can be supplied through a `storage.Storage` passed to the constructor.

### CheckGCD

Checks whether two keys share a prime. If $n_1$ and $n_2$ share a prime $p$,
then $\gcd(n_1, n_2) = p$ factors both keys. For every modulus $n_i$, the check
computes $g = \gcd(n_i, \prod_{j \ne i} n_j)$ over the other distinct moduli in
the call, using a product tree and a remainder tree ([batch GCD][batchgcd]). It
attaches $g$ and $n_i/g$ as factors.

The check only finds primes shared within the keys passed in one call, so a
single key is never flagged. Duplicate moduli are merged before the GCD, so
passing the same modulus twice does not flag it. If both primes of a key appear
in other keys, the GCD is $n$ itself and the attached factors are $n$ and 1.

### CheckGCDN1

Checks whether $n - 1$ shares an unusually large divisor with the values
$n - 1$ of the other keys in the call. For each key it computes
$\gcd(n_i - 1, \prod_{j \ne i} (n_j - 1))$ over the other distinct keys, with
the same batch GCD as CheckGCD, and flags the key if this GCD is at least
$2^{128}$. The GCD is attached under `N-1_FACTORS`. The check is heuristic and
does not factor a key. It finds patterns that point to non-random key
generation, and further analysis is needed to tell whether such a pattern is a
vulnerability. The docstring gives three motivations:

1.  It has a non-negligible chance to detect ROCA keys and keys with similar
    failures, whatever the generator. CheckROCA detects ROCA keys reliably but
    would miss them if the implementation were modified.
2.  Provable primes can be built by recursively constructing the factors of
    $p - 1$. If those factors were reused, this check might catch it.
3.  For strong primes, $p - 1$ has a large prime factor. If that factor were
    reused, this check might catch it too.

The class docstring describes the pairwise case, $\gcd(n_1 - 1, n_2 - 1)$. For
that case it argues that two integers chosen uniformly at random from
$1 \ldots m$ have a GCD larger than $k$ with a probability of at most $1/k$,
and that the values $n - 1$, though a little biased (they are always even),
should not change this by more than a small constant. The batch GCD can reach
the bound through several keys at once without any single pair doing so, so the
chance of a false positive can only grow with the number of keys tested
together. The constructor's `gcd_bound` sets the bound; the docstring's rough
estimates and experiments suggest a value of about $2^{128}$.

<!-- Literature -->

[batchgcd]: https://facthacks.cr.yp.to/batchgcd.html "FactHacks: Batch gcd"
[Coppersmith]: https://en.wikipedia.org/wiki/Coppersmith_method "Coppersmith method"
[CVE-2008-0166]: https://nvd.nist.gov/vuln/detail/CVE-2008-0166 "NVD, CVE-2008-0166"
[CVE-2017-15361]: https://nvd.nist.gov/vuln/detail/CVE-2017-15361 "NVD, CVE-2017-15361"
[CVE-2021-41117]: https://nvd.nist.gov/vuln/detail/CVE-2021-41117 "NVD, CVE-2021-41117"
[CVE-2022-26320]: https://nvd.nist.gov/vuln/detail/CVE-2022-26320 "NVD, CVE-2022-26320"
[DSA-1571]: https://www.debian.org/security/2008/dsa-1571 "Debian DSA-1571-1, New openssl packages fix predictable random number generator"
[Fermat]: https://en.wikipedia.org/wiki/Fermat%27s_factorization_method "Fermat's factorization method"
[FermatAttack]: https://fermatattack.secvuln.info/ "H. Böck, Fermat Attack on RSA"
[FIPS186-4]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf "FIPS 186-4, Digital Signature Standard (DSS) (withdrawn)"
[FIPS186-5]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf "FIPS 186-5, Digital Signature Standard (DSS)"
[GaussKuzmin]: https://en.wikipedia.org/wiki/Gauss%E2%80%93Kuzmin_distribution "Gauss-Kuzmin distribution"
[GHSA-3f99-hvg4-qjwj]: https://github.com/juliangruber/keypair/security/advisories/GHSA-3f99-hvg4-qjwj "Insecure random number generation in keypair"
[GHSL-2021-1012]: https://securitylab.github.com/advisories/GHSL-2021-1012-keypair/ "GitHub Security Lab advisory GHSL-2021-1012"
[keypair]: https://www.npmjs.com/package/keypair "keypair on npm"
[keypairGenerator]: https://github.com/juliangruber/keypair/blob/master/index.js "keypair, index.js"
[Lehman]: https://doi.org/10.1090/S0025-5718-1974-0340163-2 "R. S. Lehman, Factoring large integers, Math. Comp. 28 (1974), 637-646"
[Nemec]: https://crocs.fi.muni.cz/public/papers/rsa_ccs17 "M. Nemec, M. Sys, P. Svenda, D. Klinec, V. Matyas, The Return of Coppersmith's Attack: Practical Factorization of Widely Used RSA Moduli, ACM CCS 2017"
[primes32]: http://www.umopit.ru/CompLab/primes32eng.htm "All 32-bit prime numbers"
[ROCA]: https://en.wikipedia.org/wiki/ROCA_vulnerability "ROCA vulnerability"
[smartfacts]: https://smartfacts.cr.yp.to/smartfacts-20130916.pdf "D. J. Bernstein, Y.-A. Chang, C.-M. Cheng, L.-P. Chou, N. Heninger, T. Lange, N. van Someren, Factoring RSA keys from certified smart cards: Coppersmith in the wild, ASIACRYPT 2013"
[smartfactsEprint]: https://eprint.iacr.org/2013/599 "Cryptology ePrint Archive, Paper 2013/599"
