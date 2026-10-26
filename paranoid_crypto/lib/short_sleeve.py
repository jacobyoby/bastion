# Copyright 2026 Jacob Durham
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Factors "short-sleeve" RSA moduli by factoring polynomials.

A short-sleeve prime has a block of zero bits in every limb of its big-integer
representation, because its generator filled each w-bit limb with fewer than w
random bits. Written in base 2^w, such a prime is a polynomial f_p(x) with
small coefficients, evaluated at x = 2^w. If both primes are short-sleeve, the
digits of n are the coefficients of f_p(x) * f_q(x), and factoring that
polynomial over the integers recovers p and q. The limb windows of p and q need
not line up with the limbs of n, so the digits of n * 2^k are tried for every
shift k < w: some shift makes the product of the aligned shifted primes.
See https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/

Factoring polynomials costs far more than the other RSA checks, so a cheap
pre-filter first rejects keys that cannot be short-sleeve. The thresholds and
limb masks follow the rsapoly detector of badkeys, copyright (c) Hanno Böck,
MIT License (https://github.com/badkeys/badkeys).
"""

import itertools
import math
from typing import Optional
import gmpy2 as gmpy
import sympy

# (limb width w, bits that are zero in every limb of n). The 128-bit pattern was
# seen in certificates of Yahoo, Verizon and NetApp devices; the 32-bit one
# comes from CompleteFTP 10.0.0 to 12.0.0, which put one random byte into each
# 32-bit limb.
_PATTERNS = ((128, 0xffffffffffff0000), (32, 0x03ff00000))

# Keys with this share of one bits or more, in n or in its lower half, are not
# short-sleeve. A sparse upper half with a dense lower half is typical of keys
# with chosen ("vanity") leading bits, which are not weak.
_MAX_ONE_BITS_PERCENT = 40

# Smaller moduli cannot hold enough limbs for the pattern to be meaningful.
_MIN_BITS = 500

# The polynomial of n can split into more than two irreducible factors, and
# then p is the evaluation of a product of some of them. All subsets are tried
# up to this many factors; beyond it, only single factors are tried.
_MAX_FACTORS_FOR_SUBSETS = 16


def _OneBitsPercent(x: int) -> int:
  return gmpy.popcount(x) * 100 // x.bit_length()


def _ZeroWindowInEveryLimb(n: int, width: int, mask: int) -> bool:
  """Returns whether mask is zero in every w-bit limb of n but the lowest.

  The lowest limb is skipped because a next-prime search can carry into it. An
  all-zero limb rejects n: such a sparse n is not this pattern.

  Args:
    n: the RSA modulus
    width: the limb width w in bits
    mask: the bits of each limb that must be zero
  """
  limb_mask = (1 << width) - 1
  rest = n >> width
  while rest:
    limb = rest & limb_mask
    if limb == 0 or limb & mask:
      return False
    rest >>= width
  return True


def ShortSleeveWidths(n: int) -> list[int]:
  """Returns the limb widths for which n may be a short-sleeve modulus.

  This is the cheap pre-filter: an empty result means FactorShortSleeve need
  not be tried.

  Args:
    n: the RSA modulus
  """
  if n.bit_length() < _MIN_BITS:
    return []
  if _OneBitsPercent(n) >= _MAX_ONE_BITS_PERCENT:
    return []
  lower = n % (1 << (n.bit_length() // 2))
  if lower == 0 or _OneBitsPercent(lower) >= _MAX_ONE_BITS_PERCENT:
    return []
  return [w for w, mask in _PATTERNS if _ZeroWindowInEveryLimb(n, w, mask)]


def _Digits(a: int, width: int) -> list[int]:
  """Returns the base-2^width digits of a, most significant first."""
  digits = []
  while a:
    digits.append(a & ((1 << width) - 1))
    a >>= width
  return digits[::-1]


def _FactorFromValues(values: list[int], n: int) -> Optional[int]:
  """Returns a non-trivial factor of n from products of the values, if any."""
  max_size = len(values) // 2 if len(values) <= _MAX_FACTORS_FOR_SUBSETS else 1
  for size in range(1, max_size + 1):
    for subset in itertools.combinations(values, size):
      p = gmpy.gcd(math.prod(subset), n)
      if 1 < p < n:
        return p
  return None


def FactorShortSleeve(n: int, width: int) -> Optional[list[int]]:
  """Tries to factor n as a product of short-sleeve primes with w-bit limbs.

  Args:
    n: the RSA modulus
    width: the limb width w in bits

  Returns:
    the factors [p, n // p], or None if no factor was found.
  """
  n = int(n)
  x = sympy.Symbol("x")
  base = 1 << width
  for shift in range(width):
    poly = sympy.Poly(_Digits(n << shift, width), x)
    _, factors = poly.factor_list()
    values = []
    for factor, multiplicity in factors:
      values += [abs(int(factor.eval(base)))] * multiplicity
    p = _FactorFromValues(values, n)
    if p is not None:
      return [p, n // p]
  return None
