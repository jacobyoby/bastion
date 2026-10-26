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
"""Module containing Paranoid checks for RSA signatures."""

from typing import Optional
from absl import logging
import gmpy2 as gmpy
from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import base_check
from paranoid_crypto.lib import consts
from paranoid_crypto.lib import util

# DER encoding of the DigestInfo up to the hash value, per hash, from RFC 8017,
# Section 9.2, Note 1. The last byte is the length of the hash.
_DIGEST_INFO_PREFIXES = {
    paranoid_pb2.SignatureAlgorithm.RSA_WITH_MD5:
        bytes.fromhex("3020300c06082a864886f70d020505000410"),
    paranoid_pb2.SignatureAlgorithm.RSA_WITH_SHA1:
        bytes.fromhex("3021300906052b0e03021a05000414"),
    paranoid_pb2.SignatureAlgorithm.RSA_WITH_SHA224:
        bytes.fromhex("302d300d06096086480165030402040500041c"),
    paranoid_pb2.SignatureAlgorithm.RSA_WITH_SHA256:
        bytes.fromhex("3031300d060960864801650304020105000420"),
    paranoid_pb2.SignatureAlgorithm.RSA_WITH_SHA384:
        bytes.fromhex("3041300d060960864801650304020205000430"),
    paranoid_pb2.SignatureAlgorithm.RSA_WITH_SHA512:
        bytes.fromhex("3051300d060960864801650304020305000440"),
}


def Pkcs1v15EncodedMessage(algorithm: paranoid_pb2.SignatureAlgorithm,
                           message_hash: bytes, n: int) -> Optional[int]:
  """Returns the EMSA-PKCS1-v1_5 encoded message as an integer.

  This is EM = 0x00 || 0x01 || PS || 0x00 || T from RFC 8017, Section 9.2,
  where T is the DER-encoded DigestInfo of message_hash and PS is 0xff bytes
  filling EM to the byte length of n.

  Args:
    algorithm: a PKCS#1 v1.5 signature algorithm (RSA_WITH_<hash>).
    message_hash: the full hash of the message.
    n: the RSA modulus.

  Returns:
    EM as an integer, or None if the algorithm is not PKCS#1 v1.5 with a known
    hash, the hash has the wrong length, or n is too short to hold EM.
  """
  prefix = _DIGEST_INFO_PREFIXES.get(algorithm)
  if prefix is None or len(message_hash) != prefix[-1]:
    return None
  t = prefix + message_hash
  em_len = (n.bit_length() + 7) // 8
  if em_len < len(t) + 11:
    return None
  ps = b"\xff" * (em_len - len(t) - 3)
  return util.Bytes2Int(b"\x00\x01" + ps + b"\x00" + t)


class CheckRSASignatureFault(base_check.RSASignatureCheck):
  """Checks whether a faulty RSA signature leaks a prime factor of the key.

  An RSA signer that uses the Chinese Remainder Theorem computes the signature
  modulo p and modulo q separately. If a fault corrupts only one half, then
  s^e = m (mod q) but not (mod p), where m is the encoded message, and
  gcd(s^e - m, n) = q factors the key from that one signature (Lenstra's
  attack). Hardware accelerators and TLS offload engines have produced such
  signatures in the wild.

  The check needs the full message hash and supports the PKCS#1 v1.5
  algorithms RSA_WITH_MD5 to RSA_WITH_SHA512, whose encoding is deterministic.
  Other signatures, such as RSA-PSS, pass. A factor is attached only after it
  is confirmed to divide n, so the check has no false positives.
  """

  def __init__(self):
    super().__init__(paranoid_pb2.SeverityType.SEVERITY_CRITICAL)

  def Check(self, artifacts: list[paranoid_pb2.RSASignature]) -> bool:
    any_weak = False
    for sig in artifacts:
      test_result = self._CreateTestResult()
      n = gmpy.mpz(util.Bytes2Int(sig.issuer_key_info.n))
      e = gmpy.mpz(util.Bytes2Int(sig.issuer_key_info.e))
      s = gmpy.mpz(util.Bytes2Int(sig.rsa_sig_info.s))
      m = Pkcs1v15EncodedMessage(sig.rsa_sig_info.algorithm,
                                 sig.rsa_sig_info.message_hash, n)
      # A valid signature satisfies s^e = m (mod n), and 0 < s < n.
      if m is not None and 0 < s < n:
        p = gmpy.gcd(pow(s, e, n) - m, n)
        if 1 < p < n:
          factors = [p, n // p]
          logging.warning("Faulty signature leaks factors: %s\n%s", factors,
                          sig.rsa_sig_info)
          util.AttachFactors(sig.test_info, consts.INFO_NAME_N_FACTORS,
                             factors)
          any_weak = True
          test_result.result = True
      util.SetTestResult(sig.test_info, test_result)
    return any_weak
