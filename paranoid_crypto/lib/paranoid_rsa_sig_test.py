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
"""RSA signature Tests for paranoid_crypto.lib.paranoid."""

import hashlib
from absl.testing import absltest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import consts
from paranoid_crypto.lib import paranoid
from paranoid_crypto.lib import paranoid_base_test
from paranoid_crypto.lib import util
from paranoid_crypto.lib.paranoid import rsa_sig_checks

# (SignatureAlgorithm, cryptography hash, hashlib name) per PKCS#1 v1.5 hash.
_ALGORITHMS = (
    (paranoid_pb2.SignatureAlgorithm.RSA_WITH_MD5, hashes.MD5(), 'md5'),
    (paranoid_pb2.SignatureAlgorithm.RSA_WITH_SHA1, hashes.SHA1(), 'sha1'),
    (paranoid_pb2.SignatureAlgorithm.RSA_WITH_SHA224, hashes.SHA224(),
     'sha224'),
    (paranoid_pb2.SignatureAlgorithm.RSA_WITH_SHA256, hashes.SHA256(),
     'sha256'),
    (paranoid_pb2.SignatureAlgorithm.RSA_WITH_SHA384, hashes.SHA384(),
     'sha384'),
    (paranoid_pb2.SignatureAlgorithm.RSA_WITH_SHA512, hashes.SHA512(),
     'sha512'),
)


def _Signature(n: int, e: int, s: int, algorithm: paranoid_pb2.SignatureAlgorithm,
               message_hash: bytes) -> paranoid_pb2.RSASignature:
  sig = paranoid_pb2.RSASignature()
  sig.rsa_sig_info.s = util.Int2Bytes(s)
  sig.rsa_sig_info.algorithm = algorithm
  sig.rsa_sig_info.message_hash = message_hash
  sig.issuer_key_info.n = util.Int2Bytes(n)
  sig.issuer_key_info.e = util.Int2Bytes(e)
  return sig


class ParanoidRSASignatureTest(paranoid_base_test.ParanoidBaseTest):

  @classmethod
  def setUpClass(cls):
    super().setUpClass()
    # Signatures come from the cryptography library, so the tests do not depend
    # on Bastion's own PKCS#1 v1.5 encoding.
    cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = cls.key.private_numbers()
    cls.p, cls.q = numbers.p, numbers.q
    cls.n, cls.e = numbers.public_numbers.n, numbers.public_numbers.e

  def _Sign(self, hash_alg: hashes.HashAlgorithm, hash_name: str,
            message: bytes) -> tuple[int, bytes]:
    s = int.from_bytes(
        self.key.sign(message, padding.PKCS1v15(), hash_alg), 'big')
    return s, hashlib.new(hash_name, message).digest()

  def _Fault(self, s: int) -> int:
    """Returns s with a CRT fault: still correct mod p, wrong mod q."""
    s_q = (s + 1) % self.q
    # The s' with s' = s (mod p) and s' = s_q (mod q).
    return (s + self.p * ((s_q - s) * pow(self.p, -1, self.q) % self.q)) % self.n

  def testCheckRSASignatureFault(self):
    # Every hash needs its exact DigestInfo encoding: with a wrong encoding,
    # the gcd with n is 1 and the fault goes unnoticed.
    for algorithm, hash_alg, hash_name in _ALGORITHMS:
      with self.subTest(hash_name):
        message = b'Bastion signature fault ' + hash_name.encode()
        s, digest = self._Sign(hash_alg, hash_name, message)
        sig = _Signature(self.n, self.e, self._Fault(s), algorithm, digest)
        check = rsa_sig_checks.CheckRSASignatureFault()
        self.assertTrue(check.Check([sig]))
        self.assertResults([sig], check.check_name, True)
        factors = util.GetAttachedFactors(sig.test_info,
                                          consts.INFO_NAME_N_FACTORS)
        self.assertEqual(factors, {self.p, self.q})

  def testCheckRSASignatureFaultValidSignatures(self):
    sigs = []
    for algorithm, hash_alg, hash_name in _ALGORITHMS:
      s, digest = self._Sign(hash_alg, hash_name, b'valid ' + hash_name.encode())
      sigs.append(_Signature(self.n, self.e, s, algorithm, digest))
    check = rsa_sig_checks.CheckRSASignatureFault()
    self.assertFalse(check.Check(sigs))
    self.assertResults(sigs, check.check_name, False)

  def testCheckRSASignatureFaultMalformedInput(self):
    # None of these can leak a factor, and none may abort the batch.
    s, digest = self._Sign(hashes.SHA256(), 'sha256', b'malformed')
    sha256 = paranoid_pb2.SignatureAlgorithm.RSA_WITH_SHA256
    sigs = [
        _Signature(self.n, self.e, 0, sha256, digest),
        _Signature(self.n, self.e, self.n + self._Fault(s), sha256, digest),
        _Signature(0, self.e, self._Fault(s), sha256, digest),
        _Signature(self.n, self.e, self._Fault(s), sha256, digest[:-1]),
        _Signature(self.n, self.e, self._Fault(s),
                   paranoid_pb2.SignatureAlgorithm.RSA_PSS_SHA256, digest),
        _Signature(3233, 17, 5, sha256, digest),  # Too small to encode.
    ]
    check = rsa_sig_checks.CheckRSASignatureFault()
    self.assertFalse(check.Check(sigs))
    self.assertResults(sigs, check.check_name, False)

  def testCheckAllRSASigs(self):
    s, digest = self._Sign(hashes.SHA256(), 'sha256', b'all checks')
    sha256 = paranoid_pb2.SignatureAlgorithm.RSA_WITH_SHA256
    good = _Signature(self.n, self.e, s, sha256, digest)
    self.assertFalse(paranoid.CheckAllRSASigs([good]))
    for check_name in paranoid.GetRSASignatureChecks():
      self.assertResults([good], check_name, False)
    bad = _Signature(self.n, self.e, self._Fault(s), sha256, digest)
    self.assertTrue(paranoid.CheckAllRSASigs([bad]))
    self.assertFalse(paranoid.CheckAllRSASigs([]))


if __name__ == '__main__':
  absltest.main()
