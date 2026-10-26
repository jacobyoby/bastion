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
"""Tests for paranoid_crypto.lib.ssh_keys."""

import base64
import struct
from absl.testing import absltest
from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import ec_single_checks
from paranoid_crypto.lib import rsa_single_checks
from paranoid_crypto.lib import ssh_keys
from paranoid_crypto.lib import util

# Keys made by OpenSSH 10.5 ssh-keygen. The expected numbers come from openssl
# reading `ssh-keygen -e -m PKCS8` output, and the fingerprints from
# `ssh-keygen -l -E sha256`.
_RSA_LINE = (
    'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDPofVaHb5ga57mj/hsOAFpDnOziPoiuJl2'
    'jVm1Kwg9Vcmtr5W95PHmGYkxWWvYLyArlxN/SvfAZrXU2esT8C1xC19zfy/JGUrQOEAukd36'
    'Q0C0eZD+1UYQEI9jfrUdtcDvmaCqg9FsMtuMmO06sszgg4f0lhmSaBwZRbYgnbaI/Q== '
    'alice@example.com')
_RSA_N = int(
    'cfa1f55a1dbe606b9ee68ff86c3801690e73b388fa22b899768d59b52b083d55c9adaf95'
    'bde4f1e6198931596bd82f202b97137f4af7c066b5d4d9eb13f02d710b5f737f2fc9194a'
    'd038402e91ddfa4340b47990fed54610108f637eb51db5c0ef99a0aa83d16c32db8c98ed'
    '3ab2cce08387f4961992681c1945b6209db688fd', 16)
_RSA_FINGERPRINT = '1XLY44DZ9GIKaaFxNzSgTfYrxs6ZjSixSjlD5YJv5i0'

_EC256_LINE = (
    'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABB'
    'BPrpzL4J4RLJScVu7ff+7Ty244RHqLA7z+JrVLI0+5q0Jeg4RqWwqIR63kpoFuxia3e2rg9i'
    'RPmbasiZvtQ0+G4= ec256@example.com')
_EC256_X = 0xfae9ccbe09e112c949c56eedf7feed3cb6e38447a8b03bcfe26b54b234fb9ab4
_EC256_Y = 0x25e83846a5b0a8847ade4a6816ec626b77b6ae0f6244f99b6ac899bed434f86e
_EC256_FINGERPRINT = 'PbuQJPWnpD6u8P5hkPkuPmLzZPNGCml8xfpvlpk7AlE'

_EC384_LINE = (
    'ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABh'
    'BFvSMS8PCh991ph2Uhfx7oExrfnwYZaJvSFQuFn/cqVVtVsj6lDYcTjY2v/0PPNvxabOkrdi'
    'ArLMmiVEbZsqBXAsdAXSgz0PIZ09IuANzaGW8lH3qa20kea4zTUKc/bCyw== '
    'ec384@example.com')
_EC384_X = int(
    '5bd2312f0f0a1f7dd698765217f1ee8131adf9f0619689bd2150b859ff72a555b55b23ea'
    '50d87138d8dafff43cf36fc5', 16)
_EC384_Y = int(
    'a6ce92b76202b2cc9a25446d9b2a05702c7405d2833d0f219d3d22e00dcda196f251f7a9'
    'adb491e6b8cd350a73f6c2cb', 16)

_EC521_LINE = (
    'ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACF'
    'BADQfLfZrDsLXgZnR+olrTeQ/m8e2w27eMkmcwUNOoKq6m41p/JbHgh9Do/BNRZYW4c1psKP'
    'Rjd1NjEqWfel86Tt9ACXZGCsyLwWmFHd3K2qxpQeB0tqtZAHDVC1lnn8KF9B+cX7jqVv84jr'
    'fUg8UWsiLvv5+N7WKGwogamTuLhk7YSXHA== ec521@example.com')
_EC521_X = int(
    '00d07cb7d9ac3b0b5e066747ea25ad3790fe6f1edb0dbb78c92673050d3a82aaea6e35a7'
    'f25b1e087d0e8fc13516585b8735a6c28f46377536312a59f7a5f3a4edf4', 16)
_EC521_Y = int(
    '00976460acc8bc169851dddcadaac6941e074b6ab590070d50b59679fc285f41f9c5fb8e'
    'a56ff388eb7d483c516b222efbf9f8ded6286c2881a993b8b864ed84971c', 16)

_ED25519_LINE = ('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHloKvONHib1yGq35gkguzrP'
                 'HFEwhNnbQVKKoMRfJtQP ed@example.com')

# The point of _EC256_LINE as a FIDO security key (PROTOCOL.u2f), with
# application "ssh:". ssh-keygen -l accepts it as ECDSA-SK.
_SK_LINE = (
    'sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZA'
    'b3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBPrpzL4J4RLJScVu7ff+7Ty244RHqLA7z+Jr'
    'VLI0+5q0Jeg4RqWwqIR63kpoFuxia3e2rg9iRPmbasiZvtQ0+G4AAAAEc3NoOg== '
    'sk@example.com')
_SK_FINGERPRINT = '8ktic/lXhxo6Jv25bPUegxMmQvxAaur5Ri2pDRlA+WM'

# Weak keys encoded by the cryptography library: the CheckFermat key from
# examples/rsa_public_keys.py, and the P-256 key with private key 0x12345678.
_FERMAT_LINE = (
    'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzoTqAgjUdmwEXTsFxqdPHXmIUEJqfpCgZ'
    'xGctF4hrzWh+mkk1bQQO7HseO2ziNJbsiPPFWL/8aXMcf4tc0OSMIJrcUCse5w63vfbosPAP'
    'OIdIpd+SMb80OJtNAfZDM+sfOv1wtEF5nosF/JYzkvUBNN+sM4VLbMmZc/lLs1ffIpPMtDJI'
    'GBulsnXnrgjIzWu41Nw6EzjFD44g260SMe78v+j/5LJIHrgBE1c2c2HFWNbtvt/awNFfhY91'
    '2Grbxk6IzrEx9mvPCfzhtnUREoRcFh358Ob+KYOUV8oCpo4huC8enuEojkRT37yjOB+o0zXt'
    'JHKS1mAiWPVckQatSysf fermat')
_WEAK_EC_LINE = (
    'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABB'
    'BOQCRbfeCFwmBKpj8ugLcsyA+nxGiRYopCcbX/iOITHKr2U6kCROOuBYUd0rEpXUNpIFo4Gf'
    'G15pE9QuMV0W+OI= weak')


def _String(data: bytes) -> bytes:
  """Encodes data as an SSH string (RFC 4251, section 5)."""
  return struct.pack('>I', len(data)) + data


def _Line(key_type: str, blob: bytes) -> str:
  return key_type + ' ' + base64.b64encode(blob).decode()


def _Blob(line: str) -> bytes:
  return base64.b64decode(line.split()[1])


def _Fingerprint(sha256_b64: str) -> bytes:
  """Decodes the SHA256: fingerprint that ssh-keygen -l prints."""
  return base64.b64decode(sha256_b64 + '=')


def _P256Blob(point: bytes) -> bytes:
  return _String(b'ecdsa-sha2-nistp256') + _String(b'nistp256') + _String(point)


class SshKeysTest(absltest.TestCase):

  def testRSAKey(self):
    key = ssh_keys.ParseAuthorizedKeysLine(_RSA_LINE)
    self.assertIsInstance(key, paranoid_pb2.RSAKey)
    self.assertEqual(util.Bytes2Int(key.rsa_info.n), _RSA_N)
    self.assertEqual(util.Bytes2Int(key.rsa_info.e), 65537)
    self.assertEqual(key.origin_info.raw_data, _Blob(_RSA_LINE))
    self.assertEqual(key.origin_info.fingerprint,
                     _Fingerprint(_RSA_FINGERPRINT))

  def testECKeys(self):
    cases = (
        (_EC256_LINE, paranoid_pb2.CurveType.CURVE_SECP256R1, _EC256_X,
         _EC256_Y),
        (_EC384_LINE, paranoid_pb2.CurveType.CURVE_SECP384R1, _EC384_X,
         _EC384_Y),
        (_EC521_LINE, paranoid_pb2.CurveType.CURVE_SECP521R1, _EC521_X,
         _EC521_Y),
    )
    for line, curve_type, x, y in cases:
      with self.subTest(curve_type=curve_type):
        key = ssh_keys.ParseAuthorizedKeysLine(line)
        self.assertIsInstance(key, paranoid_pb2.ECKey)
        self.assertEqual(key.ec_info.curve_type, curve_type)
        self.assertEqual(util.Bytes2Int(key.ec_info.x), x)
        self.assertEqual(util.Bytes2Int(key.ec_info.y), y)
        self.assertEqual(key.origin_info.raw_data, _Blob(line))
    key = ssh_keys.ParseAuthorizedKeysLine(_EC256_LINE)
    self.assertEqual(key.origin_info.fingerprint,
                     _Fingerprint(_EC256_FINGERPRINT))

  def testSecurityKey(self):
    key = ssh_keys.ParseAuthorizedKeysLine(_SK_LINE)
    self.assertEqual(key.ec_info,
                     ssh_keys.ParseAuthorizedKeysLine(_EC256_LINE).ec_info)
    self.assertEqual(key.origin_info.fingerprint,
                     _Fingerprint(_SK_FINGERPRINT))

  def testAuthorizedKeysOptions(self):
    expected = ssh_keys.ParseAuthorizedKeysLine(_RSA_LINE)
    # Options may hold blanks and escaped quotes inside double quotes.
    # The last options split at their quoted blank into 'command="a' and a
    # blob that names it as its key type; they are still options.
    for options in ('no-pty', 'command="echo \\"a b\\"",no-pty',
                    'from="192.0.2.0/24, 198.51.100.1"\t', ' \tno-pty',
                    'command="a AAAACmNvbW1hbmQ9ImEh "'):
      with self.subTest(options=options):
        self.assertEqual(
            ssh_keys.ParseAuthorizedKeysLine(options + ' ' + _RSA_LINE),
            expected)
    with self.assertRaisesRegex(ValueError, 'unterminated quote'):
      ssh_keys.ParseAuthorizedKeysLine('command="echo ' + _RSA_LINE)
    with self.assertRaisesRegex(ValueError, 'no SSH key'):
      ssh_keys.ParseAuthorizedKeysLine('no-pty ssh-rsa ' +
                                       _EC256_LINE.split()[1])

  def testKnownHostsLine(self):
    expected = ssh_keys.ParseAuthorizedKeysLine(_EC256_LINE)
    for hosts in ('example.com,192.0.2.1',
                  '|1|JfKTdBh7rNbXkVAQCRp4OQoPfmI=|USECr3SWf1JUPsms5AqfD5QfxkM=',
                  '@cert-authority *.example.com',
                  '@revoked [example.com]:2222', '\t example.com'):
      with self.subTest(hosts=hosts):
        self.assertEqual(
            ssh_keys.ParseKnownHostsLine(hosts + ' ' + _EC256_LINE), expected)
    # Tabs separate fields too.
    self.assertEqual(
        ssh_keys.ParseKnownHostsLine('example.com\t' +
                                     _EC256_LINE.replace(' ', '\t')), expected)
    for markers in ('@trusted', '@cert-authority @revoked'):
      with self.subTest(markers=markers):
        with self.assertRaisesRegex(ValueError, 'marker'):
          ssh_keys.ParseKnownHostsLine(markers + ' example.com ' +
                                       _EC256_LINE)
    # A known_hosts line starts with host names, so a bare key is malformed.
    with self.assertRaises(ValueError):
      ssh_keys.ParseKnownHostsLine(_EC256_LINE)

  def testUnsupportedKeyType(self):
    for line in (_ED25519_LINE, 'no-pty ' + _ED25519_LINE):
      with self.subTest(line=line):
        with self.assertRaises(ssh_keys.UnsupportedKeyTypeError) as cm:
          ssh_keys.ParseAuthorizedKeysLine(line)
        self.assertEqual(cm.exception.key_type, 'ssh-ed25519')
    with self.assertRaises(ssh_keys.UnsupportedKeyTypeError):
      ssh_keys.ParseKnownHostsLine('example.com ' + _ED25519_LINE)

  def testMalformedKeys(self):
    rsa_blob = _Blob(_RSA_LINE)
    x = _EC256_X.to_bytes(32, 'big')
    y = _EC256_Y.to_bytes(32, 'big')
    cases = (
        ('ssh-rsa ' + _EC256_LINE.split()[1], 'does not match'),
        (_Line('ecdsa-sha2-nistp256',
               _String(b'ecdsa-sha2-nistp256') + _String(b'nistp384') +
               _String(b'\x04' + x + y)), 'curve'),
        ('ssh-rsa AAAA*AAA', 'base64'),
        ('ssh-rsa', 'base64'),
        (_Line('ssh-rsa', rsa_blob[:-1]), 'truncated'),
        (_Line('ssh-rsa', rsa_blob + b'\x00'), 'trailing'),
        (_Line('ssh-rsa',
               _String(b'ssh-rsa') + _String(b'\x81') +
               _String(util.Int2Bytes(_RSA_N))), 'negative'),
        (_Line('ecdsa-sha2-nistp256', _P256Blob(b'\x02' + x)), 'uncompressed'),
        (_Line('ecdsa-sha2-nistp256', _P256Blob(b'\x04' + x + y[1:])),
         'uncompressed'),
        (_Line('ecdsa-sha2-nistp256', _P256Blob(b'\x06' + x + y)),
         'uncompressed'),
        # A security key without its application string.
        (_Line('sk-ecdsa-sha2-nistp256@openssh.com',
               _String(b'sk-ecdsa-sha2-nistp256@openssh.com') +
               _String(b'nistp256') + _String(b'\x04' + x + y)), 'truncated'),
        (_Line('ssh-rsa', _String(b'ssh-rsa') + b'\x00\x00'), 'truncated'),
    )
    for key, message in cases:
      with self.subTest(message=message, key=key[:40]):
        with self.assertRaisesRegex(ValueError, message):
          ssh_keys.ParseKnownHostsLine('example.com ' + key)

  def testLineWithoutKey(self):
    for line in ('', '# comment', '   '):
      with self.subTest(line=line):
        with self.assertRaises(ValueError):
          ssh_keys.ParseAuthorizedKeysLine(line)
        with self.assertRaises(ValueError):
          ssh_keys.ParseKnownHostsLine(line)

  def testParseAuthorizedKeys(self):
    text = '\n'.join((
        '# keys for alice',
        '',
        _RSA_LINE,
        'no-pty ' + _ED25519_LINE,
        '  ' + _SK_LINE,
        ' '.join(_EC384_LINE.split()[:2]) + '\r',
        '\t# end',
    )) + '\n'
    keys = ssh_keys.ParseAuthorizedKeys(text)
    self.assertEqual(keys.rsa_keys,
                     [ssh_keys.ParseAuthorizedKeysLine(_RSA_LINE)])
    self.assertEqual(keys.ec_keys, [
        ssh_keys.ParseAuthorizedKeysLine(_SK_LINE),
        ssh_keys.ParseAuthorizedKeysLine(_EC384_LINE)
    ])
    self.assertEqual(keys.unsupported,
                     [ssh_keys.UnsupportedKey(4, 'ssh-ed25519')])

  def testParseKnownHosts(self):
    text = ('example.com ' + _EC521_LINE + '\n' + 'example.com ' +
            _ED25519_LINE + '\n' + '@revoked example.com ' + _RSA_LINE)
    keys = ssh_keys.ParseKnownHosts(text)
    self.assertEqual(keys.rsa_keys,
                     [ssh_keys.ParseAuthorizedKeysLine(_RSA_LINE)])
    self.assertEqual(keys.ec_keys,
                     [ssh_keys.ParseAuthorizedKeysLine(_EC521_LINE)])
    self.assertEqual(keys.unsupported,
                     [ssh_keys.UnsupportedKey(2, 'ssh-ed25519')])

  def testParseFileNamesBadLine(self):
    text = _RSA_LINE + '\n# comment\nssh-rsa AAAA*AAA\n'
    with self.assertRaisesRegex(ValueError, 'line 3'):
      ssh_keys.ParseAuthorizedKeys(text)
    with self.assertRaisesRegex(ValueError, 'line 1'):
      ssh_keys.ParseKnownHosts(text)

  def testWeakKeysAreFound(self):
    rsa_key = ssh_keys.ParseAuthorizedKeysLine(_FERMAT_LINE)
    self.assertTrue(rsa_single_checks.CheckFermat().Check([rsa_key]))
    ec_key = ssh_keys.ParseAuthorizedKeysLine(_WEAK_EC_LINE)
    self.assertTrue(ec_single_checks.CheckWeakECPrivateKey().Check([ec_key]))

  def testKeepsKeysOpenSSHRejects(self):
    # OpenSSH rejects RSA moduli under 1024 bits; the parser keeps them.
    n = 2**510 + 1
    key = ssh_keys.ParseAuthorizedKeysLine(
        _Line(
            'ssh-rsa',
            _String(b'ssh-rsa') + _String(b'\x03') +
            _String(util.Int2Bytes(n))))
    self.assertEqual(util.Bytes2Int(key.rsa_info.n), n)
    self.assertEqual(util.Bytes2Int(key.rsa_info.e), 3)
    # OpenSSH rejects this point; the parser keeps it for CheckValidECKey.
    point = b'\x04' + (1).to_bytes(32, 'big') * 2
    key = ssh_keys.ParseAuthorizedKeysLine(
        _Line('ecdsa-sha2-nistp256', _P256Blob(point)))
    self.assertEqual(util.Bytes2Int(key.ec_info.x), 1)
    self.assertEqual(util.Bytes2Int(key.ec_info.y), 1)
    self.assertTrue(ec_single_checks.CheckValidECKey().Check([key]))


if __name__ == '__main__':
  absltest.main()
