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
"""Offline tests for tlscheck.

Certificates are generated here. Nothing in this module is a real CA key.
A live network check is skipped unless TLSCHECK_LIVE=1.
"""

import datetime
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer

import certifi

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ObjectIdentifier

from tlscheck.capture import capture_tls
from tlscheck.certs import hostname_matches
from tlscheck.certs import spki_sha256
from tlscheck.cli import main
from tlscheck.fetch import FetchResponse
from tlscheck.fetch import fetch_url
from tlscheck.path import TrustStore
from tlscheck.path import mozilla_trust_store
from tlscheck.report import render_json
from tlscheck.report import render_text
from tlscheck.run import run_check

_WHEN = datetime.datetime(2024, 6, 15, tzinfo=datetime.timezone.utc)
_ROOT_NOT_BEFORE = datetime.datetime(2018, 1, 1, tzinfo=datetime.timezone.utc)
_SERIAL = 1000
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_SHA256_RSA_OID = bytes.fromhex('2a864886f70d01010b')
_SHA1_RSA_OID = bytes.fromhex('2a864886f70d010105')


def _next_serial() -> int:
  global _SERIAL
  _SERIAL += 1
  return _SERIAL


def _cn(text: str) -> x509.Name:
  return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text)])


def _rsa(bits: int = 2048):
  return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _key_usage(is_ca: bool) -> x509.KeyUsage:
  if is_ca:
    return x509.KeyUsage(
        digital_signature=False, content_commitment=False,
        key_encipherment=False, data_encipherment=False, key_agreement=False,
        key_cert_sign=True, crl_sign=True, encipher_only=False,
        decipher_only=False)
  return x509.KeyUsage(
      digital_signature=True, content_commitment=False, key_encipherment=True,
      data_encipherment=False, key_agreement=False, key_cert_sign=False,
      crl_sign=False, encipher_only=False, decipher_only=False)


def make_cert(subject: str, issuer_name: str, subject_key, issuer_key, *,
              is_ca: bool, days: int = 90, not_before=None, san=None,
              eku=None, extra=None):
  """Build one certificate. issuer_name is the issuer CN."""
  not_before = not_before or datetime.datetime(
      2024, 6, 1, tzinfo=datetime.timezone.utc)
  not_after = not_before + datetime.timedelta(days=days)
  builder = x509.CertificateBuilder()
  builder = builder.subject_name(_cn(subject))
  builder = builder.issuer_name(_cn(issuer_name))
  builder = builder.public_key(subject_key.public_key())
  builder = builder.serial_number(_next_serial())
  builder = builder.not_valid_before(not_before)
  builder = builder.not_valid_after(not_after)
  builder = builder.add_extension(
      x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
      critical=False)
  builder = builder.add_extension(
      x509.AuthorityKeyIdentifier.from_issuer_public_key(
          issuer_key.public_key()),
      critical=False)
  builder = builder.add_extension(
      x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
  builder = builder.add_extension(_key_usage(is_ca), critical=True)
  if san is not None:
    builder = builder.add_extension(
        x509.SubjectAlternativeName(san), critical=False)
  if eku is not None:
    builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
  if extra:
    for value, critical in extra:
      builder = builder.add_extension(value, critical=critical)
  return builder.sign(issuer_key, hashes.SHA256())


def _der_len(length: int) -> bytes:
  if length < 0x80:
    return bytes([length])
  encoded = length.to_bytes((length.bit_length() + 7) // 8, 'big')
  return bytes([0x80 | len(encoded)]) + encoded


def _der_tlv(tag: int, body: bytes) -> bytes:
  return bytes([tag]) + _der_len(len(body)) + body


def _parse_tlv(buf: bytes, index: int = 0):
  tag = buf[index]
  index += 1
  length = buf[index]
  index += 1
  if length & 0x80:
    count = length & 0x7f
    length = int.from_bytes(buf[index:index + count], 'big')
    index += count
  return tag, index, index + length


def _split_sequence(buf: bytes) -> list:
  _, start, end = _parse_tlv(buf, 0)
  items = []
  index = start
  while index < end:
    _, value_start, value_end = _parse_tlv(buf, index)
    items.append(buf[index:value_end])
    index = value_end
  return items


def _sha1_with_rsa_algid() -> bytes:
  oid = _der_tlv(0x06, _SHA1_RSA_OID)
  return _der_tlv(0x30, oid + b'\x05\x00')


def resign_sha1(cert: x509.Certificate, issuer_key) -> x509.Certificate:
  """Re-sign a certificate with sha1WithRSAEncryption.

  CertificateBuilder refuses SHA-1. The TBS is rewritten and signed with
  the issuer key's SHA-1 PKCS#1 operation, which cryptography still exposes.
  """
  der = cert.public_bytes(serialization.Encoding.DER)
  tbs, _, _ = _split_sequence(der)
  new_alg = _sha1_with_rsa_algid()
  replaced = False
  items = []
  for item in _split_sequence(tbs):
    if _SHA256_RSA_OID in item and item[0] == 0x30:
      items.append(new_alg)
      replaced = True
    else:
      items.append(item)
  if not replaced:
    raise AssertionError('SHA-256 algorithm identifier was not found')
  new_tbs = _der_tlv(0x30, b''.join(items))
  signature = issuer_key.sign(new_tbs, padding.PKCS1v15(), hashes.SHA1())
  signature_bits = _der_tlv(0x03, bytes([0]) + signature)
  new_der = _der_tlv(0x30, new_tbs + new_alg + signature_bits)
  return x509.load_der_x509_certificate(new_der)


def _ocsp(leaf, issuer, issuer_key, when, *, status=None, this_update=None,
          next_update=None, signer_key=None, signer_cert=None,
          revocation_time=None):
  status = status or ocsp.OCSPCertStatus.GOOD
  this_update = this_update or (when - datetime.timedelta(hours=1))
  next_update = next_update or (when + datetime.timedelta(days=1))
  reason = None
  if status is ocsp.OCSPCertStatus.REVOKED:
    revocation_time = revocation_time or (when - datetime.timedelta(hours=2))
    reason = x509.ReasonFlags.key_compromise
  builder = ocsp.OCSPResponseBuilder()
  builder = builder.add_response(
      leaf, issuer, hashes.SHA256(), status, this_update, next_update,
      revocation_time, reason)
  responder = signer_cert or issuer
  builder = builder.responder_id(ocsp.OCSPResponderEncoding.HASH, responder)
  if signer_cert is not None:
    builder = builder.certificates([signer_cert])
  key = signer_key or issuer_key
  response = builder.sign(key, hashes.SHA256())
  return response.public_bytes(serialization.Encoding.DER)


def _pem(*certs) -> bytes:
  chunks = []
  for cert in certs:
    chunks.append(cert.public_bytes(serialization.Encoding.PEM))
  return b''.join(chunks)


class TlscheckTest(unittest.TestCase):
  """Required cases, plus the profile rules the path library does not enforce."""

  @classmethod
  def setUpClass(cls):
    cls.root_key = _rsa()
    cls.int_key = _rsa()
    cls.leaf_key = _rsa()
    cls.root = make_cert(
        'Test Root', 'Test Root', cls.root_key, cls.root_key, is_ca=True,
        days=4000, not_before=_ROOT_NOT_BEFORE)
    cls.intermediate = make_cert(
        'Test Intermediate', 'Test Root', cls.int_key, cls.root_key,
        is_ca=True, days=4000, not_before=_ROOT_NOT_BEFORE)
    cls.leaf = make_cert(
        'example.com', 'Test Intermediate', cls.leaf_key, cls.int_key,
        is_ca=False,
        san=[x509.DNSName('example.com')],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    cls.trust = TrustStore([cls.root], 'test-store')

  def check(self, certificates, **kwargs):
    defaults = {
        'host': 'example.com',
        'trust': self.trust,
        'when': _WHEN,
        'fetcher': self._unexpected_fetch,
    }
    defaults.update(kwargs)
    return run_check(certificates, **defaults)

  def _unexpected_fetch(self, *args, **kwargs):
    raise AssertionError(f'unexpected fetch {args} {kwargs}')

  def test_good_chain(self):
    report = self.check([self.leaf, self.intermediate])
    self.assertEqual(report.exit_code, 0)
    self.assertEqual(report.check('presented').status, 'pass')
    self.assertEqual(report.check('fetched').status, 'pass')
    self.assertEqual(report.check('eku').status, 'pass')
    self.assertEqual(report.check('signature').status, 'pass')
    self.assertEqual(report.check('public_key').status, 'pass')
    self.assertEqual(report.check('validity').status, 'pass')
    self.assertEqual(report.check('lifetime').status, 'pass')
    self.assertEqual(report.check('hostname').status, 'pass')
    self.assertEqual(report.check('revocation').status, 'skipped')
    self.assertEqual(report.check('pin').status, 'skipped')
    self.assertEqual(report.bundle_id, 'test-store')
    subjects = [cert.subject.rfc4514_string() for cert in
                report.presented_path.chain]
    self.assertEqual(
        subjects,
        ['CN=example.com', 'CN=Test Intermediate', 'CN=Test Root'])

  def test_server_sent_root_is_not_required(self):
    report = self.check([self.leaf, self.intermediate, self.root])
    self.assertEqual(report.exit_code, 0)
    self.assertEqual(report.check('presented').status, 'pass')

  def test_expired_leaf(self):
    leaf = make_cert(
        'example.com', 'Test Intermediate', self.leaf_key, self.int_key,
        is_ca=False, not_before=datetime.datetime(
            2024, 1, 1, tzinfo=datetime.timezone.utc),
        days=30,
        san=[x509.DNSName('example.com')],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    report = self.check([leaf, self.intermediate])
    self.assertEqual(report.check('validity').status, 'fail')
    self.assertEqual(report.exit_code, 1)

  def test_not_yet_valid_leaf(self):
    leaf = make_cert(
        'example.com', 'Test Intermediate', self.leaf_key, self.int_key,
        is_ca=False, not_before=datetime.datetime(
            2024, 7, 1, tzinfo=datetime.timezone.utc),
        days=30,
        san=[x509.DNSName('example.com')],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    report = self.check([leaf, self.intermediate])
    self.assertEqual(report.check('validity').status, 'fail')
    self.assertIn('not yet valid', report.check('validity').reason)
    self.assertEqual(report.exit_code, 1)

  def test_wrong_hostname(self):
    report = self.check([self.leaf, self.intermediate], name='wrong.test')
    self.assertEqual(report.check('hostname').status, 'fail')
    self.assertEqual(report.check('presented').status, 'pass')
    self.assertEqual(report.exit_code, 1)

  def test_no_san_common_name_fails_hostname(self):
    leaf = make_cert(
        'example.com', 'Test Intermediate', self.leaf_key, self.int_key,
        is_ca=False, eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    report = self.check([leaf, self.intermediate], name='example.com')
    self.assertEqual(report.check('hostname').status, 'fail')
    self.assertIn('commonName', report.check('hostname').reason)
    self.assertEqual(report.exit_code, 1)

  def test_missing_intermediate_fails_presented_until_fetched(self):
    url = 'http://aia.test/intermediate.cer'
    aia = x509.AuthorityInformationAccess([
        x509.AccessDescription(
            AuthorityInformationAccessOID.CA_ISSUERS,
            x509.UniformResourceIdentifier(url)),
    ])
    leaf = make_cert(
        'example.com', 'Test Intermediate', self.leaf_key, self.int_key,
        is_ca=False,
        san=[x509.DNSName('example.com')],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
        extra=[(aia, False)])
    def fetcher(fetch_url, method='GET', body=None, content_type=None):
      del body, content_type
      self.assertEqual(fetch_url, url)
      self.assertEqual(method, 'GET')
      return FetchResponse(
          body=self.intermediate.public_bytes(serialization.Encoding.DER))

    report = self.check([leaf], fetcher=fetcher)
    self.assertEqual(report.check('presented').status, 'fail')
    self.assertEqual(report.check('fetched').status, 'pass')
    self.assertEqual(report.exit_code, 1)
    sources = [
        item['source'] for item in report.to_dict()['chains']['fetched']
        ['certificates']
    ]
    self.assertIn('retrieved', sources)
    self.assertIn('presented', sources)

    allowed = self.check([leaf], fetcher=fetcher, allow_fetched=True)
    self.assertEqual(allowed.exit_code, 0)
    self.assertEqual(allowed.check('fetched').status, 'pass')

  def test_sha1_signature_fails_public_profile(self):
    leaf = resign_sha1(self.leaf, self.int_key)
    self.assertEqual(leaf.signature_hash_algorithm.name, 'sha1')
    report = self.check([leaf, self.intermediate])
    self.assertEqual(report.check('signature').status, 'fail')
    self.assertEqual(report.exit_code, 1)

  def test_rsa_1024_fails_public_profile(self):
    small = _rsa(1024)
    leaf = make_cert(
        'example.com', 'Test Intermediate', small, self.int_key, is_ca=False,
        san=[x509.DNSName('example.com')],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    report = self.check([leaf, self.intermediate])
    self.assertEqual(report.check('public_key').status, 'fail')
    self.assertIn('1024', report.check('public_key').reason)
    self.assertEqual(report.check('presented').status, 'pass')
    self.assertEqual(report.exit_code, 1)

  def test_secp256k1_fails_public_profile(self):
    key = ec.generate_private_key(ec.SECP256K1())
    leaf = make_cert(
        'example.com', 'Test Intermediate', key, self.int_key, is_ca=False,
        san=[x509.DNSName('example.com')],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    report = self.check([leaf, self.intermediate])
    self.assertEqual(report.check('public_key').status, 'fail')
    self.assertEqual(report.check('presented').status, 'pass')

  def test_p256_is_accepted(self):
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = make_cert(
        'example.com', 'Test Intermediate', key, self.int_key, is_ca=False,
        san=[x509.DNSName('example.com')],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    report = self.check([leaf, self.intermediate])
    self.assertEqual(report.exit_code, 0)

  def test_must_staple_without_staple_fails(self):
    feature = x509.TLSFeature([x509.TLSFeatureType.status_request])
    leaf = make_cert(
        'example.com', 'Test Intermediate', self.leaf_key, self.int_key,
        is_ca=False,
        san=[x509.DNSName('example.com')],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
        extra=[(feature, False)])
    report = self.check([leaf, self.intermediate])
    self.assertEqual(report.check('revocation').status, 'fail')
    self.assertIn('must-staple', report.check('revocation').reason)
    self.assertEqual(report.exit_code, 1)
    disabled = self.check([leaf, self.intermediate], ocsp_mode='off')
    self.assertEqual(disabled.check('revocation').status, 'skipped')

  def test_good_staple_passes_and_bad_staple_fails(self):
    good = _ocsp(self.leaf, self.intermediate, self.int_key, _WHEN)
    report = self.check(
        [self.leaf, self.intermediate], staple=good)
    self.assertEqual(report.check('revocation').status, 'pass')
    self.assertEqual(report.exit_code, 0)

    bad = bytearray(good)
    bad[-1] ^= 0xff
    forged = self.check(
        [self.leaf, self.intermediate], staple=bytes(bad))
    self.assertEqual(forged.check('revocation').status, 'fail')
    self.assertEqual(forged.exit_code, 1)

    expired = _ocsp(
        self.leaf, self.intermediate, self.int_key, _WHEN,
        next_update=_WHEN - datetime.timedelta(hours=1))
    stale = self.check([self.leaf, self.intermediate], staple=expired)
    self.assertEqual(stale.check('revocation').status, 'fail')

    revoked = _ocsp(
        self.leaf, self.intermediate, self.int_key, _WHEN,
        status=ocsp.OCSPCertStatus.REVOKED)
    denied = self.check([self.leaf, self.intermediate], staple=revoked)
    self.assertEqual(denied.check('revocation').status, 'fail')

  def test_delegated_ocsp_responder(self):
    responder_key = _rsa()
    responder = make_cert(
        'OCSP Responder', 'Test Intermediate', responder_key, self.int_key,
        is_ca=False, eku=[ExtendedKeyUsageOID.OCSP_SIGNING])
    staple = _ocsp(
        self.leaf, self.intermediate, self.int_key, _WHEN,
        signer_key=responder_key, signer_cert=responder)
    report = self.check([self.leaf, self.intermediate], staple=staple)
    self.assertEqual(report.check('revocation').status, 'pass',
                     report.check('revocation').reason)

  def test_unanswered_ocsp_fetch_is_skipped(self):
    def fetcher(url, method='GET', body=None, content_type=None):
      del url, method, body, content_type
      return FetchResponse(unanswered=True, note='timed out')

    aia = x509.AuthorityInformationAccess([
        x509.AccessDescription(
            AuthorityInformationAccessOID.OCSP,
            x509.UniformResourceIdentifier('http://ocsp.test/')),
    ])
    leaf = make_cert(
        'example.com', 'Test Intermediate', self.leaf_key, self.int_key,
        is_ca=False,
        san=[x509.DNSName('example.com')],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
        extra=[(aia, False)])
    report = self.check(
        [leaf, self.intermediate], ocsp_mode='fetch', fetcher=fetcher)
    self.assertEqual(report.check('revocation').status, 'skipped')
    self.assertNotEqual(report.check('revocation').status, 'pass')
    self.assertEqual(report.exit_code, 0)

  def test_private_root_not_in_store_fails_trust(self):
    private_key = _rsa()
    private_root = make_cert(
        'Private Root', 'Private Root', private_key, private_key, is_ca=True,
        days=4000, not_before=_ROOT_NOT_BEFORE)
    intermediate = make_cert(
        'Private Intermediate', 'Private Root', self.int_key, private_key,
        is_ca=True, days=4000, not_before=_ROOT_NOT_BEFORE)
    leaf = make_cert(
        'example.com', 'Private Intermediate', self.leaf_key, self.int_key,
        is_ca=False,
        san=[x509.DNSName('example.com')],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    report = self.check([leaf, intermediate, private_root])
    self.assertEqual(report.check('presented').status, 'fail')
    self.assertEqual(report.exit_code, 1)

  def test_cross_signed_root_matches_trust_anchor_spki(self):
    root_b_key = _rsa()
    cross = make_cert(
        'Root B', 'Test Root', root_b_key, self.root_key, is_ca=True,
        days=4000, not_before=_ROOT_NOT_BEFORE)
    int_key = _rsa()
    intermediate = make_cert(
        'Cross Intermediate', 'Root B', int_key, root_b_key, is_ca=True,
        days=4000, not_before=_ROOT_NOT_BEFORE)
    leaf_key = _rsa()
    leaf = make_cert(
        'example.com', 'Cross Intermediate', leaf_key, int_key, is_ca=False,
        san=[x509.DNSName('example.com')],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    report = self.check([leaf, intermediate, cross])
    self.assertEqual(report.check('presented').status, 'pass',
                     report.check('presented').reason)
    self.assertEqual(report.exit_code, 0)

  def test_pin_match_and_mismatch(self):
    pin = spki_sha256(self.leaf)
    matched = self.check(
        [self.leaf, self.intermediate], pins=[pin.upper()])
    self.assertEqual(matched.check('pin').status, 'pass')
    self.assertEqual(matched.exit_code, 0)
    other = spki_sha256(self.intermediate)
    also = self.check(
        [self.leaf, self.intermediate], pins=[other])
    self.assertEqual(also.check('pin').status, 'pass')
    missed = self.check(
        [self.leaf, self.intermediate], pins=['ab' * 32])
    self.assertEqual(missed.check('pin').status, 'fail')
    self.assertEqual(missed.exit_code, 1)

  def test_unknown_critical_extension_fails_closed(self):
    unknown = x509.UnrecognizedExtension(
        ObjectIdentifier('1.2.3.4.5.6.7'), b'\x05\x00')
    leaf = make_cert(
        'example.com', 'Test Intermediate', self.leaf_key, self.int_key,
        is_ca=False,
        san=[x509.DNSName('example.com')],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
        extra=[(unknown, True)])
    report = self.check([leaf, self.intermediate])
    self.assertEqual(report.check('presented').status, 'fail')
    self.assertIn('critical', report.check('presented').reason.lower())
    self.assertEqual(report.exit_code, 1)

  def test_any_extended_key_usage_is_not_enough(self):
    leaf = make_cert(
        'example.com', 'Test Intermediate', self.leaf_key, self.int_key,
        is_ca=False,
        san=[x509.DNSName('example.com')],
        eku=[ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE])
    report = self.check([leaf, self.intermediate])
    self.assertEqual(report.check('eku').status, 'fail')
    self.assertEqual(report.exit_code, 1)

  def test_missing_eku_fails_public_profile(self):
    leaf = make_cert(
        'example.com', 'Test Intermediate', self.leaf_key, self.int_key,
        is_ca=False, san=[x509.DNSName('example.com')])
    report = self.check([leaf, self.intermediate])
    self.assertEqual(report.check('eku').status, 'fail')
    self.assertEqual(report.check('presented').status, 'pass')

  def test_leaf_lifetime_limit(self):
    start = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    short = make_cert(
        'example.com', 'Test Intermediate', self.leaf_key, self.int_key,
        is_ca=False, not_before=start, days=398,
        san=[x509.DNSName('example.com')],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    ok = self.check([short, self.intermediate])
    self.assertEqual(ok.check('lifetime').status, 'pass',
                     ok.check('lifetime').reason)
    long = make_cert(
        'example.com', 'Test Intermediate', self.leaf_key, self.int_key,
        is_ca=False, not_before=start, days=399,
        san=[x509.DNSName('example.com')],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    bad = self.check([long, self.intermediate])
    self.assertEqual(bad.check('lifetime').status, 'fail')
    self.assertEqual(bad.check('validity').status, 'pass')
    self.assertEqual(bad.exit_code, 1)
    old = make_cert(
        'example.com', 'Test Intermediate', self.leaf_key, self.int_key,
        is_ca=False,
        not_before=datetime.datetime(2019, 1, 1, tzinfo=datetime.timezone.utc),
        days=2000,
        san=[x509.DNSName('example.com')],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    exempt = self.check([old, self.intermediate])
    self.assertEqual(exempt.check('lifetime').status, 'pass')
    self.assertEqual(exempt.check('validity').status, 'pass')

  def test_wildcard_and_idna_hostname_rules(self):
    wild = make_cert(
        'example.com', 'Test Intermediate', self.leaf_key, self.int_key,
        is_ca=False, san=[x509.DNSName('*.example.com')],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    self.assertEqual(hostname_matches('www.example.com', wild)[0], 'pass')
    self.assertEqual(hostname_matches('WWW.Example.COM', wild)[0], 'pass')
    self.assertEqual(hostname_matches('example.com', wild)[0], 'fail')
    self.assertEqual(hostname_matches('a.b.example.com', wild)[0], 'fail')
    single = make_cert(
        'com', 'Test Intermediate', self.leaf_key, self.int_key, is_ca=False,
        san=[x509.DNSName('*.com')],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    self.assertEqual(hostname_matches('foo.com', single)[0], 'fail')
    partial = make_cert(
        'example.com', 'Test Intermediate', self.leaf_key, self.int_key,
        is_ca=False, san=[x509.DNSName('www.*.example.com')],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    self.assertEqual(
        hostname_matches('www.a.example.com', partial)[0], 'fail')
    idna = make_cert(
        'xn--bcher-kva.example', 'Test Intermediate', self.leaf_key,
        self.int_key, is_ca=False,
        san=[x509.DNSName('xn--bcher-kva.example')],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    self.assertEqual(hostname_matches('Bücher.example', idna)[0], 'pass')
    address = make_cert(
        '203.0.113.5', 'Test Intermediate', self.leaf_key, self.int_key,
        is_ca=False,
        san=[x509.IPAddress(ipaddress.ip_address('203.0.113.5'))],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    self.assertEqual(hostname_matches('203.0.113.5', address)[0], 'pass')
    self.assertEqual(hostname_matches('203.0.113.6', address)[0], 'fail')

  def test_crl_fetch_revoked_and_unanswered(self):
    points = x509.CRLDistributionPoints([
        x509.DistributionPoint(
            full_name=[x509.UniformResourceIdentifier(
                'http://crl.test/leaf.crl')],
            relative_name=None, reasons=None, crl_issuer=None),
    ])
    leaf = make_cert(
        'example.com', 'Test Intermediate', self.leaf_key, self.int_key,
        is_ca=False,
        san=[x509.DNSName('example.com')],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
        extra=[(points, False)])
    revoked_builder = x509.RevokedCertificateBuilder()
    revoked_builder = revoked_builder.serial_number(leaf.serial_number)
    revoked_builder = revoked_builder.revocation_date(
        _WHEN - datetime.timedelta(days=1))
    crl = x509.CertificateRevocationListBuilder()
    crl = crl.issuer_name(self.intermediate.subject)
    crl = crl.last_update(_WHEN - datetime.timedelta(hours=1))
    crl = crl.next_update(_WHEN + datetime.timedelta(days=1))
    crl = crl.add_revoked_certificate(revoked_builder.build())
    crl = crl.sign(self.int_key, hashes.SHA256())
    der = crl.public_bytes(serialization.Encoding.DER)

    def fetcher(url, method='GET', body=None, content_type=None):
      del url, method, body, content_type
      return FetchResponse(body=der)

    report = self.check(
        [leaf, self.intermediate], crl_mode='fetch', fetcher=fetcher)
    self.assertEqual(report.check('revocation').status, 'fail')
    self.assertIn('revoked', report.check('revocation').reason)

    def silent(url, method='GET', body=None, content_type=None):
      del url, method, body, content_type
      return FetchResponse(unanswered=True, note='timed out')

    skipped = self.check(
        [leaf, self.intermediate], crl_mode='fetch', fetcher=silent)
    self.assertEqual(skipped.check('revocation').status, 'skipped')

  def test_fetch_url_rejects_non_http_and_does_not_follow_redirects(self):
    refused = fetch_url('file:///etc/passwd')
    self.assertTrue(refused.unanswered)
    ftp = fetch_url('ftp://example.invalid/ca.cer')
    self.assertTrue(ftp.unanswered)
    der = self.intermediate.public_bytes(serialization.Encoding.DER)

    class Handler(BaseHTTPRequestHandler):
      def do_GET(self):
        if self.path == '/redir':
          self.send_response(302)
          self.send_header('Location', '/int.cer')
          self.end_headers()
          return
        if self.path == '/int.cer':
          self.send_response(200)
          self.send_header('Content-Type', 'application/pkix-cert')
          self.send_header('Content-Length', str(len(der)))
          self.end_headers()
          self.wfile.write(der)
          return
        self.send_response(404)
        self.end_headers()

      def log_message(self, fmt, *args):
        del fmt, args

    server = HTTPServer(('127.0.0.1', 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
      direct = fetch_url(f'http://127.0.0.1:{port}/int.cer')
      self.assertFalse(direct.unanswered)
      self.assertEqual(direct.body, der)
      bounced = fetch_url(f'http://127.0.0.1:{port}/redir')
      self.assertTrue(bounced.unanswered)
      self.assertIsNone(bounced.body)
    finally:
      server.shutdown()
      server.server_close()

  def test_aia_over_local_http(self):
    der = self.intermediate.public_bytes(serialization.Encoding.DER)

    class Handler(BaseHTTPRequestHandler):
      def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', str(len(der)))
        self.end_headers()
        self.wfile.write(der)

      def log_message(self, fmt, *args):
        del fmt, args

    server = HTTPServer(('127.0.0.1', 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
      url = f'http://127.0.0.1:{port}/int.cer'
      aia = x509.AuthorityInformationAccess([
          x509.AccessDescription(
              AuthorityInformationAccessOID.CA_ISSUERS,
              x509.UniformResourceIdentifier(url)),
      ])
      leaf = make_cert(
          'example.com', 'Test Intermediate', self.leaf_key, self.int_key,
          is_ca=False,
          san=[x509.DNSName('example.com')],
          eku=[ExtendedKeyUsageOID.SERVER_AUTH],
          extra=[(aia, False)])
      report = self.check([leaf], fetcher=None, allow_fetched=True)
      self.assertEqual(report.check('presented').status, 'fail')
      self.assertEqual(report.check('fetched').status, 'pass',
                       report.check('fetched').reason)
      self.assertEqual(report.exit_code, 0)
    finally:
      server.shutdown()
      server.server_close()

  def test_capture_local_server(self):
    leaf = self.leaf
    key = self.leaf_key
    with tempfile.TemporaryDirectory() as tmp:
      cert_path = os.path.join(tmp, 'cert.pem')
      key_path = os.path.join(tmp, 'key.pem')
      with open(cert_path, 'wb') as handle:
        handle.write(leaf.public_bytes(serialization.Encoding.PEM))
        handle.write(self.intermediate.public_bytes(serialization.Encoding.PEM))
      with open(key_path, 'wb') as handle:
        handle.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
      context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
      context.load_cert_chain(cert_path, key_path)
      ready = threading.Event()
      box = {}

      def serve():
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('127.0.0.1', 0))
        sock.listen(1)
        sock.settimeout(5)
        box['port'] = sock.getsockname()[1]
        ready.set()
        try:
          conn, _ = sock.accept()
        except socket.timeout:
          sock.close()
          return
        try:
          tls = context.wrap_socket(conn, server_side=True)
          tls.recv(1)
          tls.close()
        except Exception:
          try:
            conn.close()
          except OSError:
            pass
        finally:
          sock.close()

      thread = threading.Thread(target=serve, daemon=True)
      thread.start()
      self.assertTrue(ready.wait(5))
      captured = capture_tls('example.com', box['port'], ip='127.0.0.1')
      thread.join(5)
    self.assertEqual(captured.peer_ip, '127.0.0.1')
    self.assertEqual(captured.sni, 'example.com')
    self.assertTrue(captured.tls_version.startswith('TLS'))
    self.assertIsNone(captured.staple)
    self.assertGreaterEqual(len(captured.certificates), 1)
    self.assertEqual(
        captured.certificates[0].fingerprint(hashes.SHA256()),
        leaf.fingerprint(hashes.SHA256()))

  def test_mozilla_bundle_is_the_vendored_certifi_file(self):
    store = mozilla_trust_store()
    self.assertTrue(store.bundle_id.startswith('certifi '))
    self.assertGreater(len(store.certificates), 50)
    self.assertTrue(os.path.isfile(certifi.where()))
    with open(certifi.where(), 'rb') as handle:
      self.assertIn(b'BEGIN CERTIFICATE', handle.read())

  def test_text_and_json_reports(self):
    report = self.check([self.leaf, self.intermediate])
    text = render_text(report)
    self.assertIn(report.leaf.subject.rfc4514_string(), text)
    self.assertIn(self.leaf.fingerprint(hashes.SHA256()).hex(), text)
    self.assertIn('fingerprint_sha256', text)
    self.assertIn('not_after', text)
    self.assertIn('test-store', text)
    self.assertIn('presented', text)
    payload = json.loads(render_json(report))
    self.assertEqual(payload['peer_ip'], None)
    self.assertIn('tls_version', payload)
    self.assertIn('sni', payload)
    self.assertEqual(payload['exit_code'], 0)
    self.assertEqual(payload['leaf']['fingerprint_sha256'],
                     self.leaf.fingerprint(hashes.SHA256()).hex())

  def test_cli_module_chain_and_connect_failure(self):
    env = os.environ.copy()
    env['PYTHONPATH'] = _REPO_ROOT + os.pathsep + env.get('PYTHONPATH', '')
    help_run = subprocess.run(
        [sys.executable, '-m', 'tlscheck', '--help'],
        cwd=_REPO_ROOT, env=env, capture_output=True, text=True, check=False)
    self.assertEqual(help_run.returncode, 0, help_run.stderr)
    self.assertIn('--allow-fetched', help_run.stdout)
    with tempfile.TemporaryDirectory() as tmp:
      path = os.path.join(tmp, 'chain.pem')
      with open(path, 'wb') as handle:
        handle.write(_pem(self.leaf, self.intermediate))
      proc = subprocess.run(
          [sys.executable, '-m', 'tlscheck', 'example.com', '--chain', path,
           '--at', '2024-06-15T00:00:00+00:00', '--json', '--ocsp', 'off'],
          cwd=_REPO_ROOT, env=env, capture_output=True, text=True, check=False)
    self.assertEqual(proc.returncode, 1, proc.stderr)
    payload = json.loads(proc.stdout)
    self.assertEqual(payload['host'], 'example.com')
    self.assertIsNone(payload['peer_ip'])
    self.assertIsNone(payload['tls_version'])
    self.assertTrue(payload['bundle_id'].startswith('certifi '))
    self.assertIn('fingerprint_sha256', payload['leaf'])
    refused = subprocess.run(
        [sys.executable, '-m', 'tlscheck', '127.0.0.1', '--port', '1',
         '--ocsp', 'off'],
        cwd=_REPO_ROOT, env=env, capture_output=True, text=True, check=False)
    self.assertEqual(refused.returncode, 2, refused.stdout + refused.stderr)
    self.assertIn('tlscheck:', refused.stderr)


@unittest.skipUnless(os.environ.get('TLSCHECK_LIVE') == '1',
                     'set TLSCHECK_LIVE=1 to connect to a public host')
class TlscheckLiveTest(unittest.TestCase):

  def test_live_microsoft(self):
    code = main(['www.microsoft.com', '--json', '--ocsp', 'staple'])
    self.assertIn(code, (0, 1))
