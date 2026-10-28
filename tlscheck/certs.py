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
"""Certificate helpers and the web PKI profile checks.

Path building lives in tlscheck.path and calls cryptography's verifier.
The checks here are the extra public-trust rules that verifier does not
apply on its own: serverAuth (anyExtendedKeyUsage is not enough), no MD5
or SHA-1 on non-anchors, RSA >= 2048, NIST P-256/P-384/P-521 only, the
398-day leaf lifetime, and RFC 9525 name matching with no CN fallback.
"""

import datetime
import hashlib
import ipaddress
from typing import Optional, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import ObjectIdentifier

from tlscheck.errors import TlscheckError

# CAB Forum baseline: a leaf issued on or after this date may not be valid
# for more than 398 days.
_CAB_LIFETIME_START = datetime.datetime(
    2020, 9, 1, tzinfo=datetime.timezone.utc)
_MAX_LEAF_LIFETIME = datetime.timedelta(days=398)

_WEAK_HASHES = ('sha1', 'md5')
_WEAK_SIGNATURE_OIDS = {
    ObjectIdentifier('1.2.840.113549.1.1.4'),  # md5WithRSAEncryption
    ObjectIdentifier('1.2.840.113549.1.1.5'),  # sha1WithRSAEncryption
    ObjectIdentifier('1.2.840.10040.4.3'),  # dsa-with-sha1
    ObjectIdentifier('1.2.840.10045.4.1'),  # ecdsa-with-SHA1
}
_ALLOWED_CURVES = (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)
_OCSP_SIGNING = ExtendedKeyUsageOID.OCSP_SIGNING
_SERVER_AUTH = ExtendedKeyUsageOID.SERVER_AUTH
_ANY_EKU = ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE


def aware(moment: datetime.datetime) -> datetime.datetime:
  """Return moment as UTC. Naive values are interpreted as UTC."""
  if moment.tzinfo is None:
    return moment.replace(tzinfo=datetime.timezone.utc)
  return moment.astimezone(datetime.timezone.utc)


def parse_time(text: str) -> datetime.datetime:
  """Parse an ISO-8601 time. A trailing Z is accepted. Naive means UTC."""
  try:
    parsed = datetime.datetime.fromisoformat(text.replace('Z', '+00:00'))
  except ValueError as exc:
    raise TlscheckError(f'invalid --at time {text!r}') from exc
  if parsed.tzinfo is None:
    parsed = parsed.replace(tzinfo=datetime.timezone.utc)
  return parsed.astimezone(datetime.timezone.utc)


def cert_not_before(cert: x509.Certificate) -> datetime.datetime:
  value = getattr(cert, 'not_valid_before_utc', None)
  if value is None:
    value = cert.not_valid_before
  return aware(value)


def cert_not_after(cert: x509.Certificate) -> datetime.datetime:
  value = getattr(cert, 'not_valid_after_utc', None)
  if value is None:
    value = cert.not_valid_after
  return aware(value)


def fingerprint_sha256(cert: x509.Certificate) -> str:
  return cert.fingerprint(hashes.SHA256()).hex()


def spki_der(cert: x509.Certificate) -> bytes:
  return cert.public_key().public_bytes(
      serialization.Encoding.DER,
      serialization.PublicFormat.SubjectPublicKeyInfo)


def spki_sha256(cert: x509.Certificate) -> str:
  return hashlib.sha256(spki_der(cert)).hexdigest()


def subject_text(cert: x509.Certificate) -> str:
  return cert.subject.rfc4514_string()


def _der_span(buf: bytes, index: int) -> tuple:
  """Return (header_len, value_start, value_end) for the TLV at index."""
  if index >= len(buf):
    raise TlscheckError('truncated ASN.1 value')
  index += 1
  length = buf[index]
  index += 1
  if length & 0x80:
    count = length & 0x7f
    if count == 0 or index + count > len(buf):
      raise TlscheckError('truncated ASN.1 length')
    length = int.from_bytes(buf[index:index + count], 'big')
    index += count
  end = index + length
  if end > len(buf):
    raise TlscheckError('truncated ASN.1 value')
  return index, end


def public_key_bits(cert: x509.Certificate) -> bytes:
  """Return the subjectPublicKey bits, without the BIT STRING header.

  RFC 5280 key identifiers and OCSP CertID issuerKeyHash both hash these
  bytes (tag, length, and the unused-bits count are excluded).
  """
  spki = spki_der(cert)
  value_start, value_end = _der_span(spki, 0)
  body = spki[value_start:value_end]
  _, first_end = _der_span(body, 0)
  bit_start, bit_end = _der_span(body, first_end)
  bit_string = body[bit_start:bit_end]
  if not bit_string or bit_string[0] != 0:
    raise TlscheckError('subject public key is not a whole number of bytes')
  return bit_string[1:]


def key_identifier(cert: x509.Certificate) -> bytes:
  """SHA-1 of the public key bits. Matches a standard subjectKeyIdentifier."""
  return hashlib.sha1(public_key_bits(cert)).digest()


def digest_key(cert: x509.Certificate, algorithm) -> bytes:
  digest = hashes.Hash(algorithm)
  digest.update(public_key_bits(cert))
  return digest.finalize()


def digest_name(name: x509.Name, algorithm) -> bytes:
  digest = hashes.Hash(algorithm)
  digest.update(name.public_bytes())
  return digest.finalize()


def load_certificates(data: bytes) -> list:
  """Parse PEM or DER certificates, including a PKCS#7 bag."""
  if not data:
    raise TlscheckError('empty certificate data')
  if b'-----BEGIN CERTIFICATE-----' in data:
    try:
      certs = list(x509.load_pem_x509_certificates(data))
    except ValueError as exc:
      raise TlscheckError(f'could not parse PEM certificates: {exc}') from exc
    if not certs:
      raise TlscheckError('PEM data contained no certificates')
    return certs
  if b'-----BEGIN PKCS7-----' in data:
    try:
      return list(pkcs7.load_pem_pkcs7_certificates(data))
    except ValueError as exc:
      raise TlscheckError(f'could not parse PKCS#7 PEM: {exc}') from exc
  try:
    return [x509.load_der_x509_certificate(data)]
  except ValueError:
    pass
  try:
    certs = list(pkcs7.load_der_pkcs7_certificates(data))
  except ValueError as exc:
    raise TlscheckError(f'could not parse certificates: {exc}') from exc
  if not certs:
    raise TlscheckError('PKCS#7 data contained no certificates')
  return certs


def load_certificate_file(path: str) -> list:
  try:
    with open(path, 'rb') as handle:
      data = handle.read()
  except OSError as exc:
    raise TlscheckError(f'could not read {path}: {exc}') from exc
  return load_certificates(data)


def a_label(name: str) -> str:
  """Encode a domain (or a wildcard pattern) as lowercase A-labels.

  A single asterisk label is left in place so wildcard patterns can be
  compared after the other labels are encoded.
  """
  text = name.strip().rstrip('.')
  if not text:
    raise TlscheckError('empty domain name')
  labels = []
  for label in text.split('.'):
    if label == '*':
      labels.append('*')
      continue
    try:
      labels.append(label.encode('idna').decode('ascii').lower())
    except UnicodeError as exc:
      raise TlscheckError(f'invalid domain name {name!r}') from exc
  return '.'.join(labels)


def extension(cert: x509.Certificate, ext_class):
  try:
    return cert.extensions.get_extension_for_class(ext_class)
  except x509.ExtensionNotFound:
    return None


def uri_values(general_names) -> list:
  urls = []
  if general_names is None:
    return urls
  for name in general_names:
    if isinstance(name, x509.UniformResourceIdentifier):
      urls.append(name.value)
  return urls


def ca_issuer_urls(cert: x509.Certificate) -> list:
  ext = extension(cert, x509.AuthorityInformationAccess)
  if ext is None:
    return []
  urls = []
  for desc in ext.value:
    if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
      urls.extend(uri_values([desc.access_location]))
  return urls


def ocsp_urls(cert: x509.Certificate) -> list:
  ext = extension(cert, x509.AuthorityInformationAccess)
  if ext is None:
    return []
  urls = []
  for desc in ext.value:
    if desc.access_method == AuthorityInformationAccessOID.OCSP:
      urls.extend(uri_values([desc.access_location]))
  return urls


def crl_urls(cert: x509.Certificate) -> list:
  ext = extension(cert, x509.CRLDistributionPoints)
  if ext is None:
    return []
  urls = []
  for point in ext.value:
    urls.extend(uri_values(point.full_name))
  return urls


def has_must_staple(cert: x509.Certificate) -> bool:
  ext = extension(cert, x509.TLSFeature)
  if ext is None:
    return False
  return x509.TLSFeatureType.status_request in list(ext.value)


def has_ocsp_signing(cert: x509.Certificate) -> bool:
  ext = extension(cert, x509.ExtendedKeyUsage)
  if ext is None:
    return False
  return _OCSP_SIGNING in list(ext.value)


def has_ocsp_nocheck(cert: x509.Certificate) -> bool:
  """True when the responder cert carries id-pkix-ocsp-nocheck."""
  oid = ObjectIdentifier('1.3.6.1.5.5.7.48.1.5')
  try:
    cert.extensions.get_extension_for_oid(oid)
  except x509.ExtensionNotFound:
    return False
  return True


def signature_valid(child: x509.Certificate, issuer: x509.Certificate) -> bool:
  """True when issuer's key verifies child's signature. Uses cryptography."""
  algorithm = child.signature_hash_algorithm
  if algorithm is None:
    return False
  public_key = issuer.public_key()
  try:
    if isinstance(public_key, rsa.RSAPublicKey):
      public_key.verify(
          child.signature,
          child.tbs_certificate_bytes,
          padding.PKCS1v15(),
          algorithm)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
      public_key.verify(
          child.signature,
          child.tbs_certificate_bytes,
          ec.ECDSA(algorithm))
    else:
      return False
  except Exception:
    return False
  return True


def _ski(cert: x509.Certificate) -> Optional[bytes]:
  ext = extension(cert, x509.SubjectKeyIdentifier)
  if ext is None:
    return None
  return ext.value.digest


def _aki(cert: x509.Certificate) -> Optional[bytes]:
  ext = extension(cert, x509.AuthorityKeyIdentifier)
  if ext is None:
    return None
  return ext.value.key_identifier


def find_issuer(cert: x509.Certificate,
                candidates: Sequence[x509.Certificate]
                ) -> Optional[x509.Certificate]:
  """Find the candidate that signed cert, preferring AKI/SKI over names."""
  aki = _aki(cert)
  name_matches = []
  for candidate in candidates:
    if fingerprint_sha256(candidate) == fingerprint_sha256(cert):
      continue
    ski = _ski(candidate)
    if aki is not None and ski == aki and signature_valid(cert, candidate):
      return candidate
    if candidate.subject == cert.issuer:
      name_matches.append(candidate)
  for candidate in name_matches:
    if signature_valid(cert, candidate):
      return candidate
  return None


def _ip_or_none(text: str):
  try:
    return ipaddress.ip_address(text.strip().rstrip('.'))
  except ValueError:
    return None


def _wildcard_match(host: str, pattern: str) -> bool:
  """Match a single leftmost wildcard label. Rejects bare and single-label.

  `*.example.com` matches `www.example.com` and not `example.com`.
  `*.com` is rejected (one label under the star). A wildcard that is not
  the entire leftmost label never matches. This is not a public-suffix
  list: `*.co.uk` still matches one label under `co.uk`.
  """
  if '*' not in pattern:
    return host == pattern
  parts = pattern.split('.')
  if parts[0] != '*' or pattern.count('*') != 1:
    return False
  rest = parts[1:]
  if len(rest) < 2:
    return False
  host_parts = host.split('.')
  if len(host_parts) != len(rest) + 1:
    return False
  if not host_parts[0] or host_parts[0] == '*':
    return False
  return host_parts[1:] == rest


def hostname_matches(expected: str, cert: x509.Certificate) -> tuple:
  """RFC 9525 match against dNSName and iPAddress. No CN fallback.

  Returns (status, reason) with status pass or fail.
  """
  san = extension(cert, x509.SubjectAlternativeName)
  if san is None or len(list(san.value)) == 0:
    return ('fail', 'no subjectAltName; commonName is not used')
  ip_value = _ip_or_none(expected)
  if ip_value is not None:
    for name in san.value.get_values_for_type(x509.IPAddress):
      if name == ip_value:
        return ('pass', f'iPAddress {ip_value} matched')
    return ('fail', f'no iPAddress subjectAltName matches {ip_value}')
  try:
    host = a_label(expected)
  except TlscheckError as exc:
    return ('fail', str(exc))
  dns_names = list(san.value.get_values_for_type(x509.DNSName))
  if not dns_names:
    return ('fail', 'subjectAltName has no dNSName')
  for pattern in dns_names:
    try:
      encoded = a_label(pattern)
    except TlscheckError:
      continue
    if _wildcard_match(host, encoded):
      return ('pass', f'dNSName {pattern} matched {host}')
  return ('fail', f'no dNSName matches {host}')


def check_eku(leaf: x509.Certificate) -> tuple:
  ext = extension(leaf, x509.ExtendedKeyUsage)
  if ext is None:
    return ('fail', 'extendedKeyUsage is missing; serverAuth is required')
  oids = list(ext.value)
  if _SERVER_AUTH in oids:
    return ('pass', 'serverAuth is present')
  if _ANY_EKU in oids:
    return (
        'fail',
        'anyExtendedKeyUsage is not sufficient; serverAuth is required')
  return ('fail', 'extendedKeyUsage does not include serverAuth')


def _is_weak_signature(cert: x509.Certificate) -> bool:
  algorithm = cert.signature_hash_algorithm
  if algorithm is not None and algorithm.name in _WEAK_HASHES:
    return True
  return cert.signature_algorithm_oid in _WEAK_SIGNATURE_OIDS


def check_signatures(certs: Sequence[x509.Certificate],
                     anchor_spkis: set) -> tuple:
  weak = []
  for cert in certs:
    if spki_der(cert) in anchor_spkis:
      continue
    if _is_weak_signature(cert):
      name = cert.signature_hash_algorithm
      label = name.name if name is not None else str(
          cert.signature_algorithm_oid)
      weak.append(f'{subject_text(cert)} ({label})')
  if weak:
    return ('fail', 'MD5 or SHA-1 signature on ' + '; '.join(weak))
  return ('pass', 'no MD5 or SHA-1 signature on non-anchor certificates')


def check_public_keys(certs: Sequence[x509.Certificate],
                      anchor_spkis: set) -> tuple:
  problems = []
  for cert in certs:
    if spki_der(cert) in anchor_spkis:
      continue
    public_key = cert.public_key()
    label = subject_text(cert)
    if isinstance(public_key, rsa.RSAPublicKey):
      if public_key.key_size < 2048:
        problems.append(f'{label} RSA {public_key.key_size}')
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
      if not isinstance(public_key.curve, _ALLOWED_CURVES):
        problems.append(f'{label} ECDSA {public_key.curve.name}')
    else:
      problems.append(f'{label} {type(public_key).__name__}')
  if problems:
    return (
        'fail',
        'public key is not RSA >= 2048 or ECDSA P-256/P-384/P-521: '
        + '; '.join(problems))
  return ('pass', 'RSA keys are at least 2048 bits and ECDSA curves are NIST')


def check_validity(leaf: x509.Certificate, when: datetime.datetime) -> tuple:
  not_before = cert_not_before(leaf)
  not_after = cert_not_after(leaf)
  if when < not_before:
    return ('fail', f'not yet valid; notBefore is {not_before.isoformat()}')
  if when > not_after:
    return ('fail', f'expired; notAfter is {not_after.isoformat()}')
  return (
      'pass',
      f'check time is inside {not_before.isoformat()} .. '
      f'{not_after.isoformat()}')


def check_lifetime(leaf: x509.Certificate) -> tuple:
  not_before = cert_not_before(leaf)
  not_after = cert_not_after(leaf)
  span = not_after - not_before
  if not_before >= _CAB_LIFETIME_START and span > _MAX_LEAF_LIFETIME:
    days = span.total_seconds() / 86400
    return (
        'fail',
        f'leaf validity is {days:.1f} days and notBefore '
        f'{not_before.date().isoformat()} is on or after 2020-09-01')
  return ('pass', f'leaf validity is {span.days} days')


def normalize_pin(text: str) -> str:
  pin = text.strip().lower().replace(':', '')
  if len(pin) != 64 or any(char not in '0123456789abcdef' for char in pin):
    raise TlscheckError(
        f'--pin must be a SHA-256 SPKI hex digest, got {text!r}')
  return pin


def check_pins(pins: Sequence[str],
               certs: Sequence[x509.Certificate],
               anchor_spkis: set) -> tuple:
  if not pins:
    return ('skipped', 'no SPKI pins were configured')
  normalized = [normalize_pin(pin) for pin in pins]
  for cert in certs:
    if spki_der(cert) in anchor_spkis:
      continue
    digest = spki_sha256(cert)
    if digest in normalized:
      return ('pass', f'SPKI pin matched {subject_text(cert)}')
  return ('fail', 'no leaf or intermediate SPKI matched a pin')
