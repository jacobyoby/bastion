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
"""OCSP staple checks, and opt-in OCSP and CRL fetches.

A missing staple is skipped unless the leaf has the must-staple TLS
feature. An unanswered fetch is skipped and never counts as a pass.
"""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ObjectIdentifier

from tlscheck.certs import aware
from tlscheck.certs import cert_not_after
from tlscheck.certs import cert_not_before
from tlscheck.certs import crl_urls
from tlscheck.certs import digest_key
from tlscheck.certs import digest_name
from tlscheck.certs import find_issuer
from tlscheck.certs import fingerprint_sha256
from tlscheck.certs import has_must_staple
from tlscheck.certs import has_ocsp_nocheck
from tlscheck.certs import has_ocsp_signing
from tlscheck.certs import key_identifier
from tlscheck.certs import ocsp_urls
from tlscheck.certs import spki_der
from tlscheck.certs import subject_text
from tlscheck.fetch import FetchResponse

_RSA_PSS = ObjectIdentifier('1.2.840.113549.1.1.10')


def _moment(obj, utc_name: str, naive_name: str):
  """Read a cryptography timestamp, preferring the timezone-aware property."""
  if utc_name in dir(obj):
    value = getattr(obj, utc_name)
    if value is not None:
      return aware(value)
  value = getattr(obj, naive_name, None)
  if value is None:
    return None
  return aware(value)


def _verify_signature(public_key, signature: bytes, data: bytes,
                      algorithm, signature_oid) -> None:
  if isinstance(public_key, rsa.RSAPublicKey):
    if signature_oid == _RSA_PSS:
      public_key.verify(
          signature, data,
          padding.PSS(
              mgf=padding.MGF1(algorithm),
              salt_length=padding.PSS.DIGEST_LENGTH),
          algorithm)
    else:
      public_key.verify(signature, data, padding.PKCS1v15(), algorithm)
  elif isinstance(public_key, ec.EllipticCurvePublicKey):
    public_key.verify(signature, data, ec.ECDSA(algorithm))
  else:
    raise ValueError(f'unsupported OCSP key {type(public_key).__name__}')


def _responder_time_ok(cert: x509.Certificate, when: datetime.datetime) -> bool:
  if has_ocsp_nocheck(cert):
    return True
  return cert_not_before(cert) <= when <= cert_not_after(cert)


def _chains_to_issuer(cert, issuer, pool, when) -> bool:
  """True when cert is the issuer or a signature chain ends at its key."""
  current = cert
  seen = set()
  for _ in range(5):
    if spki_der(current) == spki_der(issuer):
      return True
    if not _responder_time_ok(current, when):
      return False
    parent = find_issuer(
        current,
        [item for item in pool
         if fingerprint_sha256(item) not in seen])
    if parent is None:
      return False
    seen.add(fingerprint_sha256(current))
    current = parent
  return spki_der(current) == spki_der(issuer)


def _matching_single(response, serial: int):
  if getattr(response, 'serial_number', None) == serial:
    return response
  for single in getattr(response, 'responses', ()):
    if getattr(single, 'serial_number', None) == serial:
      return single
  return None


def _authorized_signer(response, single, issuer, extras, when):
  pool = [issuer]
  pool.extend(getattr(response, 'certificates', ()) or ())
  pool.extend(extras)
  key_hash = getattr(response, 'responder_key_hash', None)
  if key_hash is None:
    key_hash = getattr(single, 'responder_key_hash', None)
  name = getattr(response, 'responder_name', None)
  if name is None:
    name = getattr(single, 'responder_name', None)
  candidates = []
  for cert in pool:
    if key_hash is not None and key_identifier(cert) == key_hash:
      candidates.append(cert)
    elif key_hash is None and name is not None and cert.subject == name:
      candidates.append(cert)
  for cert in candidates:
    if spki_der(cert) == spki_der(issuer):
      return cert
    if not has_ocsp_signing(cert):
      continue
    if _chains_to_issuer(cert, issuer, pool, when):
      return cert
  return None


def verify_ocsp(leaf: x509.Certificate, issuer: x509.Certificate,
                response_der: bytes, when: datetime.datetime,
                extras: list) -> tuple:
  """Verify one OCSP response that must cover leaf and be signed properly."""
  try:
    response = ocsp.load_der_ocsp_response(response_der)
  except ValueError as exc:
    return ('fail', f'OCSP response could not be parsed: {exc}')
  if response.response_status is not ocsp.OCSPResponseStatus.SUCCESSFUL:
    return ('fail', f'OCSP response status is {response.response_status.name}')
  single = _matching_single(response, leaf.serial_number)
  if single is None:
    return ('fail', 'OCSP response does not cover this certificate serial')
  status = single.certificate_status
  if status is not ocsp.OCSPCertStatus.GOOD:
    return ('fail', f'OCSP certificate status is {status.name}')
  this_update = _moment(single, 'this_update_utc', 'this_update')
  next_update = _moment(single, 'next_update_utc', 'next_update')
  if this_update is None:
    return ('fail', 'OCSP response has no thisUpdate')
  if when < this_update:
    return ('fail', 'OCSP thisUpdate is after the check time')
  if next_update is None:
    return ('fail', 'OCSP response has no nextUpdate covering the check time')
  if when > next_update:
    return ('fail', 'OCSP nextUpdate is before the check time')
  hash_alg = getattr(single, 'hash_algorithm', None) or response.hash_algorithm
  try:
    if digest_key(issuer, hash_alg) != single.issuer_key_hash:
      return ('fail', 'OCSP issuer key hash does not match the issuer')
    if digest_name(issuer.subject, hash_alg) != single.issuer_name_hash:
      return ('fail', 'OCSP issuer name hash does not match the issuer')
  except Exception as exc:
    return ('fail', f'OCSP issuer identifier could not be checked: {exc}')
  signer = _authorized_signer(response, single, issuer, extras, when)
  if signer is None:
    return ('fail', 'OCSP signer is not the issuer or an authorized responder')
  algorithm = response.signature_hash_algorithm
  if algorithm is None:
    return ('fail', 'OCSP signature algorithm is not supported')
  try:
    _verify_signature(
        signer.public_key(), response.signature, response.tbs_response_bytes,
        algorithm, response.signature_algorithm_oid)
  except Exception:
    return ('fail', 'OCSP signature verification failed')
  return (
      'pass',
      f'OCSP status good from {this_update.isoformat()} '
      f'until {next_update.isoformat()}, signed by {subject_text(signer)}')


def _build_ocsp_request(leaf, issuer) -> bytes:
  builder = ocsp.OCSPRequestBuilder()
  builder = builder.add_certificate(leaf, issuer, hashes.SHA1())
  request = builder.build()
  return request.public_bytes(serialization.Encoding.DER)


def _fetch_ocsp(leaf, issuer, extras, when, fetcher) -> tuple:
  urls = ocsp_urls(leaf)
  if not urls:
    return ('skipped', 'no OCSP URL in the leaf AIA extension')
  try:
    request_der = _build_ocsp_request(leaf, issuer)
  except Exception as exc:
    return ('fail', f'could not build an OCSP request: {exc}')
  notes = []
  for url in urls:
    response = fetcher(
        url, method='POST', body=request_der,
        content_type='application/ocsp-request')
    if not isinstance(response, FetchResponse):
      notes.append('fetcher returned nothing')
      continue
    if response.unanswered or not response.body:
      notes.append(response.note or 'unanswered')
      continue
    status, reason = verify_ocsp(leaf, issuer, response.body, when, extras)
    if status == 'pass':
      return (status, reason)
    return ('fail', reason)
  detail = '; '.join(note for note in notes if note) or 'unanswered'
  return ('skipped', f'OCSP fetch unanswered ({detail})')


def _load_crl(data: bytes):
  if b'-----BEGIN' in data:
    return x509.load_pem_x509_crl(data)
  return x509.load_der_x509_crl(data)


def _fetch_crl(leaf, issuer, when, fetcher) -> tuple:
  urls = crl_urls(leaf)
  if not urls:
    return ('skipped', 'no CRL distribution point on the leaf')
  notes = []
  saw_answer = False
  for url in urls:
    response = fetcher(url, method='GET', body=None, content_type=None)
    if not isinstance(response, FetchResponse):
      notes.append('fetcher returned nothing')
      continue
    if response.unanswered or not response.body:
      notes.append(response.note or 'unanswered')
      continue
    saw_answer = True
    try:
      crl = _load_crl(response.body)
    except ValueError as exc:
      return ('fail', f'CRL could not be parsed: {exc}')
    algorithm = crl.signature_hash_algorithm
    if algorithm is None:
      return ('fail', 'CRL signature algorithm is not supported')
    try:
      _verify_signature(
          issuer.public_key(), crl.signature, crl.tbs_certlist_bytes,
          algorithm, crl.signature_algorithm_oid)
    except Exception:
      return ('fail', 'CRL signature verification failed')
    this_update = _moment(crl, 'last_update_utc', 'last_update')
    next_update = _moment(crl, 'next_update_utc', 'next_update')
    if this_update is None or when < this_update:
      return ('fail', 'CRL thisUpdate does not cover the check time')
    if next_update is None or when > next_update:
      return ('fail', 'CRL nextUpdate does not cover the check time')
    revoked = crl.get_revoked_certificate_by_serial_number(leaf.serial_number)
    if revoked is not None:
      return ('fail', 'CRL lists this certificate serial as revoked')
    return ('pass', f'CRL from {url} does not list this serial')
  if saw_answer:
    return ('fail', 'CRL response was not usable')
  detail = '; '.join(note for note in notes if note) or 'unanswered'
  return ('skipped', f'CRL fetch unanswered ({detail})')


def _combine(parts: list) -> tuple:
  failures = [reason for status, reason in parts if status == 'fail']
  if failures:
    return ('fail', '; '.join(failures))
  passes = [reason for status, reason in parts if status == 'pass']
  if passes:
    return ('pass', '; '.join(passes))
  skipped = [reason for status, reason in parts if status == 'skipped']
  return ('skipped', '; '.join(skipped) if skipped else 'revocation not checked')


def check_revocation(leaf: x509.Certificate, issuer, staple: bytes,
                     ocsp_mode: str, crl_mode: str, when: datetime.datetime,
                     extras: list, fetcher) -> tuple:
  """Return (status, reason) for the revocation check.

  ocsp_mode is staple, fetch, or off. crl_mode is off or fetch.
  issuer may be None when the bag did not contain a verified issuer.
  """
  parts = []
  must_staple = has_must_staple(leaf)
  if ocsp_mode == 'off':
    parts.append(('skipped', 'OCSP checks are off'))
  elif staple:
    if issuer is None:
      parts.append((
          'fail',
          'stapled OCSP response cannot be checked without the issuer'))
    else:
      parts.append(verify_ocsp(leaf, issuer, staple, when, extras))
  elif must_staple:
    parts.append((
        'fail',
        'leaf has must-staple (status_request) and no OCSP staple was present'))
  elif ocsp_mode == 'fetch':
    if issuer is None:
      parts.append(('skipped', 'OCSP fetch skipped; issuer certificate missing'))
    else:
      parts.append(_fetch_ocsp(leaf, issuer, extras, when, fetcher))
  else:
    parts.append(('skipped', 'no stapled OCSP response and no must-staple'))
  if crl_mode == 'fetch':
    if issuer is None:
      parts.append(('skipped', 'CRL fetch skipped; issuer certificate missing'))
    else:
      parts.append(_fetch_crl(leaf, issuer, when, fetcher))
  else:
    parts.append(('skipped', 'CRL fetch is off'))
  return _combine(parts)
