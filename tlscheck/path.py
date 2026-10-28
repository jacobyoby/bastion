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
"""Build a certificate path with cryptography's verifier.

The server sends a bag of certificates. Trust anchors come only from the
store passed in (the Mozilla bundle, or a test store). A certificate the
server sent is an anchor only when its subject public key is in that store,
which is how a cross-signed root is recognized. System verify paths are
never loaded.
"""

import datetime
import ipaddress
import pathlib
import warnings

import certifi
from cryptography.utils import CryptographyDeprecationWarning
from cryptography import x509
from cryptography.x509.verification import DNSName
from cryptography.x509.verification import IPAddress
from cryptography.x509.verification import PolicyBuilder
from cryptography.x509.verification import Store
from cryptography.x509.verification import VerificationError

from tlscheck.certs import a_label
from tlscheck.certs import ca_issuer_urls
from tlscheck.certs import extension
from tlscheck.certs import find_issuer
from tlscheck.certs import fingerprint_sha256
from tlscheck.certs import load_certificates
from tlscheck.certs import spki_der
from tlscheck.errors import TlscheckError
from tlscheck.fetch import FetchResponse
from tlscheck.fetch import fetch_url

_MAX_FETCHES = 8
_MAX_RETRIEVED = 16


class TrustStore:
  """Certificates that may end a path, plus a name for the report."""

  def __init__(self, certificates: list, bundle_id: str):
    if not certificates:
      raise TlscheckError('trust store is empty')
    self.certificates = list(certificates)
    self.bundle_id = bundle_id

  def anchor_spkis(self) -> set:
    return {spki_der(cert) for cert in self.certificates}


def mozilla_trust_store() -> TrustStore:
  """Mozilla roots vendored in the certifi wheel. Nothing is downloaded."""
  bundle = pathlib.Path(certifi.where())
  try:
    data = bundle.read_bytes()
  except OSError as exc:
    raise TlscheckError(f'could not read certifi bundle: {exc}') from exc
  # A few historical Mozilla roots have a zero or negative serial.
  # cryptography still loads them and warns that a future release will not.
  with warnings.catch_warnings():
    warnings.filterwarnings(
        'ignore',
        message="Parsed a serial number which wasn't positive",
        category=CryptographyDeprecationWarning)
    certificates = load_certificates(data)
  return TrustStore(certificates, f'certifi {certifi.__version__}')


class PathResult:
  """One built path: presented-only, or presented plus AIA fetches."""

  def __init__(self, ok: bool, chain: list, reason: str, retrieved: list):
    self.ok = ok
    self.chain = chain
    self.reason = reason
    self.retrieved = retrieved

  @property
  def status(self) -> str:
    return 'pass' if self.ok else 'fail'


def _subject_for(name: str):
  try:
    address = ipaddress.ip_address(name.strip().rstrip('.'))
  except ValueError:
    return DNSName(a_label(name))
  return IPAddress(address)


def _is_name_failure(message: str) -> bool:
  text = message.lower()
  return 'subjectaltname' in text


def _verify(leaf, intermediates, store, subject, when):
  builder = PolicyBuilder().store(store).time(when)
  verifier = builder.build_server_verifier(subject)
  return list(verifier.verify(leaf, intermediates))


def _probe_subjects(leaf: x509.Certificate) -> list:
  """Names taken from the leaf, used only to ask the verifier for a path.

  Hostname acceptance is decided separately. A wildcard SAN is probed with
  one concrete label so the library can return the chain it already built.
  """
  san = extension(leaf, x509.SubjectAlternativeName)
  if san is None:
    return []
  subjects = []
  for pattern in san.value.get_values_for_type(x509.DNSName):
    try:
      encoded = a_label(pattern)
    except TlscheckError:
      continue
    parts = encoded.split('.')
    if parts[0] == '*' and encoded.count('*') == 1 and len(parts) >= 3:
      encoded = '.'.join(['a'] + parts[1:])
    elif '*' in encoded:
      continue
    try:
      subjects.append(DNSName(encoded))
    except ValueError:
      continue
  for address in san.value.get_values_for_type(x509.IPAddress):
    subjects.append(IPAddress(address))
  return subjects


def _walk(leaf, pool, anchor_spkis) -> list:
  """Leaf-first AKI/SKI walk, for the report when the verifier has no chain."""
  chain = [leaf]
  current = leaf
  seen = {fingerprint_sha256(leaf)}
  for _ in range(8):
    if current is not leaf and spki_der(current) in anchor_spkis:
      break
    issuer = find_issuer(
        current, [cert for cert in pool if fingerprint_sha256(cert) not in seen])
    if issuer is None:
      break
    chain.append(issuer)
    seen.add(fingerprint_sha256(issuer))
    current = issuer
    if spki_der(issuer) in anchor_spkis:
      break
  return chain


def _intermediates(leaf, extras, anchor_spkis) -> list:
  """Bag entries that are not the leaf and not a trust-anchor SPKI."""
  intermediates = []
  seen = {fingerprint_sha256(leaf)}
  for cert in extras:
    digest = fingerprint_sha256(cert)
    if digest in seen:
      continue
    seen.add(digest)
    if spki_der(cert) in anchor_spkis:
      continue
    intermediates.append(cert)
  return intermediates


def build_path(leaf: x509.Certificate, extras: list, trust: TrustStore,
               name: str, when: datetime.datetime) -> PathResult:
  """Validate leaf against trust using only extras plus the store."""
  anchor_spkis = trust.anchor_spkis()
  store = Store(trust.certificates)
  intermediates = _intermediates(leaf, extras, anchor_spkis)
  pool = list(extras) + list(trust.certificates)
  try:
    subject = _subject_for(name)
  except (ValueError, TlscheckError) as exc:
    raise TlscheckError(f'invalid name {name!r}: {exc}') from exc
  try:
    chain = _verify(leaf, intermediates, store, subject, when)
  except VerificationError as exc:
    message = str(exc)
    if _is_name_failure(message):
      for subject in _probe_subjects(leaf):
        try:
          chain = _verify(leaf, intermediates, store, subject, when)
        except VerificationError as retry_exc:
          if _is_name_failure(str(retry_exc)):
            continue
          partial = _walk(leaf, pool, anchor_spkis)
          return PathResult(False, partial, str(retry_exc), [])
        return PathResult(
            True, chain,
            'path is valid; the hostname is checked on its own', [])
      partial = _walk(leaf, pool, anchor_spkis)
      if partial and spki_der(partial[-1]) in anchor_spkis:
        return PathResult(
            True, partial,
            'path reaches a trust anchor; the hostname is checked on its own',
            [])
    partial = _walk(leaf, pool, anchor_spkis)
    return PathResult(False, partial or [leaf], message, [])
  return PathResult(True, chain, 'certificate path is valid', [])


def _fetch_issuers(leaf, pool, anchor_spkis, seen_urls, fetcher) -> list:
  found = []
  urls = []
  for cert in [leaf] + list(pool):
    if spki_der(cert) in anchor_spkis:
      continue
    for url in ca_issuer_urls(cert):
      if url not in seen_urls:
        urls.append(url)
  for url in urls:
    seen_urls.add(url)
    response = fetcher(url, method='GET', body=None, content_type=None)
    if not isinstance(response, FetchResponse):
      response = FetchResponse(unanswered=True, note='fetcher returned nothing')
    if response.unanswered or not response.body:
      continue
    try:
      certificates = load_certificates(response.body)
    except TlscheckError:
      continue
    known = {fingerprint_sha256(cert) for cert in [leaf] + list(pool) + found}
    for cert in certificates[:10]:
      if fingerprint_sha256(cert) in known:
        continue
      found.append(cert)
      known.add(fingerprint_sha256(cert))
      if len(found) >= _MAX_RETRIEVED:
        return found
  return found


def build_presented_and_fetched(leaf: x509.Certificate, extras: list,
                                trust: TrustStore, name: str,
                                when: datetime.datetime,
                                fetcher=None) -> tuple:
  """Return (presented, fetched) path results.

  presented uses only certificates the caller supplied. fetched may GET
  caIssuers URLs when that path does not validate. fetcher defaults to
  fetch_url. A test passes its own function with the same signature.
  """
  if fetcher is None:
    fetcher = fetch_url
  presented = build_path(leaf, extras, trust, name, when)
  if presented.ok:
    fetched = PathResult(
        True, presented.chain,
        'presented path is valid; no certificates were fetched', [])
    return presented, fetched
  pool = list(extras)
  retrieved = []
  seen_urls = set()
  outcome = presented
  for _ in range(_MAX_FETCHES):
    added = _fetch_issuers(
        leaf, pool, trust.anchor_spkis(), seen_urls, fetcher)
    if not added:
      break
    pool.extend(added)
    retrieved.extend(added)
    outcome = build_path(leaf, pool, trust, name, when)
    if outcome.ok:
      break
    if len(retrieved) >= _MAX_RETRIEVED:
      break
  if outcome.ok:
    reason = 'path is valid using retrieved intermediate certificates'
  elif not retrieved:
    reason = outcome.reason + '; no caIssuers certificate was retrieved'
  else:
    reason = outcome.reason
  fetched = PathResult(outcome.ok, outcome.chain, reason, retrieved)
  return presented, fetched
