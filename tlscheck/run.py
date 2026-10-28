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
"""Run the path, profile, hostname, pin, and revocation checks."""

import datetime

from tlscheck.certs import check_eku
from tlscheck.certs import hostname_matches
from tlscheck.certs import check_lifetime
from tlscheck.certs import check_pins
from tlscheck.certs import check_public_keys
from tlscheck.certs import check_signatures
from tlscheck.certs import check_validity
from tlscheck.certs import find_issuer
from tlscheck.certs import fingerprint_sha256
from tlscheck.certs import normalize_pin
from tlscheck.certs import spki_der
from tlscheck.errors import TlscheckError
from tlscheck.fetch import fetch_url
from tlscheck.path import build_presented_and_fetched
from tlscheck.report import Check
from tlscheck.report import Report
from tlscheck.revoke import check_revocation

_OCSP_MODES = ('staple', 'fetch', 'off')
_CRL_MODES = ('off', 'fetch')


def _profile_certs(leaf, chain, bag, anchor_spkis) -> list:
  """Certificates the public profile and pins apply to.

  When the chain reaches a trust anchor, only that path is used and the
  anchor itself is skipped. Otherwise every non-anchor certificate in the
  bag is used, so a weak leaf is still reported when the path stops early.
  """
  if (chain and spki_der(chain[-1]) in anchor_spkis and chain[-1] is not leaf):
    return [cert for cert in chain if spki_der(cert) not in anchor_spkis]
  seen = set()
  chosen = []
  for cert in [leaf] + list(bag):
    digest = fingerprint_sha256(cert)
    if digest in seen:
      continue
    seen.add(digest)
    if spki_der(cert) in anchor_spkis:
      continue
    chosen.append(cert)
  return chosen or [leaf]


def _check(name: str, result: tuple) -> Check:
  status, reason = result
  return Check(name, status, reason)


def run_check(certificates: list, host: str, trust, port: int = 443,
              name: str = None, when: datetime.datetime = None,
              ocsp_mode: str = 'staple', crl_mode: str = 'off',
              staple: bytes = None, pins: list = None,
              allow_fetched: bool = False, fetcher=None,
              peer_ip: str = None, peer_port: int = None,
              tls_version: str = None, sni: str = None) -> Report:
  """Check a presented certificate list. The first certificate is the leaf.

  trust is a TrustStore. Tests pass a store that contains only their own
  root. The CLI passes the Mozilla bundle from certifi.
  """
  if not certificates:
    raise TlscheckError('no certificates to check')
  if ocsp_mode not in _OCSP_MODES:
    raise TlscheckError(f'unknown --ocsp mode {ocsp_mode!r}')
  if crl_mode not in _CRL_MODES:
    raise TlscheckError(f'unknown --crl mode {crl_mode!r}')
  expected = name or host
  if not expected:
    raise TlscheckError('a hostname or --name is required')
  pins = list(pins or [])
  for pin in pins:
    normalize_pin(pin)
  if fetcher is None:
    fetcher = fetch_url
  if when is None:
    when = datetime.datetime.now(datetime.timezone.utc)
  elif when.tzinfo is None:
    when = when.replace(tzinfo=datetime.timezone.utc)
  else:
    when = when.astimezone(datetime.timezone.utc)

  leaf = certificates[0]
  extras = list(certificates[1:])
  anchor_spkis = trust.anchor_spkis()
  presented, fetched = build_presented_and_fetched(
      leaf, extras, trust, expected, when, fetcher=fetcher)

  if allow_fetched:
    chosen = fetched
    bag = extras + list(fetched.retrieved)
  else:
    chosen = presented
    bag = extras
  profile_certs = _profile_certs(leaf, chosen.chain, bag, anchor_spkis)

  issuer_pool = list(chosen.chain[1:]) + extras + list(fetched.retrieved)
  issuer_pool.extend(trust.certificates)
  issuer = find_issuer(leaf, issuer_pool)

  checks = [
      _check('presented', (presented.status, presented.reason)),
      _check('fetched', (fetched.status, fetched.reason)),
      _check('eku', check_eku(leaf)),
      _check('signature', check_signatures(profile_certs, anchor_spkis)),
      _check('public_key', check_public_keys(profile_certs, anchor_spkis)),
      _check('validity', check_validity(leaf, when)),
      _check('lifetime', check_lifetime(leaf)),
      _check('hostname', hostname_matches(expected, leaf)),
      _check('revocation', check_revocation(
          leaf, issuer, staple, ocsp_mode, crl_mode, when,
          issuer_pool, fetcher)),
      _check('pin', check_pins(pins, profile_certs, anchor_spkis)),
  ]
  return Report(
      host=host,
      port=port,
      name=expected,
      peer_ip=peer_ip,
      peer_port=peer_port,
      tls_version=tls_version,
      sni=sni,
      bundle_id=trust.bundle_id,
      leaf=leaf,
      presented=list(certificates),
      presented_path=presented,
      fetched_path=fetched,
      checks=checks,
      anchor_spkis=anchor_spkis,
      allow_fetched=allow_fetched)
