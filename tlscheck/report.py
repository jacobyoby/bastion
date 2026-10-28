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
"""Text and JSON reports."""

import json

from tlscheck import __version__
from tlscheck.certs import cert_not_after
from tlscheck.certs import cert_not_before
from tlscheck.certs import fingerprint_sha256
from tlscheck.certs import spki_der
from tlscheck.certs import spki_sha256
from tlscheck.certs import subject_text


class Check:
  """One pass, fail, or skipped result."""

  def __init__(self, name: str, status: str, reason: str):
    self.name = name
    self.status = status
    self.reason = reason

  def to_dict(self) -> dict:
    return {'name': self.name, 'status': self.status, 'reason': self.reason}


def _cert_dict(cert, source: str) -> dict:
  return {
      'subject': subject_text(cert),
      'issuer': cert.issuer.rfc4514_string(),
      'fingerprint_sha256': fingerprint_sha256(cert),
      'spki_sha256': spki_sha256(cert),
      'not_before': cert_not_before(cert).isoformat(),
      'not_after': cert_not_after(cert).isoformat(),
      'serial': format(cert.serial_number, 'x'),
      'source': source,
  }


def _source(cert, presented_fps: set, retrieved_fps: set,
            anchor_spkis: set) -> str:
  digest = fingerprint_sha256(cert)
  if digest in presented_fps:
    return 'presented'
  if digest in retrieved_fps:
    return 'retrieved'
  if spki_der(cert) in anchor_spkis:
    return 'trust-anchor'
  return 'unknown'


class Report:
  """The full result of one run."""

  def __init__(self, host: str, port: int, name: str, peer_ip, peer_port,
               tls_version, sni: str, bundle_id: str, leaf, presented: list,
               presented_path, fetched_path, checks: list,
               anchor_spkis: set, allow_fetched: bool):
    self.host = host
    self.port = port
    self.name = name
    self.peer_ip = peer_ip
    self.peer_port = peer_port
    self.tls_version = tls_version
    self.sni = sni
    self.bundle_id = bundle_id
    self.leaf = leaf
    self.presented = presented
    self.presented_path = presented_path
    self.fetched_path = fetched_path
    self.checks = checks
    self.anchor_spkis = anchor_spkis
    self.allow_fetched = allow_fetched
    self._by_name = {check.name: check for check in checks}
    self.exit_code = exit_code_for(checks, allow_fetched)

  def check(self, name: str) -> Check:
    return self._by_name[name]

  def chain_dicts(self, path, retrieved_fps: set) -> list:
    presented_fps = {fingerprint_sha256(cert) for cert in self.presented}
    return [
        _cert_dict(
            cert,
            _source(cert, presented_fps, retrieved_fps, self.anchor_spkis))
        for cert in path.chain
    ]

  def to_dict(self) -> dict:
    retrieved_fps = {
        fingerprint_sha256(cert) for cert in self.fetched_path.retrieved}
    presented_fps = {fingerprint_sha256(cert) for cert in self.presented}
    return {
        'version': __version__,
        'host': self.host,
        'port': self.port,
        'name': self.name,
        'peer_ip': self.peer_ip,
        'peer_port': self.peer_port,
        'tls_version': self.tls_version,
        'sni': self.sni,
        'bundle_id': self.bundle_id,
        'leaf': _cert_dict(self.leaf, 'presented'),
        'presented_certificates': [
            _cert_dict(cert, 'presented') for cert in self.presented
        ],
        'chains': {
            'presented': {
                'status': self.presented_path.status,
                'reason': self.presented_path.reason,
                'certificates': self.chain_dicts(
                    self.presented_path, retrieved_fps),
            },
            'fetched': {
                'status': self.fetched_path.status,
                'reason': self.fetched_path.reason,
                'certificates': self.chain_dicts(
                    self.fetched_path, retrieved_fps),
            },
        },
        'checks': [check.to_dict() for check in self.checks],
        'exit_code': self.exit_code,
        'presented_fingerprints': sorted(presented_fps),
    }


def exit_code_for(checks: list, allow_fetched: bool) -> int:
  """Exit 1 when a required check failed. Skipped checks do not fail."""
  by_name = {check.name: check for check in checks}
  path_name = 'fetched' if allow_fetched else 'presented'
  if by_name[path_name].status != 'pass':
    return 1
  for name in (
      'eku', 'signature', 'public_key', 'validity', 'lifetime', 'hostname'):
    if by_name[name].status != 'pass':
      return 1
  if by_name['pin'].status == 'fail':
    return 1
  if by_name['revocation'].status == 'fail':
    return 1
  return 0


def _format_chain(certs: list) -> list:
  lines = []
  for index, cert in enumerate(certs):
    lines.append(f'  {index} {cert["source"]:12} {cert["subject"]}')
  return lines


def render_text(report: Report) -> str:
  """Human-readable report. The same facts are in the JSON object."""
  leaf = report.leaf
  retrieved_fps = {
      fingerprint_sha256(cert) for cert in report.fetched_path.retrieved}
  presented_chain = report.chain_dicts(report.presented_path, retrieved_fps)
  fetched_chain = report.chain_dicts(report.fetched_path, retrieved_fps)
  lines = [
      f'tlscheck {__version__} (alpha)',
      f'host: {report.host}:{report.port}',
      f'name: {report.name}',
      f'peer: {report.peer_ip or "-"}:{report.peer_port if report.peer_port is not None else "-"}',
      f'tls: {report.tls_version or "-"}',
      f'sni: {report.sni or "-"}',
      f'bundle: {report.bundle_id}',
      '',
      f'leaf: {subject_text(leaf)}',
      f'fingerprint_sha256: {fingerprint_sha256(leaf)}',
      f'not_after: {cert_not_after(leaf).isoformat()}',
      '',
      'presented certificates:',
  ]
  for index, cert in enumerate(report.presented):
    lines.append(f'  {index} presented    {subject_text(cert)}')
  lines.append('')
  lines.append(f'presented path: {report.presented_path.status}')
  lines.extend(_format_chain(presented_chain))
  lines.append(f'  {report.presented_path.reason}')
  lines.append(f'fetched path: {report.fetched_path.status}')
  lines.extend(_format_chain(fetched_chain))
  lines.append(f'  {report.fetched_path.reason}')
  lines.append('')
  lines.append('checks:')
  for check in report.checks:
    lines.append(f'  {check.name:18} {check.status:7} {check.reason}')
  lines.append('')
  lines.append(f'exit: {report.exit_code}')
  return '\n'.join(lines)


def render_json(report: Report) -> str:
  return json.dumps(report.to_dict(), indent=2)
