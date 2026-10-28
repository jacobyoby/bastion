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
"""Witness report structure and friendly labels."""

import base64
from typing import Any

from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import util

from witness import __version__

OverallStatus = str  # confirmed | needs_attention | incomplete

_SEVERITY_LABELS = {
    paranoid_pb2.SeverityType.SEVERITY_CRITICAL: 'Critical',
    paranoid_pb2.SeverityType.SEVERITY_HIGH: 'High',
    paranoid_pb2.SeverityType.SEVERITY_MEDIUM: 'Medium',
    paranoid_pb2.SeverityType.SEVERITY_LOW: 'Low',
    paranoid_pb2.SeverityType.SEVERITY_UNKNOWN: 'Unknown',
}

_CHECK_BLURBS = {
    'CheckFermat': 'RSA modulus may factor via Fermat’s method (weak generation).',
    'CheckGCD': 'RSA modulus shares a prime factor with another key.',
    'CheckROCA': 'RSA key may be affected by the Infineon ROCA vulnerability.',
    'CheckOpensslDenylist': 'RSA key matches a known weak OpenSSL/Debian pattern.',
    'CheckKnownPrimes': 'RSA modulus contains a prime seen in earlier scans.',
    'CheckSizes': 'RSA modulus size or shape is out of policy.',
    'CheckSmallUpperDifferences': 'RSA prime factors are unusually close.',
    'CheckLowHammingWeight': 'RSA modulus has suspiciously low Hamming weight.',
    'CheckKeypairDenylist': 'RSA key matches a published weak keypair.',
    'CheckShortSleeveRSA': 'RSA key matches a short-sleeve generation pattern.',
    'CheckUnseededRand': 'RSA key may come from an improperly seeded generator.',
    'CheckECInvalidCurve': 'EC point is not on the declared curve.',
    'CheckECWeakPrivateScalar': 'EC key may come from a weak private scalar.',
}


def severity_label(severity: int) -> str:
  return _SEVERITY_LABELS.get(severity, 'Unknown')


def check_blurb(name: str) -> str:
  return _CHECK_BLURBS.get(name, 'Bastion cryptographic check.')


def fingerprint_display(digest: bytes) -> str:
  """OpenSSH-style SHA256 fingerprint (no SHA256: prefix)."""
  return base64.b64encode(digest).decode().rstrip('=')


def _check_rows(test_info: paranoid_pb2.TestInfo) -> list[dict]:
  rows = []
  for entry in test_info.test_results:
    rows.append({
        'name': entry.test_name,
        'failed': bool(entry.result),
        'severity': severity_label(entry.severity),
        'blurb': check_blurb(entry.test_name),
    })
  rows.sort(key=lambda row: row['name'])
  return rows


def key_artifact_dict(key, key_type: str) -> dict:
  fp = fingerprint_display(key.origin_info.fingerprint)
  return {
      'type': key_type,
      'fingerprint_sha256': fp,
      'weak': bool(key.test_info.weak),
      'checks': _check_rows(key.test_info),
  }


def overall_summary(status: OverallStatus) -> str:
  if status == 'confirmed':
    return ('Confirmed — no weak SSH keys were found and optional TLS checks '
            'did not report failures.')
  if status == 'needs_attention':
    return ('Needs attention — at least one SSH key or TLS check failed '
            'Bastion’s witness checks.')
  return ('Incomplete — some paths could not be read or TLS could not '
          'complete; review details below.')


class WitnessReport:
  """Structured witness result."""

  def __init__(self, machine_hostname: str, timestamp: str, bastion_version: str,
               ssh: dict, tls: dict, overall_status: OverallStatus):
    self.machine_hostname = machine_hostname
    self.timestamp = timestamp
    self.bastion_version = bastion_version
    self.witness_version = __version__
    self.ssh = ssh
    self.tls = tls
    self.overall_status = overall_status

  def to_dict(self) -> dict[str, Any]:
    return {
        'machine_hostname': self.machine_hostname,
        'timestamp': self.timestamp,
        'bastion_version': self.bastion_version,
        'witness_version': self.witness_version,
        'overall_status': self.overall_status,
        'overall_summary': overall_summary(self.overall_status),
        'ssh': self.ssh,
        'tls': self.tls,
    }


def compute_overall_status(ssh_weak: bool, ssh_unreadable: bool,
                           tls_exit_code: int | None,
                           tls_requested: bool) -> OverallStatus:
  if ssh_weak or tls_exit_code == 1:
    return 'needs_attention'
  if ssh_unreadable or tls_exit_code == 2:
    return 'incomplete'
  if tls_requested and tls_exit_code is None:
    return 'incomplete'
  return 'confirmed'
