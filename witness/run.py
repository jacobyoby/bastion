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
"""Run witness checks and build a report."""

import copy
import datetime
import socket
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from paranoid_crypto.lib import paranoid

from witness.report import WitnessReport
from witness.report import compute_overall_status
from witness.report import key_artifact_dict
from witness.scan import collect_sources
from witness.scan import parse_sources


def _bastion_version() -> str:
  try:
    return version('paranoid_crypto')
  except PackageNotFoundError:
    version_path = Path(__file__).resolve().parents[1] / 'paranoid_crypto' / 'VERSION'
    return version_path.read_text(encoding='utf-8').strip()


def _run_ssh_checks(merged) -> tuple[list[dict], bool]:
  rsa_keys = [copy.deepcopy(key) for key in merged.rsa_keys]
  ec_keys = [copy.deepcopy(key) for key in merged.ec_keys]
  if rsa_keys:
    paranoid.CheckAllRSA(rsa_keys)
  if ec_keys:
    paranoid.CheckAllEC(ec_keys)

  artifacts = []
  ssh_weak = False
  for key in rsa_keys:
    artifacts.append(key_artifact_dict(key, 'RSA'))
    ssh_weak |= key.test_info.weak
  for key in ec_keys:
    curve = key.ec_info.curve_type
    artifacts.append(key_artifact_dict(key, f'EC ({curve})'))
    ssh_weak |= key.test_info.weak
  artifacts.sort(key=lambda item: item['fingerprint_sha256'])
  return artifacts, ssh_weak


def _run_tls(tls_host: str | None, tls_port: int) -> dict:
  if not tls_host or not tls_host.strip():
    return {
        'requested': False,
        'skipped': True,
        'message': 'No TLS hostname supplied.',
        'exit_code': None,
        'report': None,
    }
  host = tls_host.strip()
  try:
    from tlscheck.capture import capture_tls
    from tlscheck.errors import TlscheckError
    from tlscheck.path import mozilla_trust_store
    from tlscheck.report import render_json
    from tlscheck.run import run_check
  except ImportError:
    return {
        'requested': True,
        'skipped': True,
        'message': ('tlscheck is not installed in this environment; '
                    'TLS witness was skipped.'),
        'exit_code': None,
        'report': None,
        'host': host,
        'port': tls_port,
    }

  try:
    trust = mozilla_trust_store()
    captured = capture_tls(host, tls_port, sni=None, ip=None)
    report = run_check(
        captured.certificates,
        host=host,
        trust=trust,
        port=tls_port,
        name=None,
        when=None,
        ocsp_mode='staple',
        crl_mode='off',
        staple=captured.staple,
        pins=None,
        allow_fetched=False,
        peer_ip=captured.peer_ip,
        peer_port=captured.peer_port,
        tls_version=captured.tls_version,
        sni=captured.sni)
    return {
        'requested': True,
        'skipped': False,
        'message': None,
        'exit_code': report.exit_code,
        'host': host,
        'port': tls_port,
        'report': report.to_dict(),
        'report_json': render_json(report),
    }
  except TlscheckError as exc:
    return {
        'requested': True,
        'skipped': False,
        'message': str(exc),
        'exit_code': exc.exit_code,
        'host': host,
        'port': tls_port,
        'report': None,
    }


def witness_machine(
    ssh_paths: list[str] | None = None,
    scan_home_ssh: bool = True,
    tls_host: str | None = None,
    tls_port: int = 443,
    include_etc_ssh: bool = True,
) -> dict:
  """Run SSH and optional TLS witness checks on this machine."""
  reads = collect_sources(
      scan_home_ssh=scan_home_ssh,
      extra_paths=ssh_paths,
      include_etc_ssh=include_etc_ssh)
  sources, merged = parse_sources(reads)
  artifacts, ssh_weak = _run_ssh_checks(merged)

  unsupported = [
      {'line_number': item.line_number, 'key_type': item.key_type}
      for item in merged.unsupported
  ]

  ssh_unreadable = any(source['status'] == 'unreadable' for source in sources)
  tls = _run_tls(tls_host, tls_port)
  tls_exit = tls.get('exit_code')
  tls_requested = bool(tls_host and tls_host.strip())

  status = compute_overall_status(
      ssh_weak, ssh_unreadable, tls_exit, tls_requested)

  now = datetime.datetime.now(datetime.timezone.utc).isoformat()
  ssh_section = {
      'sources': sources,
      'keys': artifacts,
      'unsupported': unsupported,
      'weak_count': sum(1 for key in artifacts if key['weak']),
      'key_count': len(artifacts),
  }

  report = WitnessReport(
      machine_hostname=socket.gethostname(),
      timestamp=now,
      bastion_version=_bastion_version(),
      ssh=ssh_section,
      tls=tls,
      overall_status=status)
  return report.to_dict()


def witness_ssh_file(path: str, text: str, kind: str = 'authorized_keys') -> dict:
  """Run witness checks on in-memory SSH file contents (for tests)."""
  from witness.scan import SourceRead
  from witness.scan import parse_sources

  read = SourceRead(path, kind, 'ok', None, text)
  sources, merged = parse_sources([read])
  artifacts, ssh_weak = _run_ssh_checks(merged)
  return {
      'sources': sources,
      'keys': artifacts,
      'weak_count': sum(1 for key in artifacts if key['weak']),
      'ssh_weak': ssh_weak,
  }
