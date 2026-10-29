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

from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import paranoid

try:
  from tlscheck.capture import capture_tls
  from tlscheck.errors import TlscheckError
  from tlscheck.path import mozilla_trust_store
  from tlscheck.report import render_json
  from tlscheck.run import run_check
  _TLSCHECK_AVAILABLE = True
except ImportError:  # optional dependency
  capture_tls = None
  TlscheckError = Exception
  mozilla_trust_store = None
  render_json = None
  run_check = None
  _TLSCHECK_AVAILABLE = False

from witness.hostscan import scan_apps as scan_installed_apps
from witness.hostscan import scan_browsers as scan_installed_browsers
from witness.material import KeyMaterial
from witness.report import WitnessReport
from witness.report import compute_overall_status
from witness.report import curve_label
from witness.report import key_artifact_dict
from witness.scan import SourceRead
from witness.scan import collect_sources
from witness.scan import parse_sources


def _bastion_version() -> str:
  try:
    return version('paranoid_crypto')
  except PackageNotFoundError:
    version_path = Path(__file__).resolve().parents[1] / 'paranoid_crypto' / 'VERSION'
    return version_path.read_text(encoding='utf-8').strip()


def check_public_keys(items: list[KeyMaterial]) -> list[dict]:
  """Run CheckAllRSA / CheckAllEC once across every public key."""
  cloned: list[tuple[KeyMaterial, object]] = []
  rsa_keys = []
  ec_keys = []
  for item in items:
    key = copy.deepcopy(item.key)
    cloned.append((item, key))
    if isinstance(key, paranoid_pb2.RSAKey):
      rsa_keys.append(key)
    elif isinstance(key, paranoid_pb2.ECKey):
      ec_keys.append(key)
  if rsa_keys:
    paranoid.CheckAllRSA(rsa_keys)
  if ec_keys:
    paranoid.CheckAllEC(ec_keys)

  artifacts = []
  for item, key in cloned:
    if isinstance(key, paranoid_pb2.RSAKey):
      type_name = 'RSA'
    elif isinstance(key, paranoid_pb2.ECKey):
      type_name = f'EC ({curve_label(key.ec_info.curve_type)})'
    else:
      continue
    artifacts.append(key_artifact_dict(
        key,
        type_name,
        path=item.path or None,
        group=item.group,
        subject=item.subject,
        section=item.section))
  artifacts.sort(key=lambda item: (
      not item['weak'],
      item.get('group') or '',
      item.get('path') or '',
      item['fingerprint_sha256'],
  ))
  return artifacts


def _ssh_material(reads: list[SourceRead]) -> tuple[list[dict], list[KeyMaterial], list[dict]]:
  sources = []
  items = []
  unsupported = []
  for read in reads:
    parsed_sources, merged = parse_sources([read])
    sources.append(parsed_sources[0])
    for key in list(merged.rsa_keys) + list(merged.ec_keys):
      items.append(KeyMaterial('ssh', 'SSH', read.path, None, key))
    for item in merged.unsupported:
      unsupported.append({
          'path': read.path,
          'line_number': item.line_number,
          'key_type': item.key_type,
      })
  return sources, items, unsupported


def _empty_local_section() -> dict:
  return {
      'requested': False,
      'discovered': [],
      'none_found': False,
      'packages': None,
      'roots': [],
      'keys': [],
      'skipped': [],
      'unreadable': [],
      'private_skipped': [],
      'unsupported': [],
      'notes': [],
      'truncated': False,
      'files_read': 0,
      'weak_count': 0,
      'key_count': 0,
  }


def _local_section(raw: dict, artifacts: list[dict], requested: bool) -> dict:
  section = _empty_local_section()
  section.update({
      'requested': requested,
      'discovered': raw.get('discovered') or [],
      'none_found': bool(raw.get('none_found')),
      'packages': raw.get('packages'),
      'roots': raw.get('roots') or [],
      'keys': artifacts,
      'skipped': raw.get('skipped') or [],
      'unreadable': raw.get('unreadable') or [],
      'private_skipped': raw.get('private_skipped') or [],
      'unsupported': raw.get('unsupported') or [],
      'notes': raw.get('notes') or [],
      'truncated': bool(raw.get('truncated')),
      'files_read': raw.get('files_read') or 0,
      'weak_count': sum(1 for key in artifacts if key['weak']),
      'key_count': len(artifacts),
  })
  return section


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
  if not _TLSCHECK_AVAILABLE:
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
    scan_browsers: bool = True,
    scan_apps: bool = True,
    browser_roots: list[dict] | None = None,
    discover_default_browsers: bool = True,
    app_roots: list[tuple[str, int]] | None = None,
    system_bundle_path: str | None = None,
    user_ca_dir: str | None = None,
    include_nss: bool = True,
    bundle_cert_cap: int = 25,
) -> dict:
  """Run SSH, browser, app, and optional TLS witness checks on this machine."""
  ssh_requested = bool(scan_home_ssh or include_etc_ssh or ssh_paths)
  ssh_items: list[KeyMaterial] = []
  ssh_sources: list[dict] = []
  ssh_unsupported: list[dict] = []
  if ssh_requested:
    reads = collect_sources(
        scan_home_ssh=scan_home_ssh,
        extra_paths=ssh_paths,
        include_etc_ssh=include_etc_ssh)
    ssh_sources, ssh_items, ssh_unsupported = _ssh_material(reads)

  seen: set[str] = set()
  browser_raw = None
  if scan_browsers:
    browser_raw = scan_installed_browsers(
        extra_roots=browser_roots,
        discover_defaults=discover_default_browsers,
        system_bundle_path=system_bundle_path,
        user_ca_dir=user_ca_dir,
        include_nss=include_nss,
        seen=seen,
        bundle_cert_cap=bundle_cert_cap)
  app_raw = None
  if scan_apps:
    app_raw = scan_installed_apps(
        roots=app_roots,
        seen=seen,
        system_bundle_path=system_bundle_path,
        note_skipped_system_certs=not scan_browsers,
        bundle_cert_cap=bundle_cert_cap)

  combined = list(ssh_items)
  if browser_raw:
    combined.extend(browser_raw.get('keys') or [])
  if app_raw:
    combined.extend(app_raw.get('keys') or [])
  artifacts = check_public_keys(combined)

  def _for(section: str) -> list[dict]:
    return [item for item in artifacts if item.get('section') == section]

  ssh_keys = _for('ssh')
  browser_keys = _for('browsers')
  app_keys = _for('apps')

  ssh_section = {
      'requested': ssh_requested,
      'sources': ssh_sources,
      'keys': ssh_keys,
      'unsupported': ssh_unsupported,
      'weak_count': sum(1 for key in ssh_keys if key['weak']),
      'key_count': len(ssh_keys),
  }
  browsers = (_local_section(browser_raw, browser_keys, True)
              if browser_raw is not None else _empty_local_section())
  apps = (_local_section(app_raw, app_keys, True)
          if app_raw is not None else _empty_local_section())

  ssh_unreadable = any(source['status'] == 'unreadable' for source in ssh_sources)
  other_unreadable = bool(browsers['unreadable'] or apps['unreadable'])
  ssh_weak = any(key['weak'] for key in ssh_keys)
  other_weak = any(key['weak'] for key in browser_keys + app_keys)

  tls = _run_tls(tls_host, tls_port)
  tls_exit = tls.get('exit_code')
  tls_requested = bool(tls_host and str(tls_host).strip())
  status = compute_overall_status(
      ssh_weak,
      ssh_unreadable,
      tls_exit,
      tls_requested,
      other_weak=other_weak,
      other_unreadable=other_unreadable)

  now = datetime.datetime.now(datetime.timezone.utc).isoformat()
  report = WitnessReport(
      machine_hostname=socket.gethostname(),
      timestamp=now,
      bastion_version=_bastion_version(),
      ssh=ssh_section,
      tls=tls,
      browsers=browsers,
      apps=apps,
      overall_status=status)
  return report.to_dict()


def witness_ssh_file(path: str, text: str, kind: str = 'authorized_keys') -> dict:
  """Run witness checks on in-memory SSH file contents (for tests)."""
  read = SourceRead(path, kind, 'ok', None, text)
  sources, merged = parse_sources([read])
  items = [
      KeyMaterial('ssh', 'SSH', path, None, key)
      for key in list(merged.rsa_keys) + list(merged.ec_keys)
  ]
  artifacts = check_public_keys(items)
  return {
      'sources': sources,
      'keys': artifacts,
      'weak_count': sum(1 for key in artifacts if key['weak']),
      'ssh_weak': any(key['weak'] for key in artifacts),
  }
