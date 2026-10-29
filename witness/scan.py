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
"""Discover and read SSH public-key sources on this machine."""

import glob
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from paranoid_crypto.lib import ssh_keys

ParseKind = Literal['authorized_keys', 'known_hosts']
SourceStatus = Literal['ok', 'missing', 'unreadable']


@dataclass(frozen=True)
class SourceRead:
  path: str
  kind: ParseKind
  status: SourceStatus
  error: str | None
  text: str | None


def _home_ssh_paths() -> list[tuple[str, ParseKind]]:
  home = Path.home()
  return [
      (str(home / '.ssh' / 'authorized_keys'), 'authorized_keys'),
      (str(home / '.ssh' / 'known_hosts'), 'known_hosts'),
  ]


def _etc_ssh_pub_paths() -> list[tuple[str, ParseKind]]:
  paths = []
  for path in sorted(glob.glob('/etc/ssh/*.pub')):
    paths.append((path, 'authorized_keys'))
  return paths


def _guess_kind(path: str) -> ParseKind:
  base = os.path.basename(path)
  if base == 'known_hosts' or base.endswith('_known_hosts'):
    return 'known_hosts'
  return 'authorized_keys'


def read_source(path: str, kind: ParseKind | None = None) -> SourceRead:
  """Read one path; missing and permission errors are non-fatal."""
  kind = kind or _guess_kind(path)
  if not os.path.exists(path):
    return SourceRead(path, kind, 'missing', None, None)
  try:
    with open(path, encoding='utf-8', errors='replace') as handle:
      text = handle.read()
  except OSError as exc:
    return SourceRead(path, kind, 'unreadable', str(exc), None)
  return SourceRead(path, kind, 'ok', None, text)


def collect_sources(
    scan_home_ssh: bool = True,
    extra_paths: list[str] | None = None,
    include_etc_ssh: bool = True,
    max_extra: int = 32,
) -> list[SourceRead]:
  """Return ordered source reads for witness."""
  seen: set[str] = set()
  ordered: list[tuple[str, ParseKind | None]] = []

  if scan_home_ssh:
    ordered.extend(_home_ssh_paths())
  if include_etc_ssh:
    ordered.extend(_etc_ssh_pub_paths())
  for raw in (extra_paths or [])[:max_extra]:
    path = raw.strip()
    if not path or path in seen:
      continue
    ordered.append((path, None))

  reads: list[SourceRead] = []
  for path, kind in ordered:
    if path in seen:
      continue
    seen.add(path)
    reads.append(read_source(path, kind))
  return reads


def parse_sources(reads: list[SourceRead]) -> tuple[list[dict], ssh_keys.SshKeys]:
  """Parse reads into a merged SshKeys bundle and per-source metadata."""
  merged = ssh_keys.SshKeys([], [], [])
  sources: list[dict] = []

  for read in reads:
    entry = {
        'path': read.path,
        'kind': read.kind,
        'status': read.status,
        'error': read.error,
        'rsa_count': 0,
        'ec_count': 0,
        'unsupported_count': 0,
        'parse_error': None,
    }
    if read.status != 'ok' or read.text is None:
      sources.append(entry)
      continue
    try:
      if read.kind == 'known_hosts':
        keys = ssh_keys.ParseKnownHosts(read.text)
      else:
        keys = ssh_keys.ParseAuthorizedKeys(read.text)
    except ValueError as exc:
      entry['parse_error'] = str(exc)
      sources.append(entry)
      continue
    entry['rsa_count'] = len(keys.rsa_keys)
    entry['ec_count'] = len(keys.ec_keys)
    entry['unsupported_count'] = len(keys.unsupported)
    merged.rsa_keys.extend(keys.rsa_keys)
    merged.ec_keys.extend(keys.ec_keys)
    merged.unsupported.extend(keys.unsupported)
    sources.append(entry)
  return sources, merged
