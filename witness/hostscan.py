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
"""Discover browsers and installed-app public crypto on this machine.

The system CA bundle is counted and reported as skipped. Full Bastion checks
run only on application and user keys, not on the public root set.
"""

import errno
import glob
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from witness.material import KeyMaterial
from witness.material import MAX_FILE_BYTES
from witness.material import count_certificates
from witness.material import inspect_bytes
from witness.material import looks_like_private_key
from witness.material import read_bounded

SYSTEM_BUNDLE = '/etc/ssl/certs/ca-certificates.crt'
USER_CA_DIR = '/usr/local/share/ca-certificates'
BUNDLE_MAX_BYTES = 4 * 1024 * 1024
BUNDLE_CERT_CAP = 25
MAX_APP_FILES = 200
MAX_BROWSER_FILES = 40
MAX_APP_DIRS = 2500
MAX_BROWSER_DIRS = 800
MAX_NOTES = 30

_CANDIDATE_EXTS = frozenset(('.pem', '.crt', '.cer', '.pub'))
_CANDIDATE_NAMES = frozenset(('authorized_keys', 'known_hosts'))
_SKIP_DIR_NAMES = frozenset((
    '.git', 'node_modules', '__pycache__', 'proc', 'sys',
))
# Hash links and per-root PEMs live here. The bundle is handled on its own.
_SKIP_DIR_PREFIXES = (
    '/etc/ssl/certs',
    '/etc/ssl/private',
    '/etc/credstore',
    '/etc/credstore.encrypted',
)

_NOTABLE_PREFIXES = (
    'openssl', 'openssh', 'ca-certificates', 'nginx', 'apache2',
    'firefox', 'chromium', 'google-chrome', 'microsoft-edge',
    'curl', 'wget', 'gnutls', 'libnss3',
)


@dataclass(frozen=True)
class BrowserSpec:
  name: str
  prefixes: tuple[str, ...]
  binaries: tuple[str, ...]
  binary_globs: tuple[str, ...]


def _browser_specs() -> tuple[BrowserSpec, ...]:
  home = str(Path.home())
  flatpak_user = os.path.join(home, '.local', 'share', 'flatpak', 'app')
  return (
      BrowserSpec(
          'Google Chrome',
          (
              '/opt/google/chrome',
              '/opt/google/chrome-beta',
              '/opt/google/chrome-unstable',
              '/snap/google-chrome/current',
              '/var/lib/flatpak/app/com.google.Chrome/current/active/files',
              os.path.join(flatpak_user, 'com.google.Chrome', 'current',
                           'active', 'files'),
          ),
          (
              '/usr/bin/google-chrome',
              '/usr/bin/google-chrome-stable',
              '/usr/bin/google-chrome-beta',
              '/usr/bin/google-chrome-unstable',
          ),
          ('/usr/bin/google-chrome*',),
      ),
      BrowserSpec(
          'Chromium',
          (
              '/usr/lib/chromium',
              '/usr/lib/chromium-browser',
              '/snap/chromium/current',
              '/var/lib/flatpak/app/org.chromium.Chromium/current/active/files',
              os.path.join(flatpak_user, 'org.chromium.Chromium', 'current',
                           'active', 'files'),
          ),
          (
              '/usr/bin/chromium',
              '/usr/bin/chromium-browser',
          ),
          ('/usr/bin/chromium*',),
      ),
      BrowserSpec(
          'Microsoft Edge',
          (
              '/opt/microsoft/msedge',
              '/opt/microsoft/msedge-beta',
              '/opt/microsoft/msedge-dev',
              '/snap/microsoft-edge/current',
              '/var/lib/flatpak/app/com.microsoft.Edge/current/active/files',
              os.path.join(flatpak_user, 'com.microsoft.Edge', 'current',
                           'active', 'files'),
          ),
          (
              '/usr/bin/microsoft-edge',
              '/usr/bin/microsoft-edge-stable',
              '/usr/bin/microsoft-edge-beta',
          ),
          ('/usr/bin/microsoft-edge*',),
      ),
      BrowserSpec(
          'Firefox',
          (
              '/usr/lib/firefox',
              '/usr/lib/firefox-esr',
              '/snap/firefox/current',
              '/var/lib/flatpak/app/org.mozilla.firefox/current/active/files',
              os.path.join(flatpak_user, 'org.mozilla.firefox', 'current',
                           'active', 'files'),
          ),
          (
              '/usr/bin/firefox',
              '/usr/bin/firefox-esr',
          ),
          ('/usr/bin/firefox*',),
      ),
  )


def system_bundle_reason(count: int) -> str:
  return (f'system trust bundle present, {count} certificates, '
          'full weakness scan not run on public roots in this alpha')


def _skip_record(path: str, reason: str, cert_count: int | None = None) -> dict:
  return {
      'path': path,
      'status': 'skipped',
      'cert_count': cert_count,
      'not_a_pass': True,
      'reason': reason,
  }


def _is_candidate(name: str) -> bool:
  if name in _CANDIDATE_NAMES:
    return True
  return os.path.splitext(name)[1].lower() in _CANDIDATE_EXTS


def _same_path(left: str, right: str) -> bool:
  try:
    return os.path.realpath(left) == os.path.realpath(right)
  except OSError:
    return os.path.abspath(left) == os.path.abspath(right)


def _under_skipped_dir(path: str) -> bool:
  absolute = os.path.abspath(path)
  for prefix in _SKIP_DIR_PREFIXES:
    if absolute == prefix or absolute.startswith(prefix + os.sep):
      return True
  return False


def group_for_path(path: str, home: str | None = None) -> str:
  """Group an on-disk file by the app directory that contains it."""
  absolute = os.path.abspath(path)
  home = home or str(Path.home())
  config = os.path.join(home, '.config')
  if absolute == config or absolute.startswith(config + os.sep):
    rest = absolute[len(config):].strip(os.sep)
    name = rest.split(os.sep, 1)[0] if rest else ''
    return f'~/.config/{name}' if name else '~/.config'
  for prefix in ('/opt', '/usr/local/share', '/etc'):
    if absolute == prefix:
      return prefix
    if absolute.startswith(prefix + os.sep):
      rest = absolute[len(prefix):].strip(os.sep)
      name = rest.split(os.sep, 1)[0]
      return os.path.join(prefix, name)
  parent = os.path.dirname(absolute)
  return parent or absolute


@dataclass
class ScanAccum:
  """Mutable collector shared by browser and app walks."""

  section: str
  seen: set[str] = field(default_factory=set)
  keys: list[KeyMaterial] = field(default_factory=list)
  skipped: list[dict] = field(default_factory=list)
  unreadable: list[dict] = field(default_factory=list)
  private_skipped: list[dict] = field(default_factory=list)
  unsupported: list[dict] = field(default_factory=list)
  notes: list[str] = field(default_factory=list)
  files_read: int = 0
  truncated: bool = False
  bundle_cert_cap: int = BUNDLE_CERT_CAP

  def add_note(self, text: str) -> None:
    if len(self.notes) < MAX_NOTES:
      self.notes.append(text)
    elif len(self.notes) == MAX_NOTES:
      self.notes.append('Further notes omitted.')

  def as_dict(self) -> dict:
    return {
        'keys': self.keys,
        'skipped': self.skipped,
        'unreadable': self.unreadable,
        'private_skipped': self.private_skipped,
        'unsupported': self.unsupported,
        'notes': self.notes,
        'files_read': self.files_read,
        'truncated': self.truncated,
    }


def _remember(seen: set[str], path: str) -> bool:
  """Return True if this path was not seen before."""
  try:
    key = os.path.realpath(path)
  except OSError:
    key = os.path.abspath(path)
  if key in seen:
    return False
  seen.add(key)
  return True


def _permission_denied(exc: OSError) -> bool:
  if isinstance(exc, PermissionError):
    return True
  return getattr(exc, 'errno', None) in (errno.EACCES, errno.EPERM)


def consume_file(accum: ScanAccum, path: str, group: str,
                 system_bundle: str | None) -> None:
  """Read one candidate file into `accum`. Private keys are not kept."""
  if not _remember(accum.seen, path):
    return
  if system_bundle and _same_path(path, system_bundle):
    return
  if _under_skipped_dir(path):
    return
  try:
    if not os.path.isfile(path):
      return
  except OSError as exc:
    if _permission_denied(exc):
      accum.unreadable.append({'path': path, 'error': exc.strerror or str(exc)})
    else:
      accum.add_note(f'{path}: {exc.strerror or exc}')
    return
  data, reason = read_bounded(path, MAX_FILE_BYTES)
  if data is None:
    if reason and ('cap' in reason or 'byte' in reason):
      accum.skipped.append(_skip_record(path, reason + '. This is not a pass.'))
    else:
      accum.unreadable.append({'path': path, 'error': reason or 'unreadable'})
    return
  if looks_like_private_key(data):
    accum.private_skipped.append({
        'path': path,
        'reason': 'looks like a private key; contents not reported',
    })
    return
  accum.files_read += 1
  parsed = inspect_bytes(path, data)
  if parsed.private:
    accum.private_skipped.append({
        'path': path,
        'reason': 'looks like a private key; contents not reported',
    })
    return
  if parsed.cert_count > accum.bundle_cert_cap:
    accum.skipped.append(_skip_record(
        path,
        (f'large certificate bundle ({parsed.cert_count} certificates); '
         'full weakness scan not run in this alpha. This is not a pass.'),
        parsed.cert_count))
    return
  if parsed.error:
    accum.add_note(f'{path}: {parsed.error}')
  for detail in parsed.unsupported:
    accum.unsupported.append({'path': path, 'detail': detail})
  for key, subject in parsed.keys:
    accum.keys.append(KeyMaterial(accum.section, group, path, subject, key))


def walk_tree(accum: ScanAccum, root: str, group: str | None, max_depth: int,
              file_budget: list[int], dir_budget: list[int],
              system_bundle: str | None) -> None:
  """Walk `root` for public crypto files, honoring depth and count caps."""
  if file_budget[0] <= 0 or dir_budget[0] <= 0:
    accum.truncated = True
    return
  if not os.path.exists(root):
    accum.add_note(f'{root} is not present')
    return
  if _under_skipped_dir(root):
    return
  if not os.path.isdir(root):
    if _is_candidate(os.path.basename(root)) and file_budget[0] > 0:
      file_budget[0] -= 1
      consume_file(accum, root, group or group_for_path(root), system_bundle)
    return
  try:
    os.listdir(root)
  except OSError as exc:
    if _permission_denied(exc):
      accum.unreadable.append({
          'path': root,
          'error': exc.strerror or 'permission denied',
      })
    else:
      accum.add_note(f'{root}: {exc.strerror or exc}')
    return

  def onerror(err: OSError) -> None:
    filename = getattr(err, 'filename', None) or root
    if os.path.abspath(str(filename)) == os.path.abspath(root) and _permission_denied(err):
      accum.unreadable.append({
          'path': str(filename),
          'error': err.strerror or 'permission denied',
      })
      return
    if _permission_denied(err):
      accum.add_note(f'{filename}: {err.strerror or "permission denied"}')
      return
    accum.add_note(f'{filename}: {err.strerror or err}')

  for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=onerror):
    dir_budget[0] -= 1
    if dir_budget[0] <= 0:
      accum.truncated = True
      accum.add_note(
          'Directory walk stopped at the directory cap. '
          'Remaining files were not checked and are not confirmed.')
      dirnames[:] = []
      break
    depth = 0 if dirpath == root else os.path.relpath(dirpath, root).count(os.sep) + 1
    kept = []
    for name in dirnames:
      child = os.path.join(dirpath, name)
      if name in _SKIP_DIR_NAMES or _under_skipped_dir(child):
        continue
      kept.append(name)
    if depth >= max_depth:
      dirnames[:] = []
    else:
      dirnames[:] = kept
    for name in filenames:
      if file_budget[0] <= 0:
        accum.truncated = True
        accum.add_note(
            'Stopped after the candidate file cap. '
            'Further files were not checked and are not confirmed.')
        return
      if not _is_candidate(name):
        continue
      file_budget[0] -= 1
      path = os.path.join(dirpath, name)
      file_group = group if group is not None else group_for_path(path)
      consume_file(accum, path, file_group, system_bundle)


def _existing_paths(paths: tuple[str, ...], patterns: tuple[str, ...]) -> list[str]:
  found = []
  seen = set()
  for path in paths:
    if path in seen:
      continue
    if os.path.exists(path):
      seen.add(path)
      found.append(path)
  for pattern in patterns:
    for path in sorted(glob.glob(pattern)):
      if path in seen:
        continue
      seen.add(path)
      found.append(path)
  return found


def discover_browsers(extra_roots: list[dict] | None = None,
                      use_defaults: bool = True) -> list[dict]:
  """Return installed browsers and any caller-supplied roots."""
  found = []
  seen_names = set()
  for item in extra_roots or []:
    name = item.get('name') or 'Browser'
    path = item.get('path') or ''
    found.append({
        'name': name,
        'path': path,
        'scanned_prefix': bool(path),
        'extra': True,
    })
    seen_names.add(name)
  if not use_defaults:
    return found
  for spec in _browser_specs():
    prefixes = [path for path in spec.prefixes if os.path.isdir(path)]
    binaries = _existing_paths(spec.binaries, spec.binary_globs)
    if not prefixes and not binaries:
      continue
    if prefixes:
      for prefix in prefixes:
        found.append({
            'name': spec.name,
            'path': prefix,
            'scanned_prefix': True,
            'extra': False,
        })
    else:
      found.append({
          'name': spec.name,
          'path': binaries[0],
          'scanned_prefix': False,
          'extra': False,
      })
  return found


def _scan_system_bundle(accum: ScanAccum, path: str) -> None:
  if not os.path.exists(path):
    accum.skipped.append(_skip_record(
        path,
        ('system trust bundle not found; full weakness scan was not run. '
         'This is not a pass of public roots.'),
        0))
    return
  _remember(accum.seen, path)
  if looks_like_private_key_file(path):
    accum.private_skipped.append({
        'path': path,
        'reason': 'looks like a private key; contents not reported',
    })
    accum.skipped.append(_skip_record(
        path,
        'system trust bundle path looks like a private key and was not scanned. '
        'This is not a pass.',
        None))
    return
  data, reason = read_bounded(path, BUNDLE_MAX_BYTES)
  if data is None:
    if reason and 'cap' in reason:
      accum.skipped.append(_skip_record(
          path,
          reason + '. Full weakness scan was not run. This is not a pass.',
          None))
    else:
      accum.unreadable.append({'path': path, 'error': reason or 'unreadable'})
    return
  if looks_like_private_key(data):
    accum.private_skipped.append({
        'path': path,
        'reason': 'looks like a private key; contents not reported',
    })
    return
  count = count_certificates(data)
  accum.files_read += 1
  accum.skipped.append(_skip_record(path, system_bundle_reason(count), count))


def looks_like_private_key_file(path: str) -> bool:
  """Header-only check so a private-key path is never fully parsed."""
  try:
    with open(path, 'rb') as handle:
      head = handle.read(4096)
  except OSError:
    return False
  return looks_like_private_key(head)


def _scan_user_cas(accum: ScanAccum, path: str, system_bundle: str,
                   file_budget: list[int]) -> None:
  if not os.path.isdir(path):
    accum.skipped.append(_skip_record(
        path,
        ('User-installed CAs were not distinguished from the system bundle. '
         f'{path} is missing or not a directory, so certificates added only '
         'inside the bundle were not fully checked. This is not a pass.'),
        None))
    return
  before = len(accum.keys)
  walk_tree(
      accum,
      path,
      'User-installed CAs',
      max_depth=3,
      file_budget=file_budget,
      dir_budget=[200],
      system_bundle=system_bundle)
  added = len(accum.keys) - before
  if added:
    accum.add_note(
        f'Fully checked {added} public key(s) under {path}. '
        'The system trust bundle itself was not fully scanned.')
  else:
    accum.skipped.append(_skip_record(
        path,
        ('User-installed CA directory is present but had no public '
         'certificates to check. Certificates that exist only inside the '
         'system bundle were not separated and were not fully checked. '
         'This is not a pass.'),
        0))


def _nss_databases() -> list[tuple[str, str]]:
  home = Path.home()
  found = []
  chrome = home / '.pki' / 'nssdb'
  if (chrome / 'cert9.db').is_file():
    found.append(('Chrome/Chromium NSS', str(chrome)))
  firefox = home / '.mozilla' / 'firefox'
  if firefox.is_dir():
    try:
      profiles = sorted(firefox.iterdir())
    except OSError:
      profiles = []
    for profile in profiles:
      if (profile / 'cert9.db').is_file():
        found.append((f'Firefox profile {profile.name}', str(profile)))
        if len(found) >= 6:
          break
  return found


def _certutil_nicknames(db_dir: str) -> tuple[list[str], str | None]:
  certutil = shutil.which('certutil')
  if not certutil:
    return [], 'certutil is not installed'
  try:
    proc = subprocess.run(
        [certutil, '-L', '-d', f'sql:{db_dir}'],
        capture_output=True,
        text=True,
        timeout=8,
        check=False)
  except (OSError, subprocess.TimeoutExpired) as exc:
    return [], str(exc)
  if proc.returncode != 0 and not proc.stdout.strip():
    detail = (proc.stderr or '').strip() or f'certutil exited {proc.returncode}'
    return [], detail
  names = []
  for line in proc.stdout.splitlines():
    if not line.strip():
      continue
    if line.startswith('Certificate Nickname'):
      continue
    if line.startswith(' ') and 'SSL' in line:
      continue
    name = line.split('  ', 1)[0].strip()
    if name:
      names.append(name)
    if len(names) >= 30:
      break
  return names, None


def _scan_nss(accum: ScanAccum) -> None:
  databases = _nss_databases()
  if not databases:
    accum.add_note(
        'No NSS cert9.db was found for Chrome or Firefox profiles. '
        'Nothing in those stores to check.')
    return
  certutil = shutil.which('certutil')
  for label, db_dir in databases:
    cert_path = os.path.join(db_dir, 'cert9.db')
    if not certutil:
      accum.skipped.append(_skip_record(
          cert_path,
          (f'{label}: NSS cert9.db is present but certutil is not installed, '
           'so certificates were not read. This is not a pass.'),
          None))
      continue
    nicknames, error = _certutil_nicknames(db_dir)
    if error and not nicknames:
      accum.skipped.append(_skip_record(
          cert_path,
          (f'{label}: certutil could not list nicknames ({error}). '
           'Certificates were not checked. This is not a pass.'),
          None))
      continue
    shown = ', '.join(nicknames[:12])
    extra = f' Examples: {shown}.' if shown else ''
    accum.skipped.append(_skip_record(
        cert_path,
        (f'{label}: listed {len(nicknames)} NSS nickname(s). '
         'PEM certificates were not exported, so Bastion did not check them. '
         f'This is not a pass.{extra}'),
        len(nicknames)))


def scan_browsers(extra_roots: list[dict] | None = None,
                  discover_defaults: bool = True,
                  system_bundle_path: str | None = None,
                  user_ca_dir: str | None = None,
                  include_system_bundle: bool = True,
                  include_user_cas: bool = True,
                  include_nss: bool = True,
                  seen: set[str] | None = None,
                  bundle_cert_cap: int = BUNDLE_CERT_CAP) -> dict:
  """Discover browsers and public certs they ship. Does not scan NSS databases."""
  bundle = system_bundle_path or SYSTEM_BUNDLE
  user_cas = user_ca_dir or USER_CA_DIR
  discovered = discover_browsers(extra_roots, use_defaults=discover_defaults)
  accum = ScanAccum('browsers', seen=seen if seen is not None else set(),
                    bundle_cert_cap=bundle_cert_cap)
  installs = [item for item in discovered if item.get('scanned_prefix') and item.get('path')]
  none_found = not any(not item.get('extra') for item in discovered)
  if not discovered:
    accum.add_note('No browsers found on this machine.')
  elif not installs and none_found:
    accum.add_note('No browsers found on this machine.')
  for item in discovered:
    if item.get('scanned_prefix'):
      continue
    accum.add_note(
        f'{item["name"]} was discovered at {item["path"]}, but there is no '
        'install prefix to scan for PEM or CRT files.')
  for item in installs:
    walk_tree(
        accum,
        item['path'],
        item['name'],
        max_depth=6,
        file_budget=[MAX_BROWSER_FILES],
        dir_budget=[MAX_BROWSER_DIRS],
        system_bundle=bundle)
  if include_system_bundle:
    _scan_system_bundle(accum, bundle)
  if include_user_cas:
    _scan_user_cas(accum, user_cas, bundle, [MAX_BROWSER_FILES])
  if include_nss:
    _scan_nss(accum)
  result = accum.as_dict()
  result['discovered'] = [
      {'name': item['name'], 'path': item['path'],
       'scanned_prefix': bool(item.get('scanned_prefix'))}
      for item in discovered
  ]
  result['none_found'] = not discovered
  return result


def _is_notable(name: str) -> bool:
  for prefix in _NOTABLE_PREFIXES:
    if name == prefix or name.startswith(prefix + '-'):
      return True
  return False


def list_installed_packages(which=None, run=None) -> dict:
  """Return a short package summary. Missing dpkg does not raise."""
  which = which or shutil.which
  run = run or subprocess.run
  if not which('dpkg-query'):
    return {
        'available': False,
        'count': 0,
        'sample': [],
        'message': 'dpkg-query is not installed; package list was not read.',
    }
  try:
    proc = run(
        ['dpkg-query', '-W', '-f', '${Package}\n'],
        capture_output=True,
        text=True,
        timeout=20,
        check=False)
  except (OSError, subprocess.TimeoutExpired) as exc:
    return {
        'available': False,
        'count': 0,
        'sample': [],
        'message': f'Could not list packages: {exc}',
    }
  names = [line.strip() for line in (proc.stdout or '').splitlines() if line.strip()]
  notable = [name for name in names if _is_notable(name)][:12]
  if notable:
    sample = notable[:12]
  else:
    sample = sorted(names)[:8]
  message = None
  if proc.returncode not in (0, None) and not names:
    message = (proc.stderr or '').strip() or f'dpkg-query exited {proc.returncode}'
    return {
        'available': False,
        'count': 0,
        'sample': [],
        'message': message,
    }
  return {
      'available': True,
      'count': len(names),
      'sample': sample,
      'message': message,
  }


def default_app_roots() -> list[tuple[str, int]]:
  home = Path.home()
  return [
      ('/etc', 4),
      ('/usr/local/share', 5),
      ('/opt', 5),
      (str(home / '.config'), 3),
  ]


def scan_apps(roots: list[tuple[str, int]] | None = None,
              list_packages=None,
              seen: set[str] | None = None,
              system_bundle_path: str | None = None,
              note_skipped_system_certs: bool = False,
              bundle_cert_cap: int = BUNDLE_CERT_CAP) -> dict:
  """Scan bounded paths for public PEM, CRT, and OpenSSH material."""
  bundle = system_bundle_path or SYSTEM_BUNDLE
  chosen = list(roots) if roots is not None else default_app_roots()
  packages = list_packages() if list_packages is not None else list_installed_packages()
  accum = ScanAccum('apps', seen=seen if seen is not None else set(),
                    bundle_cert_cap=bundle_cert_cap)
  file_budget = [MAX_APP_FILES]
  dir_budget = [MAX_APP_DIRS]
  saw_etc = False
  for root, depth in chosen:
    if os.path.abspath(root) == '/etc':
      saw_etc = True
    walk_tree(
        accum,
        root,
        None,
        max_depth=depth,
        file_budget=file_budget,
        dir_budget=dir_budget,
        system_bundle=bundle)
  if note_skipped_system_certs and saw_etc:
    accum.skipped.append(_skip_record(
        '/etc/ssl/certs',
        ('Individual certificates and hash links under /etc/ssl/certs were '
         'not scanned. This is not a pass of system roots.'),
        None))
  result = accum.as_dict()
  result['packages'] = packages
  result['roots'] = [{'path': path, 'max_depth': depth} for path, depth in chosen]
  return result
