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
"""Local witness web UI on 127.0.0.1."""

import argparse
import html
import http.server
import socketserver
import urllib.parse
from typing import Callable

from witness import __version__
from witness.run import witness_machine

DEFAULT_PORT = 8770
MAX_BODY_BYTES = 65536
MAX_EXTRA_PATHS = 32
MAX_PATH_LEN = 4096

# Tests may replace this hook.
WITNESS_RUNNER: Callable[..., dict] = witness_machine

_CSP = ("default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "base-uri 'none'; form-action 'self'")

_PAGE_CSS = """
body{font-family:system-ui,sans-serif;margin:0 auto;padding:1.25rem;
max-width:68rem;line-height:1.45;color:#1a1a1a;background:#eef1f5}
h1{font-size:1.7rem;margin:0 0 .35rem;letter-spacing:-.02em}
h2{font-size:1.15rem;margin:0}
h3{font-size:1rem;margin:1rem 0 .35rem}
.sub{color:#243040;margin:0;font-size:1.05rem;max-width:40rem}
.intro{margin:0 0 1.25rem}
form{background:transparent;border:0;padding:0;margin:0}
fieldset.choices{border:0;margin:0;padding:0;display:grid;
grid-template-columns:repeat(3,minmax(0,1fr));gap:.85rem}
legend{grid-column:1 / -1;font-weight:700;font-size:1rem;padding:0;margin:0}
label{display:block;font-weight:600;margin:.75rem 0 .25rem}
label.choice{display:flex;flex-direction:column;align-items:flex-start;gap:.35rem;
margin:0;min-height:8.5rem;padding:1.05rem 1rem 1rem;font-weight:400;
border:2px solid #d0d7e2;border-radius:16px;background:#fff;cursor:pointer;
box-sizing:border-box}
label.choice input{width:1.3rem;height:1.3rem;margin:0 0 .45rem;accent-color:#1a5fb4}
label.choice:hover{border-color:#8eabcf}
label.choice:has(input:checked){border-color:#1a5fb4;background:#f2f7fd;
box-shadow:inset 0 0 0 1px #1a5fb4}
label.choice:focus-within{outline:2px solid #1a5fb4;outline-offset:2px}
.choice-title{font-size:1.28rem;font-weight:700;letter-spacing:-.02em}
.choice-desc{color:#243040;font-size:1rem}
.tls{margin-top:1rem}
.tls label{font-weight:500;color:#444;font-size:.95rem;margin:0 0 .35rem}
.tls-row{display:flex;gap:.5rem}
.tls-row input[type=number]{width:6.5rem;flex:none}
input[type=text],input[type=number],textarea{width:100%;box-sizing:border-box;
padding:.55rem .65rem;border:1px solid #c5ced8;border-radius:8px;font:inherit;
background:#fff}
textarea{min-height:4.5rem;font-family:ui-monospace,monospace}
details.extra{margin-top:.85rem;background:#fff;border:1px solid #d5dbe3;
border-radius:12px;padding:.45rem .9rem}
details.extra summary{font-weight:600;color:#333}
button.primary{margin-top:1.15rem;padding:.9rem 1.45rem;font:inherit;
font-size:1.05rem;font-weight:700;border:0;border-radius:12px;background:#1a5fb4;
color:#fff;cursor:pointer;width:auto;min-width:16rem}
button.primary:hover{background:#1c71d8}
.status{padding:1.35rem 1.4rem 1.3rem;border-radius:18px;margin:0 0 1.15rem}
.status-label{font-size:clamp(2.1rem,6vw,3rem);font-weight:700;margin:0;
letter-spacing:-.03em;line-height:1.05}
.status-reason{font-size:1.2rem;margin:.55rem 0 0;font-weight:500;max-width:42rem}
.status-ok{background:#e3f7eb;border:2px solid #1b8a45;color:#0e3d24}
.status-warn{background:#fff4df;border:2px solid #d4880f;color:#5c3b00}
.status-incomplete{background:#e7f3fc;border:2px solid #1a73b8;color:#0c3a5e}
.results{display:grid;grid-template-columns:1fr;gap:.85rem;margin:0 0 1.5rem}
.result{background:#fff;border:1px solid #d5dbe3;border-radius:16px;
padding:1rem;min-width:0}
.result-wide{grid-column:1 / -1}
.result-head{display:flex;flex-wrap:wrap;align-items:baseline;gap:.35rem .7rem;
margin-bottom:.35rem}
.count{margin:0;color:#243040}
.badge{margin:0 0 0 auto;font-weight:700;font-size:.82rem;padding:.2rem .6rem;
border-radius:999px}
.badge-clean{background:#e7f6ee;color:#146c3a}
.badge-warn{background:#fff1d6;color:#6a3d00}
.badge-skip{background:#eef1f4;color:#3d4752}
.badge-incomplete{background:#e7f2fb;color:#0c3458}
.err{color:#7a1f1f;background:#fadbd8;padding:.75rem;border-radius:8px;margin:.5rem 0}
.info{background:#f4f7fb;border:1px solid #d5deea;color:#1e2a36;border-radius:10px;
padding:.7rem .8rem;margin:.7rem 0}
.skip{background:#f3f4f6;border:1px solid #9aa3ad;color:#1f2933;border-radius:10px;
padding:.7rem .8rem;margin:.7rem 0}
.weak{background:#fff4df;border:1px solid #e0a14a;border-radius:10px;
padding:.35rem .75rem;margin:.55rem 0}
details.files{background:#f8fafc;border:1px solid #e1e6ee;border-radius:10px;
padding:.45rem .75rem;margin:.75rem 0 0}
.weak details,details.extra details{border:0;background:transparent;padding:0;margin:0}
summary{cursor:pointer;font-weight:600}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th,td{border-bottom:1px solid #eee;padding:.4rem;text-align:left;vertical-align:top}
tr.fail td{color:#7a1f1f}
.meta{font-size:.85rem;color:#526070}
.run-meta{margin:-.4rem 0 1.15rem}
.fp{font-family:ui-monospace,monospace;overflow-wrap:anywhere}
.footer{margin:1.5rem 0 0;color:#526070;font-size:.9rem}
ul{margin:.35rem 0 .75rem;padding-left:1.2rem}
@media (max-width:40rem){
  body{padding:.75rem}
  fieldset.choices,.results{grid-template-columns:1fr}
  button.primary{width:100%}
  .tls-row{flex-direction:column}
  .tls-row input[type=number]{width:100%}
  table{display:block;overflow-x:auto}
  label.choice{min-height:0}
}
"""


def _escape(value) -> str:
  return html.escape('' if value is None else str(value))


def _status_view(status: str) -> tuple[str, str]:
  if status == 'confirmed':
    return 'Confirmed', 'status status-ok'
  if status == 'needs_attention':
    return 'Needs attention', 'status status-warn'
  return 'Incomplete', 'status status-incomplete'


def _parse_extra_paths(raw: str) -> list[str]:
  paths = []
  for line in raw.splitlines():
    path = line.strip()
    if not path:
      continue
    if len(path) > MAX_PATH_LEN:
      continue
    paths.append(path)
    if len(paths) >= MAX_EXTRA_PATHS:
      break
  return paths


def _flag(data: dict, name: str) -> bool:
  values = data.get(name)
  if not values:
    return False
  return values[0] in ('on', '1', 'true', 'yes')


def _parse_form(body: bytes) -> dict:
  data = urllib.parse.parse_qs(body.decode('utf-8', errors='replace'),
                               keep_blank_values=True)
  scan_ssh = _flag(data, 'scan_ssh') or _flag(data, 'scan_home')
  extra = _parse_extra_paths(data.get('extra_paths', [''])[0])
  tls_host = data.get('tls_host', [''])[0].strip()
  if len(tls_host) > 253:
    tls_host = tls_host[:253]
  port_raw = data.get('tls_port', ['443'])[0].strip() or '443'
  try:
    tls_port = int(port_raw)
  except ValueError:
    tls_port = 443
  if tls_port < 1 or tls_port > 65535:
    tls_port = 443
  return {
      'scan_ssh': scan_ssh,
      'scan_browsers': _flag(data, 'scan_browsers'),
      'scan_apps': _flag(data, 'scan_apps'),
      'extra_paths': extra,
      'tls_host': tls_host,
      'tls_port': tls_port,
  }


def _default_form() -> dict:
  return {
      'scan_ssh': True,
      'scan_browsers': True,
      'scan_apps': True,
      'extra_paths': [],
      'tls_host': '',
      'tls_port': 443,
  }


def _section_requested(section: dict | None, kind: str) -> bool:
  if not section:
    return False
  if 'requested' in section:
    return bool(section['requested'])
  return kind == 'ssh'


def _weak_count(section: dict) -> int:
  if 'weak_count' in section and section['weak_count'] is not None:
    return int(section['weak_count'])
  return sum(1 for key in (section.get('keys') or []) if key.get('weak'))


def _key_count(section: dict) -> int:
  if 'key_count' in section and section['key_count'] is not None:
    return int(section['key_count'])
  return len(section.get('keys') or [])


def _unreadable_items(section: dict, kind: str) -> list:
  if kind == 'ssh':
    return [
        item for item in (section.get('sources') or [])
        if item.get('status') == 'unreadable'
    ]
  return list(section.get('unreadable') or [])


def _is_system_root_skip(item: dict) -> bool:
  path = str(item.get('path') or '').replace('\\', '/').rstrip('/')
  reason = str(item.get('reason') or '').lower()
  if path.endswith('ca-certificates.crt') or path == '/etc/ssl/certs':
    return True
  if 'system trust bundle' in reason:
    return True
  if 'public roots' in reason or 'system roots' in reason:
    return True
  return False


def _join(parts: list[str]) -> str:
  if not parts:
    return ''
  if len(parts) == 1:
    return parts[0]
  if len(parts) == 2:
    return f'{parts[0]} and {parts[1]}'
  return ', '.join(parts[:-1]) + ', and ' + parts[-1]


def _sentence(text: str) -> str:
  if not text:
    return text
  return text[0].upper() + text[1:] + '.'


def _confirmed_sentence(included: list[str]) -> str:
  if included == ['browsers', 'apps', 'SSH']:
    return ('No weak public keys in the browsers, apps, and SSH files '
            'we could read.')
  if not included:
    return 'No weak public keys in the files we could read.'
  if included == ['SSH']:
    return 'No weak public keys in the SSH files we could read.'
  return f'No weak public keys in the {_join(included)} files we could read.'


def _attention_clause(count: int, label: str) -> str:
  if count == 1:
    return f'1 key needs attention in {label}'
  return f'{count} keys need attention in {label}'


def _attention_sentence(attention: list[tuple[int, str]], tls_failed: bool) -> str:
  bits = [_attention_clause(count, label) for count, label in attention]
  if tls_failed:
    bits.append('the TLS certificate needs attention')
  if not bits:
    return 'Something that was checked needs attention.'
  return _sentence(_join(bits))


def _incomplete_sentence(unreadable: list[str], tls_on: bool, exit_code,
                         skipped: bool) -> str:
  bits = []
  if len(unreadable) == 1:
    bits.append(f'a file in {unreadable[0]} could not be read')
  elif unreadable:
    bits.append(f'files in {_join(unreadable)} could not be read')
  tls_stuck = tls_on and (exit_code == 2 or (exit_code is None and not skipped))
  if tls_stuck:
    bits.append('the TLS check could not finish')
  if not bits:
    return ('A requested check could not finish, so this confirmation '
            'is incomplete.')
  text = _join(bits)
  return text[0].upper() + text[1:] + ', so this confirmation is incomplete.'


def _plain_reason(report: dict) -> str:
  """One sentence for the confirmation panel."""
  status = report.get('overall_status') or 'incomplete'
  phrases = {'browsers': 'browsers', 'apps': 'apps', 'ssh': 'SSH'}
  labels = {'browsers': 'Browsers', 'apps': 'Installed apps', 'ssh': 'SSH'}
  included = []
  attention = []
  unreadable = []
  for key in ('browsers', 'apps', 'ssh'):
    section = report.get(key) or {}
    if not _section_requested(section, key):
      continue
    included.append(phrases[key])
    weak = _weak_count(section)
    if weak:
      attention.append((weak, labels[key]))
    if _unreadable_items(section, key):
      unreadable.append(labels[key])
  tls = report.get('tls') or {}
  tls_on = bool(tls.get('requested'))
  exit_code = tls.get('exit_code')
  if status == 'confirmed':
    return _confirmed_sentence(included)
  if status == 'needs_attention':
    return _attention_sentence(attention, bool(tls_on and exit_code == 1))
  return _incomplete_sentence(
      unreadable, tls_on, exit_code, bool(tls.get('skipped')))


def _choice(name: str, title: str, description: str, checked: bool) -> str:
  mark = ' checked' if checked else ''
  return (
      '<label class="choice">'
      f'<input type="checkbox" name="{name}" value="on"{mark}>'
      f'<span class="choice-title">{_escape(title)}</span>'
      f'<span class="choice-desc">{_escape(description)}</span>'
      '</label>')


def _grouped(keys: list[dict]) -> list[tuple[str, list[dict]]]:
  order = []
  buckets: dict[str, list[dict]] = {}
  for key in keys:
    name = key.get('group') or 'Other'
    if name not in buckets:
      buckets[name] = []
      order.append(name)
    buckets[name].append(key)
  return [(name, buckets[name]) for name in order]


def _render_checks(checks: list[dict]) -> list[str]:
  parts = ['<table><tr><th>Check</th><th>Result</th><th>Severity</th></tr>']
  for check in checks:
    failed = check.get('failed')
    cls = ' class="fail"' if failed else ''
    result = 'fail' if failed else 'pass'
    parts.append(
        f'<tr{cls}><td>{_escape(check.get("name"))}</td>'
        f'<td>{result}</td><td>{_escape(check.get("severity"))}</td></tr>'
        f'<tr{cls}><td colspan="3" class="meta">'
        f'{_escape(check.get("blurb"))}</td></tr>')
  parts.append('</table>')
  return parts


def _render_keys(keys: list[dict], hide_group: str | None = None) -> list[str]:
  parts = []
  for name, grouped in _grouped(keys):
    if name != hide_group:
      parts.append(f'<h3>{_escape(name)}</h3>')
    for key in grouped:
      weak = key.get('weak')
      label = 'Needs attention' if weak else 'Checked'
      box = 'weak' if weak else 'key'
      open_attr = ' open' if weak else ''
      subject = key.get('subject')
      path = key.get('path')
      parts.append(f'<div class="{box}"><details{open_attr}><summary>'
                   f'{_escape(label)} · {_escape(key.get("type"))} · '
                   f'SHA256:{_escape(key.get("fingerprint_sha256"))}</summary>')
      if path:
        parts.append(f'<p class="fp">{_escape(path)}</p>')
      if subject:
        parts.append(f'<p class="meta">{_escape(subject)}</p>')
      failed = [row for row in (key.get('checks') or []) if row.get('failed')]
      if failed:
        parts.append('<p><strong>Failed checks:</strong> ')
        bits = [
            f'{_escape(row.get("name"))} ({_escape(row.get("severity"))})'
            for row in failed
        ]
        parts.append(', '.join(bits))
        parts.append('</p>')
      if key.get('checks'):
        parts.extend(_render_checks(key['checks']))
      parts.append('</details></div>')
  return parts


def _card_badge(section: dict, kind: str) -> tuple[str, str]:
  if not _section_requested(section, kind):
    return 'badge-skip', 'skipped'
  weak = _weak_count(section)
  if weak == 1:
    return 'badge-warn', '1 needs attention'
  if weak > 1:
    return 'badge-warn', f'{weak} need attention'
  if _unreadable_items(section, kind):
    return 'badge-incomplete', 'incomplete'
  if kind == 'browsers' and section.get('none_found'):
    return 'badge-skip', 'skipped'
  return 'badge-clean', 'clean'


def _count_label(section: dict, kind: str) -> str:
  if not _section_requested(section, kind):
    return 'Not included'
  keys = _key_count(section)
  noun = 'public key' if keys == 1 else 'public keys'
  if kind == 'apps':
    packages = section.get('packages') or {}
    if packages.get('available'):
      count = int(packages.get('count') or 0)
      word = 'package' if count == 1 else 'packages'
      return f'{count} {word} · {keys} {noun}'
  return f'{keys} {noun}'


def _details_open(section: dict, kind: str) -> bool:
  if _weak_count(section) or _unreadable_items(section, kind):
    return True
  if (section.get('skipped') or section.get('private_skipped')
      or section.get('keys')):
    return True
  if kind == 'ssh' and section.get('sources'):
    return True
  return False


def _render_system_roots(items: list[dict]) -> list[str]:
  roots = [item for item in items if _is_system_root_skip(item)]
  if not roots:
    return []
  parts = [
      '<p class="skip"><strong>Public root certificates were counted, '
      'not weakness-scanned.</strong> This is not a pass.</p>',
  ]
  for item in roots:
    count = item.get('cert_count')
    count_text = ''
    if isinstance(count, int):
      noun = 'certificate' if count == 1 else 'certificates'
      count_text = f'{count} {noun}. '
    parts.append(
        f'<p class="meta">{count_text}'
        f'<span class="fp">{_escape(item.get("path"))}</span></p>')
    if item.get('reason'):
      parts.append(f'<p class="meta">{_escape(item.get("reason"))}</p>')
  return parts


def _render_other_skips(items: list[dict]) -> list[str]:
  parts = []
  for item in items:
    if _is_system_root_skip(item):
      continue
    count = item.get('cert_count')
    count_text = f' ({count} certificates)' if isinstance(count, int) else ''
    parts.append(
        '<p class="skip"><strong>Skipped — not a pass.</strong> '
        f'<span class="fp">{_escape(item.get("path"))}</span>'
        f'{_escape(count_text)} {_escape(item.get("reason"))}</p>')
  return parts


def _render_empty(section: dict, kind: str) -> list[str]:
  if kind == 'browsers' and section.get('none_found'):
    return ['<p class="info">No browser install found</p>']
  if kind == 'apps' and _key_count(section) == 0 and not _weak_count(section):
    return ['<p class="info">No public keys in app configs</p>']
  if kind == 'ssh' and _key_count(section) == 0 and not _weak_count(section):
    return ['<p class="info">No public keys in the SSH files we could read.</p>']
  if _weak_count(section) == 0:
    return ['<p class="info">No weak keys in the files we could read.</p>']
  return []


def _render_discovered(section: dict) -> list[str]:
  parts = []
  for item in section.get('discovered') or []:
    prefix = ''
    if item.get('scanned_prefix') is False:
      prefix = ' (no install prefix to scan)'
    parts.append(
        f'<p>{_escape(item.get("name"))} — '
        f'<span class="fp">{_escape(item.get("path"))}</span>'
        f'{_escape(prefix)}</p>')
  return parts


def _render_packages(section: dict) -> list[str]:
  packages = section.get('packages')
  if not packages:
    return []
  if packages.get('available'):
    sample = ', '.join(packages.get('sample') or [])
    text = f'{packages.get("count", 0)} installed packages'
    if sample:
      text += f'. Notable: {sample}'
    return [f'<p>{_escape(text)}.</p>']
  if packages.get('message'):
    return [f'<p class="info">{_escape(packages.get("message"))}</p>']
  return []


def _render_problems(section: dict, kind: str) -> list[str]:
  if kind == 'ssh':
    return []
  parts = []
  for item in section.get('unreadable') or []:
    parts.append(
        f'<div class="err">Could not read '
        f'<span class="fp">{_escape(item.get("path"))}</span> — '
        f'{_escape(item.get("error"))}</div>')
  return parts


def _render_private(section: dict) -> list[str]:
  parts = []
  skipped = section.get('private_skipped') or []
  for item in skipped[:40]:
    parts.append(
        '<p class="skip"><strong>Private key not read.</strong> '
        f'<span class="fp">{_escape(item.get("path"))}</span> — '
        f'{_escape(item.get("reason"))}</p>')
  hidden = len(skipped) - 40
  if hidden > 0:
    parts.append(f'<p class="meta">{hidden} more private-key files skipped.</p>')
  return parts


def _render_unsupported(section: dict, kind: str) -> list[str]:
  parts = []
  if kind == 'ssh':
    for item in section.get('unsupported') or []:
      parts.append(
          f'<p class="meta">Not checked: {_escape(item.get("key_type"))} '
          f'line {_escape(item.get("line_number"))} — '
          f'<span class="fp">{_escape(item.get("path"))}</span></p>')
    return parts
  for item in (section.get('unsupported') or [])[:20]:
    parts.append(
        f'<p class="meta">Not checked ({_escape(item.get("detail"))}) — '
        f'<span class="fp">{_escape(item.get("path"))}</span></p>')
  return parts


def _render_ssh_sources(section: dict) -> list[str]:
  sources = section.get('sources') or []
  if not sources:
    return []
  parts = ['<table><tr><th>Path</th><th>Status</th><th>Keys</th></tr>']
  for source in sources:
    counts = (f'RSA {source.get("rsa_count", 0)}, '
              f'EC {source.get("ec_count", 0)}, '
              f'other {source.get("unsupported_count", 0)}')
    note = source.get('parse_error') or source.get('error') or ''
    detail = f' — {_escape(note)}' if note else ''
    parts.append(
        f'<tr><td class="fp">{_escape(source.get("path"))}</td>'
        f'<td>{_escape(source.get("status"))}{detail}</td>'
        f'<td>{_escape(counts)}</td></tr>')
  parts.append('</table>')
  return parts


def _render_result_card(title: str, section: dict | None, kind: str) -> list[str]:
  section = section or {}
  badge_class, badge = _card_badge(section, kind)
  parts = [
      f'<article class="result" id="result-{kind}">',
      '<header class="result-head">',
      f'<h2>{_escape(title)}</h2>',
      f'<p class="count">{_escape(_count_label(section, kind))}</p>',
      f'<p class="badge {badge_class}">{_escape(badge)}</p>',
      '</header>',
  ]
  if not _section_requested(section, kind):
    parts.append('<p class="info">Not included in this confirmation.</p></article>')
    return parts
  parts.extend(_render_system_roots(section.get('skipped') or []))
  parts.extend(_render_empty(section, kind))
  parts.extend(_render_discovered(section))
  parts.extend(_render_packages(section))
  open_attr = ' open' if _details_open(section, kind) else ''
  parts.append(f'<details class="files"{open_attr}>')
  parts.append('<summary>Files and checks</summary>')
  if kind == 'ssh':
    parts.extend(_render_ssh_sources(section))
  parts.extend(_render_other_skips(section.get('skipped') or []))
  parts.extend(_render_problems(section, kind))
  parts.extend(_render_private(section))
  parts.extend(_render_unsupported(section, kind))
  hide = 'SSH' if kind == 'ssh' else None
  parts.extend(_render_keys(section.get('keys') or [], hide_group=hide))
  for note in section.get('notes') or []:
    parts.append(f'<p class="meta">{_escape(note)}</p>')
  if kind != 'ssh':
    parts.append(
        f'<p class="meta">{_key_count(section)} public keys checked, '
        f'{int(section.get("files_read") or 0)} files read.</p>')
  parts.append('</details></article>')
  return parts


def _render_tls_card(tls: dict | None) -> list[str]:
  if not tls or not tls.get('requested'):
    return []
  exit_code = tls.get('exit_code')
  if tls.get('skipped'):
    badge_class, badge = 'badge-skip', 'skipped'
  elif exit_code == 1:
    badge_class, badge = 'badge-warn', '1 needs attention'
  elif exit_code == 2 or exit_code is None:
    badge_class, badge = 'badge-incomplete', 'incomplete'
  else:
    badge_class, badge = 'badge-clean', 'clean'
  host = tls.get('host') or ''
  port = tls.get('port')
  where = f'{host}:{port}' if host else 'TLS host'
  parts = [
      '<article class="result result-wide" id="result-tls">',
      '<header class="result-head">',
      '<h2>TLS</h2>',
      f'<p class="count">{_escape(where)}</p>',
      f'<p class="badge {badge_class}">{_escape(badge)}</p>',
      '</header>',
  ]
  if tls.get('skipped') or not tls.get('report'):
    message = tls.get('message') or 'TLS check did not finish.'
    box = 'skip' if tls.get('skipped') else 'err'
    parts.append(f'<p class="{box}">{_escape(message)}</p>')
  else:
    for check in tls['report'].get('checks') or []:
      parts.append(
          f'<p><strong>{_escape(check.get("name"))}</strong> '
          f'{_escape(check.get("status"))} — '
          f'{_escape(check.get("reason"))}</p>')
  parts.append('</article>')
  return parts


def _render_status(report: dict) -> list[str]:
  status = report.get('overall_status') or 'incomplete'
  title, css = _status_view(status)
  meta = (
      f'Host {_escape(report.get("machine_hostname"))} · '
      f'{_escape(report.get("timestamp"))} · Bastion '
      f'{_escape(report.get("bastion_version"))} · witness '
      f'{_escape(report.get("witness_version"))}'
  )
  return [
      f'<section class="{css}" id="confirmation" role="status">',
      f'<p class="status-label">{title}</p>',
      f'<p class="status-reason">{_escape(_plain_reason(report))}</p>',
      '</section>',
      f'<p class="meta run-meta">{meta}</p>',
  ]


def _render_results(report: dict) -> list[str]:
  parts = ['<section class="results" id="results">']
  parts.extend(_render_result_card('Browsers', report.get('browsers'), 'browsers'))
  parts.extend(_render_result_card(
      'Installed apps', report.get('apps'), 'apps'))
  parts.extend(_render_result_card('SSH', report.get('ssh'), 'ssh'))
  parts.extend(_render_tls_card(report.get('tls')))
  parts.append('</section>')
  return parts


def _render_intro() -> list[str]:
  return [
      '<header class="intro">',
      '<h1>Witness this machine</h1>',
      '<p class="sub">Checks public keys and certificates on this computer, '
      'then confirms the result.</p>',
      '</header>',
  ]


def _render_form(form: dict) -> list[str]:
  extra_text = '\n'.join(form.get('extra_paths') or [])
  extra_open = ' open' if extra_text else ''
  return [
      '<form method="POST" action="/">',
      '<fieldset class="choices">',
      '<legend>On this machine</legend>',
      _choice(
          'scan_browsers', 'Browsers',
          'Chrome, Chromium, Edge, Firefox',
          bool(form.get('scan_browsers', True))),
      _choice(
          'scan_apps', 'Installed apps',
          'package list and public certs in app config',
          bool(form.get('scan_apps', True))),
      _choice(
          'scan_ssh', 'SSH',
          'authorized_keys and known_hosts',
          bool(form.get('scan_ssh', True))),
      '</fieldset>',
      '<div class="tls">',
      '<label for="tls_host">Optional TLS host</label>',
      '<div class="tls-row">',
      f'<input id="tls_host" name="tls_host" type="text" '
      f'value="{_escape(form.get("tls_host"))}" '
      f'placeholder="Leave blank to skip" autocomplete="off">',
      f'<input id="tls_port" name="tls_port" type="number" min="1" '
      f'max="65535" aria-label="TLS port" '
      f'value="{_escape(form.get("tls_port", 443))}">',
      '</div></div>',
      f'<details class="extra"{extra_open}>',
      '<summary>Add an SSH file</summary>',
      '<label for="extra_paths">One path per line, if it is not in the '
      'usual SSH folder.</label>',
      f'<textarea id="extra_paths" name="extra_paths">'
      f'{_escape(extra_text)}</textarea>',
      '</details>',
      '<button class="primary" type="submit">Confirm this machine</button>',
      '</form>',
  ]


def _page(form: dict | None, report: dict | None, error: str | None) -> bytes:
  form = form or _default_form()
  parts = [
      '<!DOCTYPE html><html lang="en"><head>',
      '<meta charset="utf-8">',
      '<meta name="viewport" content="width=device-width, initial-scale=1">',
      f'<title>Bastion witness {__version__}</title>',
      f'<style>{_PAGE_CSS}</style></head><body>',
  ]
  if report:
    parts.extend(_render_status(report))
  parts.extend(_render_intro())
  if error:
    parts.append(f'<div class="err">{_escape(error)}</div>')
  if report:
    parts.extend(_render_results(report))
  parts.extend(_render_form(form))
  parts.append(
      '<p class="footer">Runs on this computer only. Private keys are not '
      'read. Nothing is uploaded.</p>')
  parts.append('</body></html>')
  return ''.join(parts).encode('utf-8')


class WitnessHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
  """Serve the witness form and results."""

  server_version = f'witness/{__version__}'

  def log_message(self, fmt, *args):
    return

  def _send(self, code: int, body: bytes, content_type: str = 'text/html; charset=utf-8'):
    self.send_response(code)
    self.send_header('Content-Type', content_type)
    self.send_header('Content-Security-Policy', _CSP)
    self.send_header('X-Content-Type-Options', 'nosniff')
    self.send_header('Content-Length', str(len(body)))
    self.end_headers()
    self.wfile.write(body)

  def do_GET(self):
    if self.path.split('?', 1)[0] not in ('/', '/index.html'):
      self._send(404, b'Not found')
      return
    self._send(200, _page(None, None, None))

  def do_POST(self):
    if self.path.split('?', 1)[0] != '/':
      self._send(404, b'Not found')
      return
    length = int(self.headers.get('Content-Length', 0))
    if length > MAX_BODY_BYTES:
      self._send(413, _page(None, None, 'Form submission is too large.'))
      return
    body = self.rfile.read(length)
    form = _parse_form(body)
    if not (form['scan_ssh'] or form['scan_browsers'] or form['scan_apps']
            or form['extra_paths'] or form['tls_host']):
      self._send(
          400,
          _page(form, None,
                'Select SSH, browsers, installed apps, an extra path, or a TLS hostname.'))
      return
    try:
      report = WITNESS_RUNNER(
          ssh_paths=form['extra_paths'],
          scan_home_ssh=form['scan_ssh'],
          include_etc_ssh=form['scan_ssh'],
          tls_host=form['tls_host'] or None,
          tls_port=form['tls_port'],
          scan_browsers=form['scan_browsers'],
          scan_apps=form['scan_apps'])
    except Exception as exc:  # pylint: disable=broad-except
      self._send(500, _page(form, None, f'Witness checks could not run: {exc}'))
      return
    self._send(200, _page(form, report, None))


class ThreadingWitnessServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
  daemon_threads = True
  allow_reuse_address = True


def main(argv=None) -> None:
  parser = argparse.ArgumentParser(description='Bastion witness local web UI')
  parser.add_argument('--port', type=int, default=DEFAULT_PORT)
  parser.add_argument('--host', default='127.0.0.1')
  args = parser.parse_args(argv)
  if args.host not in ('127.0.0.1', 'localhost'):
    raise SystemExit('witness web binds to localhost only')
  with ThreadingWitnessServer((args.host, args.port), WitnessHTTPRequestHandler) as httpd:
    print(f'witness {__version__} listening on http://{args.host}:{args.port}/')
    try:
      httpd.serve_forever()
    except KeyboardInterrupt:
      print('\nStopped.')


if __name__ == '__main__':
  main()
