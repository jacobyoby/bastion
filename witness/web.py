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
body{font-family:system-ui,sans-serif;margin:0 auto;padding:1rem;
max-width:52rem;line-height:1.45;color:#1a1a1a;background:#fafafa}
h1{font-size:1.5rem;margin:0 0 .5rem}
h2{font-size:1.15rem;margin:0}
h3{font-size:1rem;margin:1rem 0 .35rem}
.sub{color:#555;margin:0 0 1.25rem}
form{background:#fff;border:1px solid #ddd;border-radius:8px;
padding:1rem;margin-bottom:1rem}
label{display:block;font-weight:600;margin:.75rem 0 .25rem}
label.check{display:flex;align-items:flex-start;gap:.55rem;font-weight:600;
margin:.65rem 0 .15rem}
input[type=checkbox]{width:1.15rem;height:1.15rem;margin-top:.15rem;flex:none}
.hint{font-weight:400;color:#555;margin:0 0 .45rem 1.7rem;font-size:.92rem}
input[type=text],input[type=number],textarea{width:100%;box-sizing:border-box;
padding:.55rem;border:1px solid #ccc;border-radius:4px;font:inherit}
textarea{min-height:5rem;font-family:ui-monospace,monospace}
button{margin-top:1rem;padding:.7rem 1.2rem;font:inherit;border:0;
border-radius:6px;background:#1a5fb4;color:#fff;cursor:pointer;width:100%}
button:hover{background:#1c71d8}
.banner{padding:1rem;border-radius:8px;margin:1rem 0;font-weight:600}
.banner-ok{background:#d5f5e3;border:1px solid #27ae60}
.banner-warn{background:#fdebd0;border:1px solid #e67e22}
.banner-incomplete{background:#ebf5fb;border:1px solid #3498db}
.err{color:#922;background:#fadbd8;padding:.75rem;border-radius:6px;margin:.5rem 0}
.skip{background:#f4f6f7;border:1px solid #95a5a6;border-radius:6px;
padding:.65rem .75rem;margin:.5rem 0}
.weak{background:#fdebd0;border:1px solid #e67e22;border-radius:8px;
padding:.35rem .75rem;margin:.55rem 0}
details{background:#fff;border:1px solid #ddd;border-radius:8px;
padding:.5rem 1rem;margin:.75rem 0}
.weak details,.skip details{border:0;background:transparent;padding:0;margin:0}
summary{cursor:pointer;font-weight:600}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th,td{border-bottom:1px solid #eee;padding:.4rem;text-align:left;vertical-align:top}
tr.fail td{color:#922}
.meta{font-size:.85rem;color:#555}
.fp{font-family:ui-monospace,monospace;word-break:break-all}
ul{margin:.35rem 0 .75rem;padding-left:1.2rem}
@media (max-width:40rem){
  body{padding:.75rem}
  table{display:block;overflow-x:auto}
}
"""


def _escape(value) -> str:
  return html.escape('' if value is None else str(value))


def _banner_class(status: str) -> str:
  if status == 'confirmed':
    return 'banner banner-ok'
  if status == 'needs_attention':
    return 'banner banner-warn'
  return 'banner banner-incomplete'


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


def _checkbox(name: str, label: str, checked: bool) -> str:
  mark = ' checked' if checked else ''
  return (f'<label class="check"><input type="checkbox" name="{name}" '
          f'value="on"{mark}> {_escape(label)}</label>')


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
      label = 'Needs attention' if weak else 'OK'
      box = 'weak' if weak else 'ok'
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


def _render_skipped(items: list[dict]) -> list[str]:
  parts = []
  for item in items or []:
    count = item.get('cert_count')
    count_text = f' ({count} certificates)' if isinstance(count, int) else ''
    parts.append(
        '<div class="skip"><strong>Skipped — not a pass.</strong> '
        f'<span class="fp">{_escape(item.get("path"))}</span>'
        f'{_escape(count_text)}<br>{_escape(item.get("reason"))}</div>')
  return parts


def _render_local(title: str, section: dict | None, hide_group: str | None = None) -> list[str]:
  parts = [f'<details open><summary><h2>{_escape(title)}</h2></summary>']
  if not section or not section.get('requested'):
    parts.append('<p>Not requested.</p></details>')
    return parts
  if section.get('none_found'):
    parts.append('<p>No browsers found on this machine.</p>')
  for item in section.get('discovered') or []:
    prefix = ''
    if item.get('scanned_prefix') is False:
      prefix = ' (no install prefix to scan)'
    parts.append(
        f'<p>{_escape(item.get("name"))} — '
        f'<span class="fp">{_escape(item.get("path"))}</span>'
        f'{_escape(prefix)}</p>')
  packages = section.get('packages')
  if packages:
    if packages.get('available'):
      sample = ', '.join(packages.get('sample') or [])
      text = f'{packages.get("count", 0)} installed packages'
      if sample:
        text += f'. Notable: {sample}'
      parts.append(f'<p>{_escape(text)}.</p>')
    else:
      parts.append(f'<p>{_escape(packages.get("message"))}</p>')
  parts.extend(_render_skipped(section.get('skipped') or []))
  for item in section.get('unreadable') or []:
    parts.append(
        f'<div class="err">Could not read '
        f'<span class="fp">{_escape(item.get("path"))}</span> — '
        f'{_escape(item.get("error"))}</div>')
  for item in (section.get('private_skipped') or [])[:40]:
    parts.append(
        '<div class="skip"><strong>Private key not read.</strong> '
        f'<span class="fp">{_escape(item.get("path"))}</span> — '
        f'{_escape(item.get("reason"))}</div>')
  hidden = len(section.get('private_skipped') or []) - 40
  if hidden > 0:
    parts.append(f'<p class="meta">{hidden} more private-key files skipped.</p>')
  for item in (section.get('unsupported') or [])[:20]:
    parts.append(
        f'<p class="meta">Not checked ({_escape(item.get("detail"))}) — '
        f'<span class="fp">{_escape(item.get("path"))}</span></p>')
  keys = section.get('keys') or []
  if not section.get('weak_count'):
    parts.append('<p>No weak keys in the files we could read.</p>')
  parts.append(
      f'<p class="meta">{section.get("key_count", 0)} public keys checked, '
      f'{section.get("files_read", 0)} files read.</p>')
  parts.extend(_render_keys(keys, hide_group=hide_group))
  for note in section.get('notes') or []:
    parts.append(f'<p class="meta">{_escape(note)}</p>')
  parts.append('</details>')
  return parts


def _render_ssh(ssh: dict) -> list[str]:
  parts = ['<details open><summary><h2>SSH</h2></summary>']
  if not ssh or not ssh.get('requested', True):
    parts.append('<p>Not requested.</p></details>')
    return parts
  parts.append('<table><tr><th>Path</th><th>Status</th><th>Keys</th></tr>')
  for source in ssh.get('sources') or []:
    counts = (f'RSA {source.get("rsa_count", 0)}, EC {source.get("ec_count", 0)}, '
              f'other {source.get("unsupported_count", 0)}')
    note = source.get('parse_error') or source.get('error') or ''
    detail = f' — {_escape(note)}' if note else ''
    parts.append(
        f'<tr><td class="fp">{_escape(source.get("path"))}</td>'
        f'<td>{_escape(source.get("status"))}{detail}</td>'
        f'<td>{_escape(counts)}</td></tr>')
  parts.append('</table>')
  for item in ssh.get('unsupported') or []:
    parts.append(
        f'<p class="meta">Not checked: {_escape(item.get("key_type"))} '
        f'line {_escape(item.get("line_number"))} — '
        f'<span class="fp">{_escape(item.get("path"))}</span></p>')
  keys = ssh.get('keys') or []
  if not ssh.get('weak_count'):
    parts.append('<p>No weak keys in the files we could read.</p>')
  parts.extend(_render_keys(keys, hide_group='SSH'))
  parts.append('</details>')
  return parts


def _render_tls(tls: dict) -> list[str]:
  parts = ['<details open><summary><h2>TLS</h2></summary>']
  if not tls or not tls.get('requested'):
    parts.append(f'<p>{_escape((tls or {}).get("message") or "Not requested.")}</p>')
    parts.append('</details>')
    return parts
  if tls.get('skipped'):
    parts.append(f'<div class="skip"><strong>Skipped.</strong> '
                 f'{_escape(tls.get("message"))}</div>')
  elif tls.get('report'):
    parts.append(
        f'<p class="meta">{_escape(tls.get("host"))}:'
        f'{_escape(tls.get("port"))} · exit '
        f'{_escape(tls.get("exit_code"))}</p>')
    for check in tls['report'].get('checks') or []:
      parts.append(
          f'<p><strong>{_escape(check.get("name"))}</strong> '
          f'{_escape(check.get("status"))} — '
          f'{_escape(check.get("reason"))}</p>')
  else:
    parts.append(
        f'<p class="err">{_escape(tls.get("message") or "TLS check failed.")}'
        f' (exit {_escape(tls.get("exit_code"))})</p>')
  parts.append('</details>')
  return parts


def _page(form: dict | None, report: dict | None, error: str | None) -> bytes:
  form = form or _default_form()
  extra_text = '\n'.join(form.get('extra_paths') or [])
  parts = [
      '<!DOCTYPE html><html lang="en"><head>',
      '<meta charset="utf-8">',
      '<meta name="viewport" content="width=device-width, initial-scale=1">',
      f'<title>Bastion witness {__version__}</title>',
      f'<style>{_PAGE_CSS}</style></head><body>',
      '<h1>Witness this machine</h1>',
      '<p class="sub">Local checks on this computer only (127.0.0.1). '
      'Public certificates and public keys. Private keys are not read into '
      'the report and nothing is uploaded.</p>',
  ]
  if error:
    parts.append(f'<div class="err">{_escape(error)}</div>')
  if report:
    status = report.get('overall_status', 'incomplete')
    parts.append(
        f'<div class="{_banner_class(status)}">'
        f'{_escape(report.get("overall_summary"))}</div>')
    parts.append(
        f'<p class="meta">Host {_escape(report.get("machine_hostname"))} · '
        f'{_escape(report.get("timestamp"))} · Bastion '
        f'{_escape(report.get("bastion_version"))} · witness '
        f'{_escape(report.get("witness_version"))}</p>')
    parts.extend(_render_local('Browsers', report.get('browsers')))
    parts.extend(_render_local('Installed apps', report.get('apps')))
    parts.extend(_render_ssh(report.get('ssh') or {}))
    parts.extend(_render_tls(report.get('tls') or {}))

  parts.extend([
      '<form method="POST" action="/">',
      _checkbox('scan_ssh', 'Scan SSH', bool(form.get('scan_ssh', True))),
      '<p class="hint">~/.ssh/authorized_keys, known_hosts, and readable '
      '/etc/ssh/*.pub</p>',
      _checkbox('scan_browsers', 'Scan browsers',
                bool(form.get('scan_browsers', True))),
      '<p class="hint">Installed Chrome, Chromium, Edge, and Firefox, plus the '
      'system trust bundle (counted, not fully scanned) and user-added CAs</p>',
      _checkbox('scan_apps', 'Scan installed apps',
                bool(form.get('scan_apps', True))),
      '<p class="hint">Package list, then public PEM, CRT, and OpenSSH files '
      'under /etc, /usr/local/share, /opt, and ~/.config</p>',
      '<label for="extra_paths">Extra SSH paths (one per line)</label>',
      f'<textarea id="extra_paths" name="extra_paths">{_escape(extra_text)}</textarea>',
      '<label for="tls_host">Optional TLS hostname</label>',
      f'<input id="tls_host" name="tls_host" type="text" '
      f'value="{_escape(form.get("tls_host"))}" placeholder="example.com">',
      '<label for="tls_port">TLS port</label>',
      f'<input id="tls_port" name="tls_port" type="number" min="1" max="65535" '
      f'value="{_escape(form.get("tls_port", 443))}">',
      '<button type="submit">Run witness checks</button>',
      '</form>',
      '</body></html>',
  ])
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
