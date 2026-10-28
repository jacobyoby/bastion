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


def _parse_form(body: bytes) -> dict:
  data = urllib.parse.parse_qs(body.decode('utf-8', errors='replace'),
                               keep_blank_values=True)
  scan_home = data.get('scan_home', ['off'])[0] in ('on', '1', 'true', 'yes')
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
      'scan_home': scan_home,
      'extra_paths': extra,
      'tls_host': tls_host,
      'tls_port': tls_port,
  }


def _page(form: dict | None, report: dict | None, error: str | None) -> bytes:
  form = form or {
      'scan_home': True,
      'extra_paths': [],
      'tls_host': '',
      'tls_port': 443,
  }
  extra_text = '\n'.join(form.get('extra_paths') or [])
  parts = [
      '<!DOCTYPE html><html lang="en"><head>',
      '<meta charset="utf-8">',
      '<meta name="viewport" content="width=device-width, initial-scale=1">',
      f'<title>Bastion witness {__version__}</title>',
      '<style>',
      'body{font-family:system-ui,sans-serif;margin:0 auto;padding:1rem;'
      'max-width:52rem;line-height:1.45;color:#1a1a1a;background:#fafafa}',
      'h1{font-size:1.5rem;margin:0 0 .5rem}',
      '.sub{color:#555;margin:0 0 1.25rem}',
      'form{background:#fff;border:1px solid #ddd;border-radius:8px;'
      'padding:1rem;margin-bottom:1rem}',
      'label{display:block;font-weight:600;margin:.75rem 0 .25rem}',
      'input[type=text],input[type=number],textarea{width:100%;box-sizing:border-box;'
      'padding:.5rem;border:1px solid #ccc;border-radius:4px;font:inherit}',
      'textarea{min-height:5rem;font-family:ui-monospace,monospace}',
      'button{margin-top:1rem;padding:.6rem 1.2rem;font:inherit;border:0;'
      'border-radius:6px;background:#1a5fb4;color:#fff;cursor:pointer}',
      'button:hover{background:#1c71d8}',
      '.banner{padding:1rem;border-radius:8px;margin:1rem 0;font-weight:600}',
      '.banner-ok{background:#d5f5e3;border:1px solid #27ae60}',
      '.banner-warn{background:#fdebd0;border:1px solid #e67e22}',
      '.banner-incomplete{background:#ebf5fb;border:1px solid #3498db}',
      '.err{color:#c0392b;background:#fadbd8;padding:.75rem;border-radius:6px}',
      'details{background:#fff;border:1px solid #ddd;border-radius:8px;'
      'padding:.5rem 1rem;margin:.75rem 0}',
      'summary{cursor:pointer;font-weight:600}',
      'table{width:100%;border-collapse:collapse;font-size:.9rem}',
      'th,td{border-bottom:1px solid #eee;padding:.35rem;text-align:left}',
      'tr.fail td{color:#922}',
      '.meta{font-size:.85rem;color:#555}',
      '</style></head><body>',
      '<h1>Witness this machine</h1>',
      '<p class="sub">Local cryptographic witness checks (127.0.0.1 only). '
      'Reads public SSH material; never asks for private keys.</p>',
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
    ssh = report.get('ssh') or {}
    parts.append('<details open><summary>SSH sources</summary><table>')
    parts.append('<tr><th>Path</th><th>Status</th><th>Keys</th></tr>')
    for source in ssh.get('sources') or []:
      counts = (f'RSA {source.get("rsa_count", 0)}, EC {source.get("ec_count", 0)}, '
                f'other {source.get("unsupported_count", 0)}')
      note = source.get('parse_error') or source.get('error') or ''
      parts.append(
          f'<tr><td>{_escape(source.get("path"))}</td>'
          f'<td>{_escape(source.get("status"))}{(" — " + _escape(note)) if note else ""}</td>'
          f'<td>{_escape(counts)}</td></tr>')
    parts.append('</table></details>')

    parts.append('<details open><summary>SSH keys</summary>')
    keys = ssh.get('keys') or []
    if not keys:
      parts.append('<p>No RSA or EC keys were found in scanned sources.</p>')
    for key in keys:
      weak = key.get('weak')
      label = 'Needs attention' if weak else 'OK'
      parts.append(
          f'<details><summary>{_escape(key.get("type"))} · '
          f'SHA256:{_escape(key.get("fingerprint_sha256"))} · {label}</summary>')
      if key.get('checks'):
        parts.append('<table><tr><th>Check</th><th>Result</th><th>Severity</th></tr>')
        for check in key['checks']:
          failed = check.get('failed')
          cls = ' class="fail"' if failed else ''
          result = 'fail' if failed else 'pass'
          parts.append(
              f'<tr{cls}><td>{_escape(check.get("name"))}</td>'
              f'<td>{result}</td><td>{_escape(check.get("severity"))}</td></tr>'
              f'<tr{cls}><td colspan="3" class="meta">'
              f'{_escape(check.get("blurb"))}</td></tr>')
        parts.append('</table>')
      parts.append('</details>')
    parts.append('</details>')

    tls = report.get('tls') or {}
    if tls.get('requested'):
      parts.append('<details open><summary>TLS witness</summary>')
      if tls.get('skipped'):
        parts.append(f'<p>{_escape(tls.get("message"))}</p>')
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

  parts.extend([
      '<form method="POST" action="/">',
      '<label><input type="checkbox" name="scan_home" value="on" ',
      'checked' if form.get('scan_home') else '',
      '> Scan ~/.ssh/authorized_keys and known_hosts (and /etc/ssh/*.pub when readable)</label>',
      '<label for="extra_paths">Extra paths (one per line)</label>',
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
    if not form['scan_home'] and not form['extra_paths']:
      self._send(
          400,
          _page(form, None,
                'Enable home SSH scan or provide at least one extra path.'))
      return
    try:
      report = WITNESS_RUNNER(
          ssh_paths=form['extra_paths'],
          scan_home_ssh=form['scan_home'],
          tls_host=form['tls_host'] or None,
          tls_port=form['tls_port'])
    except Exception as exc:  # pylint: disable=broad-except
      self._send(500, _page(form, None, f'Witness checks could not run: {exc}'))
      return
    self._send(200, _page(form, report, None))


class ThreadingWitnessServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
  daemon_threads = True
  allow_reuse_address = True


def main(argv=None) -> None:
  import argparse

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
