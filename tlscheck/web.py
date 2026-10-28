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
"""Local page for one tlscheck run.

The page is served from this process and binds to 127.0.0.1 only. A submit
calls capture_tls and tlscheck.run.run_check, then renders that report.
The browser does not verify certificates. Nothing is stored, and the form
never asks for a private key.

  PYTHONPATH=. python -m tlscheck.web
  PYTHONPATH=. python -m tlscheck.web --listen 8765
"""

import argparse
import html
import sys
import traceback
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
from urllib.parse import parse_qs

from tlscheck import __version__
from tlscheck.capture import capture_tls
from tlscheck.errors import TlscheckError
from tlscheck.path import mozilla_trust_store
from tlscheck.run import run_check


DEFAULT_PORT = 8765
BIND_HOST = '127.0.0.1'
_MAX_BODY = 16384
_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; "
    "script-src 'unsafe-inline'; form-action 'self'; "
    "base-uri 'none'; frame-ancestors 'none'")

_PAGE_CSS = """
:root {
  color-scheme: light;
  --bg: #f6f4ef;
  --ink: #1b1916;
  --muted: #5e584e;
  --line: #ddd6c8;
  --paper: #fffdf9;
  --pass: #0e6a3a;
  --pass-bg: #e6f5ec;
  --fail: #9f1d1d;
  --fail-bg: #fdecea;
  --skip: #5e584e;
  --skip-bg: #f0ece4;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font: 16px/1.45 ui-sans-serif, system-ui, sans-serif;
  color: var(--ink);
  background: var(--bg);
}
main {
  max-width: 52rem;
  margin: 0 auto;
  padding: 1.5rem 1.25rem 3rem;
}
h1 { font-size: 1.6rem; line-height: 1.2; margin: 0; }
h2 { font-size: 1rem; margin: 1.25rem 0 0.45rem; }
.lede, .hint, .muted { color: var(--muted); }
.lede { margin: 0.35rem 0 1rem; }
form, .result {
  background: var(--paper);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 1rem;
}
.result { margin-bottom: 1rem; }
.fields {
  display: grid;
  grid-template-columns: minmax(0, 2fr) 6.5rem minmax(0, 1fr) minmax(0, 1fr);
  gap: 0.75rem;
}
label.field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  font-size: 0.85rem;
  color: var(--muted);
  min-width: 0;
}
input[type="text"], input[type="number"] {
  width: 100%;
  max-width: 100%;
  font: inherit;
  color: var(--ink);
  padding: 0.45rem 0.5rem;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: #fff;
}
input[aria-invalid="true"] { border-color: var(--fail); }
label.check {
  display: flex;
  align-items: flex-start;
  gap: 0.5rem;
  margin: 0.9rem 0 0.75rem;
}
.hint { display: block; font-size: 0.85rem; }
button {
  font: inherit;
  background: var(--ink);
  color: var(--paper);
  border: 0;
  border-radius: 6px;
  padding: 0.55rem 1rem;
  cursor: pointer;
}
button:disabled { opacity: 0.7; cursor: wait; }
:focus-visible { outline: 2px solid var(--ink); outline-offset: 2px; }
.banner {
  background: var(--fail-bg);
  color: var(--fail);
  border: 1px solid #f3c2bc;
  border-radius: 6px;
  padding: 0.65rem 0.75rem;
  margin: 0 0 1rem;
}
.overall { font-size: 1.35rem; margin: 0; }
.result-pass .overall strong { color: var(--pass); }
.result-fail .overall strong { color: var(--fail); }
.checks, ol.chain { list-style: none; padding: 0; margin: 0; }
.checks li, ol.chain li {
  display: grid;
  gap: 0.35rem 0.75rem;
  padding: 0.45rem 0;
  border-top: 1px solid var(--line);
  min-width: 0;
  align-items: baseline;
}
.checks li { grid-template-columns: 5.5rem 8.5rem minmax(0, 1fr); }
ol.chain li { grid-template-columns: 1.5rem 7.5rem minmax(0, 1fr); }
.badge {
  display: inline-block;
  width: fit-content;
  font-size: 0.78rem;
  padding: 0.1rem 0.45rem;
  border-radius: 999px;
}
.status-pass .badge { background: var(--pass-bg); color: var(--pass); }
.status-fail .badge { background: var(--fail-bg); color: var(--fail); }
.status-skipped .badge { background: var(--skip-bg); color: var(--skip); }
.src, .idx, dt { color: var(--muted); }
dl {
  display: grid;
  grid-template-columns: 8.5rem minmax(0, 1fr);
  gap: 0.35rem 0.75rem;
  margin: 0;
  align-items: baseline;
}
dt, dd { margin: 0; min-width: 0; }
.reason, .subject, .mono { overflow-wrap: anywhere; }
.mono { font-family: ui-monospace, monospace; font-size: 0.92em; }
footer { color: var(--muted); font-size: 0.85rem; margin-top: 1rem; }
footer p { margin: 0; }
@media (max-width: 36rem) {
  main { padding: 1rem 0.85rem 2rem; }
  h1 { font-size: 1.35rem; }
  .fields { grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); }
  .field-host, .field-name { grid-column: 1 / -1; }
  .checks li { grid-template-columns: 5.5rem minmax(0, 1fr); }
  .checks .reason { grid-column: 2; }
  ol.chain li { grid-template-columns: 1.5rem minmax(0, 1fr); }
  ol.chain .src, ol.chain .subject { grid-column: 2; }
  dl { grid-template-columns: 5.5rem minmax(0, 1fr); }
}
"""

_PAGE_SCRIPT = """
(function () {
  var form = document.getElementById('check-form');
  var host = document.getElementById('host');
  var error = document.getElementById('client-error');
  if (!form || !host || !error) return;
  function show() {
    error.hidden = false;
    host.setAttribute('aria-invalid', 'true');
  }
  function hide() {
    error.hidden = true;
    host.removeAttribute('aria-invalid');
  }
  host.addEventListener('invalid', function (event) {
    event.preventDefault();
    show();
  });
  host.addEventListener('input', function () {
    if (host.value.trim()) hide();
  });
  form.addEventListener('submit', function (event) {
    if (!host.value.trim()) {
      event.preventDefault();
      show();
      host.focus();
      return;
    }
    hide();
    var button = form.querySelector('button');
    if (button) {
      button.disabled = true;
      button.textContent = 'Checking...';
    }
  });
})();
"""


class _InputError(TlscheckError):
  """Bad form input, with the fields to show again."""

  def __init__(self, message: str, form: dict):
    super().__init__(message)
    self.form = form


def check_host(host: str, port: int, sni, name, allow_fetched: bool):
  """Capture one server and return the tlscheck.run.run_check report.

  Raises TlscheckError when the handshake or the input cannot be used.
  The capture contains public certificates only.
  """
  if not host or not str(host).strip():
    raise TlscheckError('a hostname is required')
  trust = mozilla_trust_store()
  captured = capture_tls(host, int(port), sni=sni or None)
  return run_check(
      captured.certificates,
      host=host,
      trust=trust,
      port=int(port),
      name=name or None,
      ocsp_mode='staple',
      crl_mode='off',
      staple=captured.staple,
      allow_fetched=bool(allow_fetched),
      peer_ip=captured.peer_ip,
      peer_port=captured.peer_port,
      tls_version=captured.tls_version,
      sni=captured.sni)


def parse_listen(value: str) -> int:
  """Return a TCP port. An address, if given, must be loopback.

  Accepted forms are '8765', '127.0.0.1:8765', and 'localhost:8765'.
  The server still binds 127.0.0.1.
  """
  text = (value or '').strip()
  if not text:
    raise TlscheckError('--listen needs a port')
  if text.startswith('['):
    raise TlscheckError('--listen must stay on 127.0.0.1')
  host = None
  port_text = text
  if ':' in text:
    host, port_text = text.rsplit(':', 1)
    if host not in ('127.0.0.1', 'localhost'):
      raise TlscheckError('--listen must stay on 127.0.0.1')
  if not port_text.isdigit():
    raise TlscheckError(f'--listen port {port_text!r} is not a number')
  port = int(port_text)
  if port < 1 or port > 65535:
    raise TlscheckError(f'port {port} is outside 1..65535')
  return port


def _blank_form() -> dict:
  return {
      'host': '',
      'port': 443,
      'port_text': '443',
      'sni': None,
      'name': None,
      'allow_fetched': False,
  }


def _first(parsed: dict, key: str) -> str:
  values = parsed.get(key) or []
  if not values:
    return ''
  return values[0]


def _parse_submission(body: bytes, content_type: str) -> dict:
  media = (content_type or '').split(';', 1)[0].strip().lower()
  if media != 'application/x-www-form-urlencoded':
    raise TlscheckError('expected a form submission')
  parsed = parse_qs(
      body.decode('utf-8', errors='replace'), keep_blank_values=True)
  host = _first(parsed, 'host').strip()
  port_text = _first(parsed, 'port').strip() or '443'
  sni = _first(parsed, 'sni').strip() or None
  name = _first(parsed, 'name').strip() or None
  allow = _first(parsed, 'allow_fetched').strip().lower()
  form = {
      'host': host,
      'port': 443,
      'port_text': port_text,
      'sni': sni,
      'name': name,
      'allow_fetched': allow in ('1', 'on', 'true', 'yes'),
  }
  if not port_text.isdigit():
    raise _InputError(f'port {port_text!r} is not a number', form)
  port = int(port_text)
  if port < 1 or port > 65535:
    raise _InputError(f'port {port} is outside 1..65535', form)
  form['port'] = port
  return form


def _esc(value) -> str:
  if value is None:
    return ''
  return html.escape(str(value), quote=True)


def _show(value) -> str:
  text = _esc(value)
  return text if text else '-'


def _row(label: str, value, mono: bool = False) -> str:
  klass = ' class="mono"' if mono else ''
  return (
      '<dt>' + _esc(label) + '</dt><dd' + klass + '>'
      + _show(value) + '</dd>')


def _peer_text(data: dict) -> str:
  ip = data.get('peer_ip')
  port = data.get('peer_port')
  if ip in (None, '') and port in (None, ''):
    return '-'
  ip_text = '-' if ip in (None, '') else str(ip)
  if port in (None, ''):
    return ip_text
  return ip_text + ':' + str(port)


def _check_rows(checks) -> str:
  if not isinstance(checks, list):
    return '<ul class="checks"></ul>'
  rows = []
  for check in checks:
    if not isinstance(check, dict):
      continue
    status = str(check.get('status') or '')
    kind = status if status in ('pass', 'fail', 'skipped') else 'skipped'
    rows.append(
        '<li class="status-' + kind + '">'
        '<span class="badge">' + _show(status) + '</span>'
        '<span class="name">' + _show(check.get('name')) + '</span>'
        '<span class="reason">' + _show(check.get('reason')) + '</span>'
        '</li>')
  return '<ul class="checks">' + ''.join(rows) + '</ul>'


def _chain_section(title: str, chain) -> str:
  if not isinstance(chain, dict):
    chain = {}
  items = []
  certs = chain.get('certificates') or []
  if isinstance(certs, list):
    for index, cert in enumerate(certs):
      if not isinstance(cert, dict):
        continue
      items.append(
          '<li><span class="idx">' + str(index) + '</span>'
          '<span class="src">' + _show(cert.get('source')) + '</span>'
          '<span class="subject">' + _show(cert.get('subject')) + '</span>'
          '</li>')
  if items:
    body = '<ol class="chain">' + ''.join(items) + '</ol>'
  else:
    body = '<p class="muted">No certificates in this chain.</p>'
  return (
      '<section class="chain"><h2>' + _esc(title) + ': '
      + _show(chain.get('status')) + '</h2>' + body
      + '<p class="reason">' + _show(chain.get('reason')) + '</p></section>')


def _result_html(data: dict, allow_fetched: bool) -> str:
  status = 'pass' if data.get('exit_code') == 0 else 'fail'
  required = 'fetched' if allow_fetched else 'presented'
  host = data.get('host') or ''
  port = data.get('port')
  target = host if port in (None, '') else f'{host}:{port}'
  chains = data.get('chains') if isinstance(data.get('chains'), dict) else {}
  leaf = data.get('leaf') if isinstance(data.get('leaf'), dict) else {}
  return (
      '<section id="result" class="result result-' + status + '">'
      '<p class="overall" role="status">Result: <strong>' + status
      + '</strong></p>'
      '<p class="target">' + _show(target) + '</p>'
      '<p class="muted">Required path: ' + _esc(required) + '</p>'
      '<h2>Checks</h2>' + _check_rows(data.get('checks'))
      + '<h2>Leaf</h2><dl>'
      + _row('Subject', leaf.get('subject'))
      + _row('SHA-256', leaf.get('fingerprint_sha256'), mono=True)
      + _row('notAfter', leaf.get('not_after'), mono=True)
      + '</dl>'
      + _chain_section('Presented chain', chains.get('presented'))
      + _chain_section('Fetched chain', chains.get('fetched'))
      + '<h2>Connection</h2><dl>'
      + _row('Bundle', data.get('bundle_id'))
      + _row('Peer', _peer_text(data))
      + _row('TLS', data.get('tls_version'))
      + _row('SNI', data.get('sni'))
      + _row('Name', data.get('name'))
      + '</dl></section>')


def _form_html(form: dict, error: str) -> str:
  checked = ' checked' if form.get('allow_fetched') else ''
  banner = ''
  if error:
    banner = (
        '<p class="banner server-error" role="alert">' + _esc(error) + '</p>')
  return (
      banner
      + '<form id="check-form" method="post" action="/" '
      + 'accept-charset="utf-8">'
      + '<p id="client-error" class="banner" role="alert" hidden>'
      + 'a hostname is required</p>'
      + '<div class="fields">'
      + '<label class="field field-host" for="host">Host'
      + '<input id="host" name="host" type="text" required '
      + 'autocomplete="off" spellcheck="false" placeholder="example.com" '
      + 'value="' + _esc(form.get('host') or '') + '"></label>'
      + '<label class="field field-port" for="port">Port'
      + '<input id="port" name="port" type="number" min="1" max="65535" '
      + 'inputmode="numeric" value="'
      + _esc(form.get('port_text') or '443') + '"></label>'
      + '<label class="field field-sni" for="sni">SNI'
      + '<input id="sni" name="sni" type="text" autocomplete="off" '
      + 'spellcheck="false" placeholder="defaults to host" value="'
      + _esc(form.get('sni') or '') + '"></label>'
      + '<label class="field field-name" for="name">Expected name'
      + '<input id="name" name="name" type="text" autocomplete="off" '
      + 'spellcheck="false" placeholder="defaults to host" value="'
      + _esc(form.get('name') or '') + '"></label>'
      + '</div>'
      + '<label class="check field-allow" for="allow_fetched">'
      + '<input id="allow_fetched" name="allow_fetched" type="checkbox" '
      + 'value="1"' + checked + '>'
      + '<span>Allow fetched chain'
      + '<span class="hint">Require the AIA-fetched path instead of the '
      + 'presented path.</span></span></label>'
      + '<div class="actions"><button type="submit">Check</button></div>'
      + '</form>')


def render_page(form: dict, report: dict = None, error: str = None) -> str:
  """Return the one page, with a report or an error when a check just ran."""
  host = form.get('host') or ''
  title = (host + ' - tlscheck') if host else 'tlscheck'
  intro = ''
  if report is None and not error:
    intro = (
        '<p class="lede">Check the certificate a TLS server presents. '
        'One check, on this machine, not saved.</p>')
  result = ''
  if report is not None:
    result = _result_html(report, bool(form.get('allow_fetched')))
  return (
      '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
      '<meta name="viewport" content="width=device-width, initial-scale=1">'
      '<title>' + _esc(title) + '</title><style>' + _PAGE_CSS + '</style>'
      '</head><body><main><header><h1>tlscheck</h1>'
      '<p class="muted">alpha ' + _esc(__version__) + '</p>'
      + intro + '</header>' + result + _form_html(form, error)
      + '<footer><p>Local only, on 127.0.0.1. No accounts and no saved '
      'checks. Same alpha limits as the command line: no Certificate '
      'Transparency, no operating system trust store. OCSP and CRL '
      'downloads stay off on this page; a stapled OCSP response is still '
      'checked.</p></footer></main><script>' + _PAGE_SCRIPT
      + '</script></body></html>')


def _report_dict(report) -> dict:
  to_dict = getattr(report, 'to_dict', None)
  if not callable(to_dict):
    raise TlscheckError('checker returned an unexpected result')
  data = to_dict()
  if not isinstance(data, dict):
    raise TlscheckError('checker returned an unexpected result')
  return data


class TlscheckHandler(BaseHTTPRequestHandler):
  """One form, one check, one rendered report."""

  server_version = 'tlscheck/' + __version__

  def do_GET(self):
    if self._route() != '/':
      self._text(404, 'not found')
      return
    self._html(render_page(_blank_form()))

  def do_POST(self):
    if self._route() != '/':
      self._text(404, 'not found')
      return
    try:
      body = self._read_body()
    except TlscheckError as exc:
      self._html(render_page(_blank_form(), error=str(exc)))
      return
    try:
      form = _parse_submission(body, self.headers.get('Content-Type', ''))
    except _InputError as exc:
      self._html(render_page(exc.form, error=str(exc)))
      return
    except TlscheckError as exc:
      self._html(render_page(_blank_form(), error=str(exc)))
      return
    if not form['host']:
      self._html(render_page(form, error='a hostname is required'))
      return
    try:
      report = self.server.checker(
          host=form['host'],
          port=form['port'],
          sni=form['sni'],
          name=form['name'],
          allow_fetched=form['allow_fetched'])
      page = render_page(form, report=_report_dict(report))
    except TlscheckError as exc:
      page = render_page(form, error=str(exc))
    except Exception:
      traceback.print_exc()
      page = render_page(
          form, error='tlscheck failed before a report was ready')
    self._html(page)

  def _route(self) -> str:
    return self.path.split('?', 1)[0]

  def _read_body(self) -> bytes:
    raw = self.headers.get('Content-Length')
    if raw is None:
      return b''
    try:
      length = int(raw)
    except ValueError as exc:
      raise TlscheckError('could not read the form') from exc
    if length < 0 or length > _MAX_BODY:
      raise TlscheckError('the form is too large')
    return self.rfile.read(length)

  def _html(self, page: str):
    body = page.encode('utf-8')
    self._send(200, body, 'text/html; charset=utf-8')

  def _text(self, status: int, text: str):
    self._send(status, text.encode('utf-8'), 'text/plain; charset=utf-8')

  def _send(self, status: int, body: bytes, content_type: str):
    self.send_response(status)
    self.send_header('Content-Type', content_type)
    self.send_header('Content-Length', str(len(body)))
    self.send_header('Cache-Control', 'no-store')
    self.send_header('X-Content-Type-Options', 'nosniff')
    self.send_header('Referrer-Policy', 'no-referrer')
    self.send_header('Content-Security-Policy', _CSP)
    self.send_header('Connection', 'close')
    self.end_headers()
    self.wfile.write(body)

  def log_message(self, fmt, *args):
    # The access line is the request path and status, never the form body
    # and never certificate bytes.
    sys.stderr.write(
        '%s - %s\n' % (self.address_string(), fmt % args))


class TlscheckServer(HTTPServer):
  """HTTP server bound to 127.0.0.1. checker runs one tlscheck."""

  allow_reuse_address = True

  def __init__(self, port: int, checker=None):
    self.checker = checker or check_host
    super().__init__((BIND_HOST, port), TlscheckHandler)


def serve(port: int, checker=None) -> None:
  """Listen until Ctrl-C. Bind address is always 127.0.0.1."""
  server = TlscheckServer(port, checker)
  print(f'tlscheck web UI on http://{BIND_HOST}:{port}/', flush=True)
  try:
    server.serve_forever()
  except KeyboardInterrupt:
    print('', flush=True)
  finally:
    server.server_close()


def main(argv=None) -> int:
  parser = argparse.ArgumentParser(
      prog='tlscheck.web',
      description=(
          'Serve a local page that runs one tlscheck at a time. '
          f'Alpha {__version__}. Binds to 127.0.0.1 only.'))
  parser.add_argument(
      '--listen', default=str(DEFAULT_PORT),
      help=(
          'port on 127.0.0.1, or 127.0.0.1:PORT '
          f'(default {DEFAULT_PORT}). Other addresses are rejected.'))
  args = parser.parse_args(argv)
  try:
    port = parse_listen(args.listen)
  except TlscheckError as exc:
    print(f'tlscheck: {exc}', file=sys.stderr)
    return exc.exit_code
  try:
    serve(port)
  except OSError as exc:
    print(
        f'tlscheck: could not listen on {BIND_HOST}: {exc}', file=sys.stderr)
    return 2
  return 0


if __name__ == '__main__':
  sys.exit(main())
