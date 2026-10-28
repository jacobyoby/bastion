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
"""Offline tests for the tlscheck web page.

The handler is exercised over HTTP on 127.0.0.1 with a fake checker.
No live TLS server is required.
"""

import os
import subprocess
import sys
import threading
import unittest
import urllib.parse
import urllib.request

from tlscheck.errors import TlscheckError
from tlscheck.web import TlscheckServer
from tlscheck.web import parse_listen


_FINGERPRINT = 'ab' * 32


class _Report:
  def __init__(self, data: dict):
    self.data = data

  def to_dict(self) -> dict:
    return self.data


def _pass_report() -> _Report:
  leaf = {
      'subject': 'CN=example.com',
      'fingerprint_sha256': _FINGERPRINT,
      'not_after': '2027-03-04T05:06:07+00:00',
  }
  chain = [
      {'subject': 'CN=example.com', 'source': 'presented'},
      {'subject': 'CN=Example Root', 'source': 'trust-anchor'},
  ]
  return _Report({
      'host': 'example.com',
      'port': 443,
      'name': 'www.example.com',
      'peer_ip': '203.0.113.10',
      'peer_port': 443,
      'tls_version': 'TLSv1.3',
      'sni': 'www.example.com',
      'bundle_id': 'certifi test',
      'leaf': leaf,
      'chains': {
          'presented': {
              'status': 'pass',
              'reason': 'path <built>',
              'certificates': chain,
          },
          'fetched': {
              'status': 'pass',
              'reason': 'same path',
              'certificates': chain,
          },
      },
      'checks': [
          {'name': 'presented', 'status': 'pass', 'reason': 'path <built>'},
          {'name': 'fetched', 'status': 'pass', 'reason': 'same path'},
          {'name': 'eku', 'status': 'pass', 'reason': 'serverAuth'},
          {'name': 'signature', 'status': 'pass', 'reason': 'acceptable'},
          {'name': 'public_key', 'status': 'pass', 'reason': 'acceptable'},
          {'name': 'validity', 'status': 'pass', 'reason': 'inside dates'},
          {'name': 'lifetime', 'status': 'pass', 'reason': 'within 398 days'},
          {'name': 'hostname', 'status': 'pass', 'reason': 'name matches'},
          {'name': 'revocation', 'status': 'skipped',
           'reason': 'no staple and no must-staple'},
          {'name': 'pin', 'status': 'skipped', 'reason': 'no pins set'},
      ],
      'exit_code': 0,
  })


class WebHandlerTest(unittest.TestCase):

  def setUp(self):
    self.calls = []
    self.server = None

  def tearDown(self):
    if self.server is not None:
      self.server.shutdown()
      self.server.server_close()
      self.server = None

  def _start(self, checker):
    self.server = TlscheckServer(0, checker=checker)
    self.assertEqual(self.server.server_address[0], '127.0.0.1')
    thread = threading.Thread(target=self.server.serve_forever, daemon=True)
    thread.start()
    self.url = 'http://127.0.0.1:%d/' % self.server.server_address[1]

  def _request(self, method: str, fields=None):
    data = None
    headers = {}
    if fields is not None:
      data = urllib.parse.urlencode(fields).encode('utf-8')
      headers['Content-Type'] = 'application/x-www-form-urlencoded'
    request = urllib.request.Request(
        self.url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=5) as response:
      body = response.read().decode('utf-8')
      return response.status, body

  def test_get_shows_the_form(self):
    self._start(self._fail_if_called)
    status, body = self._request('GET')
    self.assertEqual(status, 200)
    self.assertIn('<form id="check-form"', body)
    self.assertIn('name="host"', body)
    self.assertIn('required', body)
    self.assertIn('value="443"', body)
    self.assertIn('name="sni"', body)
    self.assertIn('name="name"', body)
    self.assertIn('name="allow_fetched"', body)
    self.assertEqual(self.calls, [])

  def test_missing_host_is_an_error(self):
    self._start(self._fail_if_called)
    status, body = self._request('POST', {'host': '   ', 'port': '443'})
    self.assertEqual(status, 200)
    self.assertIn(
        '<p class="banner server-error" role="alert">a hostname is required</p>',
        body)
    self.assertNotIn('Traceback', body)
    self.assertNotIn('id="result"', body)
    self.assertEqual(self.calls, [])

  def test_pass_result_renders(self):
    def checker(host, port, sni, name, allow_fetched):
      self.calls.append({
          'host': host,
          'port': port,
          'sni': sni,
          'name': name,
          'allow_fetched': allow_fetched,
      })
      return _pass_report()

    self._start(checker)
    status, body = self._request('POST', {
        'host': 'example.com',
        'port': '443',
        'sni': 'www.example.com',
        'name': 'www.example.com',
        'allow_fetched': '1',
    })
    self.assertEqual(status, 200)
    self.assertEqual(self.calls, [{
        'host': 'example.com',
        'port': 443,
        'sni': 'www.example.com',
        'name': 'www.example.com',
        'allow_fetched': True,
    }])
    self.assertIn('class="result result-pass"', body)
    self.assertIn('Result: <strong>pass</strong>', body)
    self.assertIn('Required path: fetched', body)
    for name in (
        'presented', 'fetched', 'eku', 'signature', 'public_key',
        'validity', 'lifetime', 'hostname', 'revocation', 'pin'):
      self.assertIn('<span class="name">' + name + '</span>', body)
    self.assertIn('class="status-pass"', body)
    self.assertIn('class="status-skipped"', body)
    self.assertNotIn('class="status-fail"', body)
    self.assertIn('no staple and no must-staple', body)
    self.assertIn('path &lt;built&gt;', body)
    self.assertNotIn('path <built>', body)
    self.assertIn('<dt>Subject</dt><dd>CN=example.com</dd>', body)
    self.assertIn(
        '<dt>SHA-256</dt><dd class="mono">' + _FINGERPRINT + '</dd>', body)
    self.assertIn(
        '<dt>notAfter</dt><dd class="mono">2027-03-04T05:06:07+00:00</dd>',
        body)
    self.assertIn('<dt>Peer</dt><dd>203.0.113.10:443</dd>', body)
    self.assertIn('<dt>TLS</dt><dd>TLSv1.3</dd>', body)
    self.assertIn('<dt>SNI</dt><dd>www.example.com</dd>', body)
    self.assertIn('Presented chain', body)
    self.assertIn('Fetched chain', body)
    self.assertIn('CN=Example Root', body)
    self.assertIn('trust-anchor', body)
    self.assertIn('certifi test', body)
    self.assertIn('203.0.113.10:443', body)
    self.assertIn('TLSv1.3', body)
    self.assertIn('www.example.com', body)
    self.assertIn('<form id="check-form"', body)
    self.assertIn('value="example.com"', body)
    self.assertNotIn('Traceback', body)
    self.assertNotIn('BEGIN PRIVATE', body)
    self.assertNotIn('server-error', body)

  def test_connect_failure_renders_as_an_error(self):
    def checker(host, port, sni, name, allow_fetched):
      del host, port, sni, name, allow_fetched
      self.calls.append('called')
      raise TlscheckError(
          'could not connect to example.com:443: <refused>')

    self._start(checker)
    status, body = self._request('POST', {'host': 'example.com', 'port': '443'})
    self.assertEqual(status, 200)
    self.assertEqual(self.calls, ['called'])
    self.assertIn('class="banner server-error"', body)
    self.assertIn('could not connect to example.com:443: &lt;refused&gt;', body)
    self.assertNotIn('<refused>', body)
    self.assertNotIn('Traceback', body)
    self.assertNotIn('id="result"', body)
    self.assertIn('value="example.com"', body)

  def _fail_if_called(self, **kwargs):
    self.calls.append(kwargs)
    raise AssertionError('checker should not run')


class WebListenTest(unittest.TestCase):

  def test_listen_stays_on_loopback(self):
    self.assertEqual(parse_listen('8765'), 8765)
    self.assertEqual(parse_listen(' 127.0.0.1:9000 '), 9000)
    self.assertEqual(parse_listen('localhost:9001'), 9001)
    for bad in ('0.0.0.0:80', '192.168.1.2:80', '[::1]:80', '::1', '0',
                '65536', ''):
      with self.assertRaises(TlscheckError):
        parse_listen(bad)
    server = TlscheckServer(0, checker=lambda **kwargs: None)
    self.addCleanup(server.server_close)
    self.assertEqual(server.server_address[0], '127.0.0.1')

  def test_module_help(self):
    env = os.environ.copy()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env['PYTHONPATH'] = root + os.pathsep + env.get('PYTHONPATH', '')
    proc = subprocess.run(
        [sys.executable, '-m', 'tlscheck.web', '--help'],
        cwd=root, env=env, capture_output=True, text=True, check=False)
    self.assertEqual(proc.returncode, 0, proc.stderr)
    self.assertIn('--listen', proc.stdout)
    self.assertIn('127.0.0.1', proc.stdout)
    self.assertIn('8765', proc.stdout)


if __name__ == '__main__':
  unittest.main()
