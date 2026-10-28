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
"""Offline tests for witness web handlers."""

import io
import unittest
from unittest import mock

import witness.web as web


def _fake_report():
  return {
      'machine_hostname': 'test-host',
      'timestamp': '2026-01-01T00:00:00+00:00',
      'bastion_version': '1.1.1',
      'witness_version': web.__version__,
      'overall_status': 'confirmed',
      'overall_summary': 'Confirmed — all good.',
      'ssh': {'sources': [], 'keys': [], 'unsupported': []},
      'tls': {'requested': False, 'skipped': True, 'message': 'No TLS hostname.'},
  }


def _handler():
  handler = web.WitnessHTTPRequestHandler.__new__(web.WitnessHTTPRequestHandler)
  handler.path = '/'
  handler.wfile = io.BytesIO()
  handler.send_response = mock.Mock()
  handler.send_header = mock.Mock()
  handler.end_headers = mock.Mock()

  def _send(code, body, content_type='text/html; charset=utf-8'):
    handler._last = (code, body)

  handler._send = _send
  return handler


class WitnessWebTest(unittest.TestCase):

  def test_get_renders_form(self):
    handler = _handler()
    handler.do_GET()
    _code, body = handler._last
    text = body.decode('utf-8')
    self.assertEqual(_code, 200)
    self.assertIn('Witness this machine', text)
    self.assertIn('Run witness checks', text)
    self.assertIn('Scan SSH', text)
    self.assertIn('Scan browsers', text)
    self.assertIn('Scan installed apps', text)

  def test_post_empty_scan_rejected(self):
    handler = _handler()
    body = b'scan_home=off&extra_paths='
    handler.headers = {'Content-Length': str(len(body))}
    handler.rfile = io.BytesIO(body)
    handler.do_POST()
    _code, html_body = handler._last
    self.assertEqual(_code, 400)
    self.assertIn('extra path', html_body.decode('utf-8'))

  def test_post_runs_witness(self):
    with mock.patch.object(web, 'WITNESS_RUNNER', return_value=_fake_report()) as runner:
      handler = _handler()
      body = b'scan_home=on&extra_paths=&tls_host=&tls_port=443'
      handler.headers = {'Content-Length': str(len(body))}
      handler.rfile = io.BytesIO(body)
      handler.do_POST()
      _code, html_body = handler._last
      self.assertEqual(_code, 200)
      self.assertIn('Confirmed', html_body.decode('utf-8'))
      runner.assert_called_once()

  def test_post_renders_browser_section(self):
    report = _fake_report()
    report['overall_status'] = 'needs_attention'
    report['overall_summary'] = 'Needs attention — weak key.'
    report['browsers'] = {
        'requested': True,
        'none_found': False,
        'discovered': [{'name': 'FakeChrome', 'path': '/opt/fake',
                        'scanned_prefix': True}],
        'packages': None,
        'keys': [{
            'type': 'RSA',
            'fingerprint_sha256': 'abcFINGERPRINT',
            'weak': True,
            'path': '/opt/fake/cert.pem',
            'group': 'FakeChrome',
            'subject': 'CN=example',
            'checks': [{
                'name': 'CheckSizes',
                'failed': True,
                'severity': 'Medium',
                'blurb': 'RSA modulus size or shape is out of policy.',
            }],
        }],
        'skipped': [{
            'path': '/etc/ssl/certs/ca-certificates.crt',
            'status': 'skipped',
            'cert_count': 3,
            'not_a_pass': True,
            'reason': ('system trust bundle present, 3 certificates, '
                       'full weakness scan not run on public roots in this alpha'),
        }],
        'unreadable': [],
        'private_skipped': [],
        'unsupported': [],
        'notes': [],
        'weak_count': 1,
        'key_count': 1,
        'files_read': 1,
    }
    report['apps'] = {
        'requested': True,
        'none_found': False,
        'discovered': [],
        'packages': {
            'available': True,
            'count': 2,
            'sample': ['openssl'],
            'message': None,
        },
        'keys': [],
        'skipped': [],
        'unreadable': [],
        'private_skipped': [],
        'unsupported': [],
        'notes': [],
        'weak_count': 0,
        'key_count': 0,
        'files_read': 0,
    }
    with mock.patch.object(web, 'WITNESS_RUNNER', return_value=report):
      handler = _handler()
      body = b'scan_browsers=on&scan_apps=on&scan_ssh=off'
      handler.headers = {'Content-Length': str(len(body))}
      handler.rfile = io.BytesIO(body)
      handler.do_POST()
      _code, html_body = handler._last
    text = html_body.decode('utf-8')
    self.assertEqual(_code, 200)
    self.assertIn('Browsers', text)
    self.assertIn('FakeChrome', text)
    self.assertIn('abcFINGERPRINT', text)
    self.assertIn('/opt/fake/cert.pem', text)
    self.assertIn('CheckSizes', text)
    self.assertIn('Medium', text)
    self.assertIn('Needs attention', text)
    self.assertIn('Skipped — not a pass.', text)
    self.assertIn('full weakness scan not run', text)
    self.assertIn('Installed apps', text)
    self.assertIn('No weak keys in the files we could read', text)
    self.assertIn('openssl', text)


if __name__ == '__main__':
  unittest.main()
