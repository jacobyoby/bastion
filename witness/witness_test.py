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
"""Tests for witness SSH, browser, and installed-app scanning."""

import datetime
import os
import subprocess
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from paranoid_crypto.lib import ssh_keys_test

from witness.hostscan import group_for_path
from witness.hostscan import list_installed_packages
from witness.hostscan import scan_apps
from witness.material import inspect_bytes
from witness.report import compute_overall_status
from witness.run import witness_machine
from witness.run import witness_ssh_file


class WitnessTest(unittest.TestCase):

  def test_weak_rsa_detected_in_temp_file(self):
    with tempfile.NamedTemporaryFile('w', encoding='utf-8', delete=False) as handle:
      handle.write(ssh_keys_test._FERMAT_LINE + '\n')
      path = handle.name
    result = witness_ssh_file(path, ssh_keys_test._FERMAT_LINE + '\n')
    self.assertGreater(result['weak_count'], 0)
    weak_keys = [key for key in result['keys'] if key['weak']]
    self.assertTrue(weak_keys)
    failed = [row for row in weak_keys[0]['checks'] if row['failed']]
    self.assertTrue(failed)

  def test_good_ec_not_weak(self):
    result = witness_ssh_file('/tmp/good', ssh_keys_test._EC256_LINE + '\n')
    self.assertEqual(result['weak_count'], 0)

  def test_witness_machine_respects_extra_path(self):
    with tempfile.NamedTemporaryFile('w', encoding='utf-8', delete=False) as handle:
      handle.write(ssh_keys_test._FERMAT_LINE + '\n')
      path = handle.name
    report = witness_machine(
        ssh_paths=[path],
        scan_home_ssh=False,
        include_etc_ssh=False,
        scan_browsers=False,
        scan_apps=False)
    self.assertEqual(report['overall_status'], 'needs_attention')
    self.assertGreaterEqual(report['ssh']['weak_count'], 1)
    self.assertFalse(report['browsers']['requested'])
    self.assertFalse(report['apps']['requested'])

  def test_status_precedence(self):
    self.assertEqual(
        compute_overall_status(False, False, None, False, other_weak=True),
        'needs_attention')
    self.assertEqual(
        compute_overall_status(False, False, None, False, other_unreadable=True),
        'incomplete')
    self.assertEqual(
        compute_overall_status(True, True, None, False),
        'needs_attention')
    self.assertEqual(
        compute_overall_status(False, False, None, False),
        'confirmed')

  def test_group_for_path(self):
    self.assertEqual(group_for_path('/opt/nginx/ssl/a.pem'), '/opt/nginx')
    self.assertEqual(group_for_path('/etc/nginx/cert.pem'), '/etc/nginx')
    self.assertEqual(
        group_for_path('/home/user/.config/mozilla/cert.pem', home='/home/user'),
        '~/.config/mozilla')


class _MaterialBase(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'witness-test')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=2))
        .sign(key, hashes.SHA256()))
    cls.cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    cls.private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())


class LocalMaterialTest(_MaterialBase):

  def test_private_pem_is_ignored(self):
    parsed = inspect_bytes('/tmp/secret.pem', self.private_pem)
    self.assertTrue(parsed.private)
    self.assertEqual(parsed.keys, [])
    self.assertEqual(parsed.cert_count, 0)
    truncated = inspect_bytes(
        '/tmp/truncated.pem', b'-----BEGIN RSA PRIVATE KEY-----\nMIIE\n')
    self.assertTrue(truncated.private)
    self.assertEqual(truncated.keys, [])

  def test_app_scan_parses_cert_and_skips_private(self):
    with tempfile.TemporaryDirectory() as tmp:
      app = os.path.join(tmp, 'demo')
      os.makedirs(app)
      cert_path = os.path.join(app, 'app.crt')
      key_path = os.path.join(app, 'secret.pem')
      with open(cert_path, 'wb') as handle:
        handle.write(self.cert_pem)
      with open(key_path, 'wb') as handle:
        handle.write(self.private_pem)
      result = scan_apps(
          roots=[(tmp, 3)],
          list_packages=lambda: {
              'available': False,
              'count': 0,
              'sample': [],
              'message': 'skipped in test',
          },
          system_bundle_path=os.path.join(tmp, 'no-bundle.crt'),
          note_skipped_system_certs=False)
    self.assertEqual(len(result['keys']), 1)
    self.assertEqual(result['keys'][0].path, cert_path)
    self.assertIn('demo', result['keys'][0].group)
    self.assertEqual([item['path'] for item in result['private_skipped']], [key_path])
    self.assertNotIn(b'PRIVATE KEY', result['keys'][0].key.SerializeToString())

  def test_large_bundle_is_not_a_pass(self):
    with tempfile.TemporaryDirectory() as tmp:
      path = os.path.join(tmp, 'cacert.pem')
      with open(path, 'wb') as handle:
        handle.write(self.cert_pem)
      result = scan_apps(
          roots=[(tmp, 2)],
          list_packages=lambda: {
              'available': True, 'count': 0, 'sample': [], 'message': None,
          },
          bundle_cert_cap=0,
          system_bundle_path=os.path.join(tmp, 'missing-bundle.crt'))
    self.assertEqual(result['keys'], [])
    self.assertTrue(result['skipped'])
    self.assertTrue(result['skipped'][0]['not_a_pass'])
    self.assertIn('not a pass', result['skipped'][0]['reason'])

  def test_dpkg_missing_and_empty(self):
    missing = list_installed_packages(which=lambda _name: None)
    self.assertFalse(missing['available'])
    self.assertEqual(missing['count'], 0)
    self.assertIn('not installed', missing['message'])

    def _empty(*_args, **_kwargs):
      return subprocess.CompletedProcess((), 0, stdout='\n', stderr='')

    empty = list_installed_packages(
        which=lambda _name: '/usr/bin/dpkg-query', run=_empty)
    self.assertTrue(empty['available'])
    self.assertEqual(empty['count'], 0)
    self.assertEqual(empty['sample'], [])

  def test_no_browsers_is_not_a_failure(self):
    missing = '/tmp/witness-missing-bundle.crt'
    report = witness_machine(
        scan_home_ssh=False,
        include_etc_ssh=False,
        scan_browsers=True,
        scan_apps=False,
        browser_roots=[],
        discover_default_browsers=False,
        system_bundle_path=missing,
        user_ca_dir=missing + '.d',
        include_nss=False)
    self.assertEqual(report['overall_status'], 'confirmed')
    self.assertTrue(report['browsers']['none_found'])
    skipped = report['browsers']['skipped']
    self.assertTrue(any(item.get('not_a_pass') for item in skipped))
    self.assertTrue(any('full weakness scan' in item['reason'] for item in skipped))

  def test_browser_cert_appears_and_private_key_does_not(self):
    with tempfile.TemporaryDirectory() as tmp:
      browser = os.path.join(tmp, 'browser')
      os.makedirs(browser)
      cert_path = os.path.join(browser, 'cert.pem')
      key_path = os.path.join(browser, 'key.pem')
      bundle_path = os.path.join(tmp, 'ca-certificates.crt')
      with open(cert_path, 'wb') as handle:
        handle.write(self.cert_pem)
      with open(key_path, 'wb') as handle:
        handle.write(self.private_pem)
      with open(bundle_path, 'wb') as handle:
        handle.write(self.cert_pem)
      report = witness_machine(
          scan_home_ssh=False,
          include_etc_ssh=False,
          scan_browsers=True,
          scan_apps=False,
          browser_roots=[{'name': 'FakeChrome', 'path': browser}],
          discover_default_browsers=False,
          system_bundle_path=bundle_path,
          user_ca_dir=os.path.join(tmp, 'no-user-cas'),
          include_nss=False)
    self.assertEqual(report['overall_status'], 'confirmed')
    keys = report['browsers']['keys']
    self.assertEqual(len(keys), 1)
    self.assertEqual(keys[0]['path'], cert_path)
    self.assertEqual(keys[0]['type'], 'RSA')
    self.assertTrue(keys[0]['fingerprint_sha256'])
    self.assertTrue(keys[0]['checks'])
    self.assertFalse(keys[0]['weak'])
    self.assertIn('FakeChrome', keys[0]['group'])
    self.assertIn('witness-test', keys[0]['subject'] or '')
    paths = [item['path'] for item in report['browsers']['private_skipped']]
    self.assertIn(key_path, paths)
    self.assertNotIn(bundle_path, [key['path'] for key in keys])
    bundle = [item for item in report['browsers']['skipped']
              if item['path'] == bundle_path]
    self.assertEqual(len(bundle), 1)
    self.assertTrue(bundle[0]['not_a_pass'])
    self.assertEqual(bundle[0]['cert_count'], 1)
    self.assertIn('full weakness scan not run on public roots', bundle[0]['reason'])
    blob = str(report)
    self.assertNotIn('-----BEGIN PRIVATE KEY-----', blob)

  def test_unreadable_browser_root_is_incomplete(self):
    if os.geteuid() == 0:
      self.skipTest('root ignores directory mode')
    with tempfile.TemporaryDirectory() as tmp:
      locked = os.path.join(tmp, 'locked')
      os.makedirs(locked)
      os.chmod(locked, 0)
      try:
        report = witness_machine(
            scan_home_ssh=False,
            include_etc_ssh=False,
            scan_browsers=True,
            scan_apps=False,
            browser_roots=[{'name': 'Locked', 'path': locked}],
            discover_default_browsers=False,
            system_bundle_path=os.path.join(tmp, 'missing-bundle.crt'),
            user_ca_dir=os.path.join(tmp, 'missing-cas'),
            include_nss=False)
      finally:
        os.chmod(locked, 0o700)
    self.assertEqual(report['overall_status'], 'incomplete')
    self.assertTrue(report['browsers']['unreadable'])


if __name__ == '__main__':
  unittest.main()
