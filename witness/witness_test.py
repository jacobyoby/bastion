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
"""Tests for witness SSH scanning and checks."""

import tempfile
import unittest

from paranoid_crypto.lib import ssh_keys_test

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
        ssh_paths=[path], scan_home_ssh=False, include_etc_ssh=False)
    self.assertIn(report['overall_status'], ('needs_attention', 'confirmed'))
    self.assertGreaterEqual(report['ssh']['weak_count'], 1)


if __name__ == '__main__':
  unittest.main()
