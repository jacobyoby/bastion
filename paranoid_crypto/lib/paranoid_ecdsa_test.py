# Copyright 2022 Google LLC
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
"""ECDSA Tests for paranoid_crypto.lib.paranoid."""

import copy
import hashlib
import subprocess
import sys
from absl.testing import absltest
import gmpy2 as gmpy
from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import consts
from paranoid_crypto.lib import ec_util
from paranoid_crypto.lib import paranoid
from paranoid_crypto.lib import paranoid_base_test
from paranoid_crypto.lib import util
from paranoid_crypto.lib.paranoid import ec_aggregate_checks
from paranoid_crypto.lib.paranoid import ecdsa_sig_checks

# Good ECDSA signatures.
good_ecdsa_secp256r1 = paranoid_pb2.ECDSASignature()
good_ecdsa_secp256r1.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
good_ecdsa_secp256r1.ecdsa_sig_info.r = util.Hex2Bytes(
    'f888377e53ce3a94565661f84f560c539ffce99d1cd29eab88d049fa669de225')
good_ecdsa_secp256r1.ecdsa_sig_info.s = util.Hex2Bytes(
    '3ba37c33c3e8e0a3520691270e4889c1a1896440c3f05252cc49ab4531677a81')
good_ecdsa_secp256r1.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    'e36abb3b87505b0ba5067c9221a58a5c81513f060202a6e3da0833cd80e977b2')
good_ecdsa_secp256r1.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
good_ecdsa_secp256r1.issuer_key_info.x = util.Hex2Bytes(
    '52840bcc3ddef170b9611001534613c03b52838db81f307865133ff727129b2')
good_ecdsa_secp256r1.issuer_key_info.y = util.Hex2Bytes(
    '34b5de1badddf0d6155b006b40fa6ace3b2c5bae704f1f720f508c48cddc3744')

good_ecdsa_secp521r1 = paranoid_pb2.ECDSASignature()
good_ecdsa_secp521r1.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
good_ecdsa_secp521r1.ecdsa_sig_info.r = util.Hex2Bytes(
    '11a9c550ae5cf63ff0ff125fd454f97fc702ff648d0743aff68eb0bae6aeb2821a854d1000a5068d21602f5d6fca01bb5e0623a7135b6c8ade5bc709825f537fae8'
)
good_ecdsa_secp521r1.ecdsa_sig_info.s = util.Hex2Bytes(
    '1988b69f2d5b58278e897854f14b369bbe7f34d25bd6bb8404975ad063cbf38ebbed802f6215a0962612e5a87e8c345efe00d09a2bdaf8a95b161124900e7597d75'
)
good_ecdsa_secp521r1.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    'e36abb3b87505b0ba5067c9221a58a5c81513f060202a6e3da0833cd80e977b2')
good_ecdsa_secp521r1.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP521R1
good_ecdsa_secp521r1.issuer_key_info.x = util.Hex2Bytes(
    '6bba7265c6efe40fb20a6d1c22756483ac590b11dcf2532ab6705f48612895a13d8a7b3503442c8a7eb60adb60e46edf827465f422199c1850626839b095fa4912'
)
good_ecdsa_secp521r1.issuer_key_info.y = util.Hex2Bytes(
    '1b471f02088804f0a9e9bf9b33c7e2081897fa25e10877eb8a4d365e4f6ece77aa4933a89b33cb80187f017e2b08a61e080973bd3e03bd05c6e8ce51cfa0b4e2473'
)

good_ecdsa_sigs = [
    good_ecdsa_secp256r1,
    good_ecdsa_secp521r1,
    # Make sure good deterministic ECDSA are not flagged:
    copy.deepcopy(good_ecdsa_secp256r1),
]

# An issuer EC key where the words in the private key repeat.
# The private key is
# 0xe899250fe899250fe899250fe899250fe899250fe899250fe899250fe899250f
bad_ecdsa_secp256r1_repeat = paranoid_pb2.ECDSASignature()
bad_ecdsa_secp256r1_repeat.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA512
bad_ecdsa_secp256r1_repeat.ecdsa_sig_info.r = util.Hex2Bytes(
    'a579c98160c2e4066f8defcc2a8510f027531287ee4b593fd9a2b17f6a9d86d9')
bad_ecdsa_secp256r1_repeat.ecdsa_sig_info.s = util.Hex2Bytes(
    '6082cf8f763ab383ca1be56dd04aa64bb0b0f862dba922821e902dd0da6c6bb0')
bad_ecdsa_secp256r1_repeat.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '25ffca8499df94d5725334521f18302f4aace2acf31f50659400cfb7d59e21338974f16127330ae6d371850cfa88c967000e373370068757409050405c5fe31e'
)
bad_ecdsa_secp256r1_repeat.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_secp256r1_repeat.issuer_key_info.x = util.Hex2Bytes(
    '7139faa536fc4b313b77fa7c2c8dd737a7a66bac756593867f797d6fb3bec5a5')
bad_ecdsa_secp256r1_repeat.issuer_key_info.y = util.Hex2Bytes(
    '1a75275829d4ca8353f3706cc584f019da41ec3eb093c0996990a6e0929be9fd')

# Two issuer EC keys where the difference between the private key is small i.e.
# smaller than 2^16.
bad_ecdsa_secp256k1_diff1 = paranoid_pb2.ECDSASignature()
bad_ecdsa_secp256k1_diff1.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA512
bad_ecdsa_secp256k1_diff1.ecdsa_sig_info.r = util.Hex2Bytes(
    'f13d8a617750045bd26f3fd05828e596d9b6e4d2855893b6b48cdfcf276e31f5')
bad_ecdsa_secp256k1_diff1.ecdsa_sig_info.s = util.Hex2Bytes(
    '39ba8c4080aa9bda6223dde0fe65ef7535f570f4473c45c3e19630664a6c50b7')
bad_ecdsa_secp256k1_diff1.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '25ffca8499df94d5725334521f18302f4aace2acf31f50659400cfb7d59e21338974f16127330ae6d371850cfa88c967000e373370068757409050405c5fe31e'
)
bad_ecdsa_secp256k1_diff1.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256K1
bad_ecdsa_secp256k1_diff1.issuer_key_info.x = util.Hex2Bytes(
    'dc93ef54134fceaafb7ea0b59be0dd272986b66ee4905d8dff57e056087ffbfe')
bad_ecdsa_secp256k1_diff1.issuer_key_info.y = util.Hex2Bytes(
    '5ae191bc21804648851489cbb7ad2a00bd955733bbe3faa3969308161353c94b')

bad_ecdsa_secp256k1_diff2 = paranoid_pb2.ECDSASignature()
bad_ecdsa_secp256k1_diff2.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA512
bad_ecdsa_secp256k1_diff2.ecdsa_sig_info.r = util.Hex2Bytes(
    'c96bc87224f1200754b0cf6b1d287e238cf23d3b12f37570646555b14d44332b')
bad_ecdsa_secp256k1_diff2.ecdsa_sig_info.s = util.Hex2Bytes(
    '2cb7b8ead9d6f8a1b5ed724db16a867736b2728ce77edf58daee59605ce3495a')
bad_ecdsa_secp256k1_diff2.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '25ffca8499df94d5725334521f18302f4aace2acf31f50659400cfb7d59e21338974f16127330ae6d371850cfa88c967000e373370068757409050405c5fe31e'
)
bad_ecdsa_secp256k1_diff2.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256K1
bad_ecdsa_secp256k1_diff2.issuer_key_info.x = util.Hex2Bytes(
    'c5989f00691851430e62bb903e7cd368b1b4754f281d4bddf2b13bc638cabe66')
bad_ecdsa_secp256k1_diff2.issuer_key_info.y = util.Hex2Bytes(
    'd886c6701ac48c1baae4a647282bd5126b6d1ede0795c07922f813fbadd76693')

bad_ecdsa_sigs = [
    bad_ecdsa_secp256r1_repeat, bad_ecdsa_secp256k1_diff1,
    bad_ecdsa_secp256k1_diff2
]

# Signatures vulnerable to Cr50 U2F.
# Only one signature vulnerable to Cr50 U2F, but private key also weak:
bad_ecdsa_cr50u2f_1 = paranoid_pb2.ECDSASignature()
bad_ecdsa_cr50u2f_1.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_cr50u2f_1.ecdsa_sig_info.r = util.Hex2Bytes(
    '5ca7141be13da0837eb8cd51ca37da75d16fed96baaa85cc9b13e76e0c509a84')
bad_ecdsa_cr50u2f_1.ecdsa_sig_info.s = util.Hex2Bytes(
    'dd3b20d56a95b4261c334e0f114031e7a2a8e561f666e478398000e3347994b7')
bad_ecdsa_cr50u2f_1.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25')
bad_ecdsa_cr50u2f_1.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_cr50u2f_1.issuer_key_info.x = util.Hex2Bytes(
    '6c45b2166cd815d15c59183e25f35a040ae2e5552ac73f04f7cabcbad416ed18')
bad_ecdsa_cr50u2f_1.issuer_key_info.y = util.Hex2Bytes(
    'e926a54e84941b840e27a43c4f3eb9d420bc514f13be9891ea0b4703e1d32c7f')

# Two signatures vulnerable to Cr50 U2F and not weak private key:
bad_ecdsa_cr50u2f_2 = paranoid_pb2.ECDSASignature()
bad_ecdsa_cr50u2f_2.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_cr50u2f_2.ecdsa_sig_info.r = util.Hex2Bytes(
    'a6e80644b57c7317643585d50b41cb953df438afc142cb59ba710f19ca638525')
bad_ecdsa_cr50u2f_2.ecdsa_sig_info.s = util.Hex2Bytes(
    '9321c03820e6f26a00085f58049754afddc38fa2d9487af06cf4dad9806c7454')
bad_ecdsa_cr50u2f_2.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25')
bad_ecdsa_cr50u2f_2.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_cr50u2f_2.issuer_key_info.x = util.Hex2Bytes(
    '483f84884a9d14785b7baccb260572cab055548f3b717ce674188077361fc562')
bad_ecdsa_cr50u2f_2.issuer_key_info.y = util.Hex2Bytes(
    'a8fe08b031ef8716cbe858d17be56fe4c2891af824ed595c89d42e8a04adab2a')

bad_ecdsa_cr50u2f_3 = paranoid_pb2.ECDSASignature()
bad_ecdsa_cr50u2f_3.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_cr50u2f_3.ecdsa_sig_info.r = util.Hex2Bytes(
    'fd686c417357e743451d27b40032c95084dadeff96c5b1c8a94479731f87bf8c')
bad_ecdsa_cr50u2f_3.ecdsa_sig_info.s = util.Hex2Bytes(
    'bf8bfd0be715b3869c5c843744cc4a85828ab7e63f82a94aed53fc61e188e4cc')
bad_ecdsa_cr50u2f_3.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25')
bad_ecdsa_cr50u2f_3.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_cr50u2f_3.issuer_key_info.x = util.Hex2Bytes(
    '483f84884a9d14785b7baccb260572cab055548f3b717ce674188077361fc562')
bad_ecdsa_cr50u2f_3.issuer_key_info.y = util.Hex2Bytes(
    'a8fe08b031ef8716cbe858d17be56fe4c2891af824ed595c89d42e8a04adab2a')

bad_ecdsa_cr50u2f = [
    bad_ecdsa_cr50u2f_1,
    bad_ecdsa_cr50u2f_2,
    bad_ecdsa_cr50u2f_3,
    # Make sure bad deterministic ECDSA are also flagged:
    copy.deepcopy(bad_ecdsa_cr50u2f_1),
]

# Three signatures with nonces generated using GMP LCG.
bad_ecdsa_lcg_gmp_1 = paranoid_pb2.ECDSASignature()
bad_ecdsa_lcg_gmp_1.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_lcg_gmp_1.ecdsa_sig_info.r = util.Hex2Bytes(
    '535aaff5af8a8ef37a6ee5d0f16d10a37a67be097994c514201e377ff47e0cdb')
bad_ecdsa_lcg_gmp_1.ecdsa_sig_info.s = util.Hex2Bytes(
    'a3ec962f1654f94293c290c66c8d8a329c9a97e7c7b52d52a29e587776f5b35f')
bad_ecdsa_lcg_gmp_1.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '1bc5d0e3df0ea12c4d0078668d14924f95106bbe173e196de50fe13a900b0937')
bad_ecdsa_lcg_gmp_1.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_lcg_gmp_1.issuer_key_info.x = util.Hex2Bytes(
    '797e0130410125e55b89154dbf90e5af10bf598699b1ea4f362c9da67f5ffe66')
bad_ecdsa_lcg_gmp_1.issuer_key_info.y = util.Hex2Bytes(
    'f0b047a184a7b3a7d1164cedd34afce21ba3c82b063bcbbf7aec847ec7d47ffc')

bad_ecdsa_lcg_gmp_2 = paranoid_pb2.ECDSASignature()
bad_ecdsa_lcg_gmp_2.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_lcg_gmp_2.ecdsa_sig_info.r = util.Hex2Bytes(
    'b4dd3d032329e61c52c68f9b47e40126350fb3032f8aa4d1d0fda6556d33c902')
bad_ecdsa_lcg_gmp_2.ecdsa_sig_info.s = util.Hex2Bytes(
    '0b91e152f7192d2c40e4300e45a3854ef27055847f0b80d0a162538169e20cfa')
bad_ecdsa_lcg_gmp_2.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '221f8af2372a95064f2ef7d7712216a9ab46e7ef98482fd237e106f83eaa7569')
bad_ecdsa_lcg_gmp_2.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_lcg_gmp_2.issuer_key_info.x = util.Hex2Bytes(
    '797e0130410125e55b89154dbf90e5af10bf598699b1ea4f362c9da67f5ffe66')
bad_ecdsa_lcg_gmp_2.issuer_key_info.y = util.Hex2Bytes(
    'f0b047a184a7b3a7d1164cedd34afce21ba3c82b063bcbbf7aec847ec7d47ffc')

bad_ecdsa_lcg_gmp_3 = paranoid_pb2.ECDSASignature()
bad_ecdsa_lcg_gmp_3.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_lcg_gmp_3.ecdsa_sig_info.r = util.Hex2Bytes(
    '2be359a5bb40508945a8cb1c0c1ee19b431882114d048aac4598dc2ee259b763')
bad_ecdsa_lcg_gmp_3.ecdsa_sig_info.s = util.Hex2Bytes(
    'a984343511eef74d335924aec1840868161ae7bc32986d01349c0b87e626c427')
bad_ecdsa_lcg_gmp_3.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    'b253668f6b59f1ff28522831931e4d3c5a3de533965af22e961735437c0172cb')
bad_ecdsa_lcg_gmp_3.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_lcg_gmp_3.issuer_key_info.x = util.Hex2Bytes(
    '797e0130410125e55b89154dbf90e5af10bf598699b1ea4f362c9da67f5ffe66')
bad_ecdsa_lcg_gmp_3.issuer_key_info.y = util.Hex2Bytes(
    'f0b047a184a7b3a7d1164cedd34afce21ba3c82b063bcbbf7aec847ec7d47ffc')

bad_ecdsa_lcg_gmp = [
    bad_ecdsa_lcg_gmp_1, bad_ecdsa_lcg_gmp_2, bad_ecdsa_lcg_gmp_3
]

# Three signatures with nonces generated using Java Util Random LCG.
bad_ecdsa_lcg_java_1 = paranoid_pb2.ECDSASignature()
bad_ecdsa_lcg_java_1.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_lcg_java_1.ecdsa_sig_info.r = util.Hex2Bytes(
    'b6a5ee458eaaf322d37117744fe2f422c30268192270cadb6a1bbcadd63b223f')
bad_ecdsa_lcg_java_1.ecdsa_sig_info.s = util.Hex2Bytes(
    'ab218e3a45929bb6ee9e12d1ecdf17cf52b7812e8499def0d75d904915dfda14')
bad_ecdsa_lcg_java_1.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '88185d128d9922e0e6bcd32b07b6c7f20f27968eab447a1d8d1cdf250f79f7d3')
bad_ecdsa_lcg_java_1.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_lcg_java_1.issuer_key_info.x = util.Hex2Bytes(
    '82056f3bf133f052b2f3ec301ac57e5b68565e51a62fdf1983591714b3b89569')
bad_ecdsa_lcg_java_1.issuer_key_info.y = util.Hex2Bytes(
    '5610988596a7585440315ab7e72453bfcded480d1861caa2ea4988ccf507c710')

bad_ecdsa_lcg_java_2 = paranoid_pb2.ECDSASignature()
bad_ecdsa_lcg_java_2.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_lcg_java_2.ecdsa_sig_info.r = util.Hex2Bytes(
    '1fbac2cccfbe1fa5a0bb8c9090dcfdee5c0c5b9f4258fbee0ac57638b59c419e')
bad_ecdsa_lcg_java_2.ecdsa_sig_info.s = util.Hex2Bytes(
    'ae22afa10de7c86918731055ca6149ecef32ec5f1c53c1e737f6c4db38dd3d6e')
bad_ecdsa_lcg_java_2.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '1bc5d0e3df0ea12c4d0078668d14924f95106bbe173e196de50fe13a900b0937')
bad_ecdsa_lcg_java_2.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_lcg_java_2.issuer_key_info.x = util.Hex2Bytes(
    '82056f3bf133f052b2f3ec301ac57e5b68565e51a62fdf1983591714b3b89569')
bad_ecdsa_lcg_java_2.issuer_key_info.y = util.Hex2Bytes(
    '5610988596a7585440315ab7e72453bfcded480d1861caa2ea4988ccf507c710')

bad_ecdsa_lcg_java_3 = paranoid_pb2.ECDSASignature()
bad_ecdsa_lcg_java_3.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_lcg_java_3.ecdsa_sig_info.r = util.Hex2Bytes(
    'f06791ad83a55bd11329a1c846b34848c45973a4463e782f20ef5a3b529fd918')
bad_ecdsa_lcg_java_3.ecdsa_sig_info.s = util.Hex2Bytes(
    'c26955f6e295eea96ce5e4b9695da10464abc1f0e107523cade43738d7019cd3')
bad_ecdsa_lcg_java_3.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '221f8af2372a95064f2ef7d7712216a9ab46e7ef98482fd237e106f83eaa7569')
bad_ecdsa_lcg_java_3.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_lcg_java_3.issuer_key_info.x = util.Hex2Bytes(
    '82056f3bf133f052b2f3ec301ac57e5b68565e51a62fdf1983591714b3b89569')
bad_ecdsa_lcg_java_3.issuer_key_info.y = util.Hex2Bytes(
    '5610988596a7585440315ab7e72453bfcded480d1861caa2ea4988ccf507c710')

bad_ecdsa_lcg_java = [
    bad_ecdsa_lcg_java_1, bad_ecdsa_lcg_java_2, bad_ecdsa_lcg_java_3
]

# Three signatures with nonces under 2^160 taken from cryptohack.org
# "No Random, No Bias" challenge. Bias.MSB is able to solve it.
bad_ecdsa_msb_1 = paranoid_pb2.ECDSASignature()
bad_ecdsa_msb_1.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA1
bad_ecdsa_msb_1.ecdsa_sig_info.r = util.Hex2Bytes(
    '91f66ac7557233b41b3044ab9daf0ad891a8ffcaf99820c3cd8a44fc709ed3ae')
bad_ecdsa_msb_1.ecdsa_sig_info.s = util.Hex2Bytes(
    '1dd0a378454692eb4ad68c86732404af3e73c6bf23a8ecc5449500fcab05208d')
bad_ecdsa_msb_1.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    'd94a29716364d9e8b67c411ee9357dd876370192')
bad_ecdsa_msb_1.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_msb_1.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_msb_1.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_msb_2 = paranoid_pb2.ECDSASignature()
bad_ecdsa_msb_2.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA1
bad_ecdsa_msb_2.ecdsa_sig_info.r = util.Hex2Bytes(
    'e8875e56b79956d446d24f06604b7705905edac466d5469f815547dea7a3171c')
bad_ecdsa_msb_2.ecdsa_sig_info.s = util.Hex2Bytes(
    '582ecf967e0e3acf5e3853dbe65a84ba59c3ec8a43951bcff08c64cb614023f8')
bad_ecdsa_msb_2.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '154004551a71cf1b3516d15fe385a7fcd02cbf44')
bad_ecdsa_msb_2.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_msb_2.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_msb_2.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_msb_3 = paranoid_pb2.ECDSASignature()
bad_ecdsa_msb_3.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA1
bad_ecdsa_msb_3.ecdsa_sig_info.r = util.Hex2Bytes(
    '566ce1db407edae4f32a20defc381f7efb63f712493c3106cf8e85f464351ca6')
bad_ecdsa_msb_3.ecdsa_sig_info.s = util.Hex2Bytes(
    '9e4304a36d2c83ef94e19a60fb98f659fa874bfb999712ceb58382e2ccda26ba')
bad_ecdsa_msb_3.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '8e30d6aac813417d581bd798bb4422107881ac34')
bad_ecdsa_msb_3.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_msb_3.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_msb_3.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_msb = [bad_ecdsa_msb_1, bad_ecdsa_msb_2, bad_ecdsa_msb_3]

# Bias.COMMON_PREFIX needs two more signatures.
bad_ecdsa_common_prefix_1 = paranoid_pb2.ECDSASignature()
bad_ecdsa_common_prefix_1.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA1
bad_ecdsa_common_prefix_1.ecdsa_sig_info.r = util.Hex2Bytes(
    'd15473271f9caebc8c7a4a9d57e35ab5d852ae57939ef55768a27c2eb3ff1c28')
bad_ecdsa_common_prefix_1.ecdsa_sig_info.s = util.Hex2Bytes(
    'b32d96b7ff5ab009979836a0442b94f4c4cc0cbab7618d3b8d9df6a5b8660b55')
bad_ecdsa_common_prefix_1.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    'f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0')
bad_ecdsa_common_prefix_1.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_common_prefix_1.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_common_prefix_1.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_common_prefix_2 = paranoid_pb2.ECDSASignature()
bad_ecdsa_common_prefix_2.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA1
bad_ecdsa_common_prefix_2.ecdsa_sig_info.r = util.Hex2Bytes(
    '3b2e11aa616736aa99782b4dc1df7d4fe9d97c78d925b29efb6b9c1fcc9e250e')
bad_ecdsa_common_prefix_2.ecdsa_sig_info.s = util.Hex2Bytes(
    '22679be92f008d2d76ae06a3d46802be6108bfc7e955256cd786b2d54f59c1ae')
bad_ecdsa_common_prefix_2.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    'f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0')
bad_ecdsa_common_prefix_2.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_common_prefix_2.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_common_prefix_2.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_common_prefix = [
    bad_ecdsa_common_prefix_1, bad_ecdsa_common_prefix_2
] + bad_ecdsa_msb

# Five signatures in which only the 160 most significant bits of the nonces are
# set. The 96 least significant bits are 0.
bad_ecdsa_common_postfix_1 = paranoid_pb2.ECDSASignature()
bad_ecdsa_common_postfix_1.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_common_postfix_1.ecdsa_sig_info.r = util.Hex2Bytes(
    'bb2924c21aa5d7c683c0c7809f8d378e519fd67a55e8bfe612ac17072bb3e62b')
bad_ecdsa_common_postfix_1.ecdsa_sig_info.s = util.Hex2Bytes(
    'e8bea721d4e68a2b4063d4c4175718807dd520fb8f61791dce9a632743bd012b')
bad_ecdsa_common_postfix_1.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969')
bad_ecdsa_common_postfix_1.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_common_postfix_1.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_common_postfix_1.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_common_postfix_2 = paranoid_pb2.ECDSASignature()
bad_ecdsa_common_postfix_2.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_common_postfix_2.ecdsa_sig_info.r = util.Hex2Bytes(
    'eadf63e84ef38d69be0524355b6e7de025081b0de18c6db95f583c6133873946')
bad_ecdsa_common_postfix_2.ecdsa_sig_info.s = util.Hex2Bytes(
    '5c3145f4f8c438e26a55c7011a17fa6126c89d18504afac863f560305d8f56c1')
bad_ecdsa_common_postfix_2.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969')
bad_ecdsa_common_postfix_2.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_common_postfix_2.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_common_postfix_2.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_common_postfix_3 = paranoid_pb2.ECDSASignature()
bad_ecdsa_common_postfix_3.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_common_postfix_3.ecdsa_sig_info.r = util.Hex2Bytes(
    '8f9fecb4d780d97813431fd75551bca15c6d891904d8df2ccbe1b665264317e2')
bad_ecdsa_common_postfix_3.ecdsa_sig_info.s = util.Hex2Bytes(
    '74551e947c523d1f482caf86a3e6f048654c03e285a1bf9d05a4e6bc4ebc7458')
bad_ecdsa_common_postfix_3.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969')
bad_ecdsa_common_postfix_3.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_common_postfix_3.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_common_postfix_3.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_common_postfix_4 = paranoid_pb2.ECDSASignature()
bad_ecdsa_common_postfix_4.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_common_postfix_4.ecdsa_sig_info.r = util.Hex2Bytes(
    '11b717242f3b597bb8fbd89d4eb6d6dae5d096055569f242f8d5bc37bb070b98')
bad_ecdsa_common_postfix_4.ecdsa_sig_info.s = util.Hex2Bytes(
    '1babb0143b1ec8738b0bc333b8aa97221da68b914fff3752d5009fc98135c77a')
bad_ecdsa_common_postfix_4.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969')
bad_ecdsa_common_postfix_4.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_common_postfix_4.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_common_postfix_4.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_common_postfix_5 = paranoid_pb2.ECDSASignature()
bad_ecdsa_common_postfix_5.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_common_postfix_5.ecdsa_sig_info.r = util.Hex2Bytes(
    'db5ca2cb8362d231c120e8b370942d1d9d193bba5d1c33374b74bc230e52b7a9')
bad_ecdsa_common_postfix_5.ecdsa_sig_info.s = util.Hex2Bytes(
    'cdf5818a45fd641048b3cc1a175c33dadff504c4067eb046b3de3a8b93a94dca')
bad_ecdsa_common_postfix_5.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969')
bad_ecdsa_common_postfix_5.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_common_postfix_5.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_common_postfix_5.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_common_postfix = [
    bad_ecdsa_common_postfix_1, bad_ecdsa_common_postfix_2,
    bad_ecdsa_common_postfix_3, bad_ecdsa_common_postfix_4,
    bad_ecdsa_common_postfix_5
]

# Six signatures in which only the 16 most and 16 least significant bits are
# set. The 224 bits in the middle are 0.
bad_ecdsa_generalized_1 = paranoid_pb2.ECDSASignature()
bad_ecdsa_generalized_1.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_generalized_1.ecdsa_sig_info.r = util.Hex2Bytes(
    '3a0483f59d861f7d9afd3e8920adf2a85430328c667aadb6925863111783df78')
bad_ecdsa_generalized_1.ecdsa_sig_info.s = util.Hex2Bytes(
    '6cff07783722b3eea2a677868cf10568729f3907ccaaf5fced065141e5b43a83')
bad_ecdsa_generalized_1.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969')
bad_ecdsa_generalized_1.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_generalized_1.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_generalized_1.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_generalized_2 = paranoid_pb2.ECDSASignature()
bad_ecdsa_generalized_2.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_generalized_2.ecdsa_sig_info.r = util.Hex2Bytes(
    '35b9c68ae198390cfacd630e324d2b28cfecb430a322dfde8ead3ff0d39304e3')
bad_ecdsa_generalized_2.ecdsa_sig_info.s = util.Hex2Bytes(
    'b774d673125c78aeb1cdac1bcbdef7e8f9f1cf936db8b5c0ed539f56c61a1e2c')
bad_ecdsa_generalized_2.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969')
bad_ecdsa_generalized_2.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_generalized_2.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_generalized_2.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_generalized_3 = paranoid_pb2.ECDSASignature()
bad_ecdsa_generalized_3.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_generalized_3.ecdsa_sig_info.r = util.Hex2Bytes(
    '55d30183bef6973072673ba51fed05a6390887d85080c75bf533b11c70f6cc25')
bad_ecdsa_generalized_3.ecdsa_sig_info.s = util.Hex2Bytes(
    'e89f6671bc0710df60f6a36ee02f864eb2bf0744ca0a91df94c661780d7f0827')
bad_ecdsa_generalized_3.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969')
bad_ecdsa_generalized_3.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_generalized_3.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_generalized_3.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_generalized_4 = paranoid_pb2.ECDSASignature()
bad_ecdsa_generalized_4.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_generalized_4.ecdsa_sig_info.r = util.Hex2Bytes(
    '1b829d3c8832095946d91ee8ef489f0e1d298a3390beb7368ea59df08de3ce05')
bad_ecdsa_generalized_4.ecdsa_sig_info.s = util.Hex2Bytes(
    '7050d267a0a893e3e3fb2b3ee6fbab706f53167acdade061feb8ea8f1cfa9672')
bad_ecdsa_generalized_4.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969')
bad_ecdsa_generalized_4.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_generalized_4.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_generalized_4.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_generalized_5 = paranoid_pb2.ECDSASignature()
bad_ecdsa_generalized_5.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_generalized_5.ecdsa_sig_info.r = util.Hex2Bytes(
    'bc4849992ba5459a1e54cbc6c7cb23de488100b86643f630b74afba5b3d6399')
bad_ecdsa_generalized_5.ecdsa_sig_info.s = util.Hex2Bytes(
    '723aa14c7e9b3ef6619d41fa67cde2d936a098484053b04b3356aeeec4dfd9a7')
bad_ecdsa_generalized_5.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969')
bad_ecdsa_generalized_5.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_generalized_5.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_generalized_5.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_generalized_6 = paranoid_pb2.ECDSASignature()
bad_ecdsa_generalized_6.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
bad_ecdsa_generalized_6.ecdsa_sig_info.r = util.Hex2Bytes(
    'cd354e94ba3e33d2a5af655ae4784ea4d5e5907eacb86e7f25b753b065ae96b2')
bad_ecdsa_generalized_6.ecdsa_sig_info.s = util.Hex2Bytes(
    'c84e185b7986543f8d1bed40bb6264ff781211239a7bfdf295eb91c84cfca123')
bad_ecdsa_generalized_6.ecdsa_sig_info.message_hash = util.Hex2Bytes(
    '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969')
bad_ecdsa_generalized_6.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
bad_ecdsa_generalized_6.issuer_key_info.x = util.Hex2Bytes(
    '6bd8ef4185015cddc53a29b99be05be1009d6f15c9b1a63805ed3fef756ceb95')
bad_ecdsa_generalized_6.issuer_key_info.y = util.Hex2Bytes(
    'a3fc62804edfe18d11e8d3d4b6c47a15f1d13c3f71bc93756cb8dfa651366b54')

bad_ecdsa_generalized = [
    bad_ecdsa_generalized_1,
    bad_ecdsa_generalized_2,
    bad_ecdsa_generalized_3,
    bad_ecdsa_generalized_4,
    bad_ecdsa_generalized_5,
    bad_ecdsa_generalized_6,
    # Make sure bad deterministic ECDSA are also flagged:
    copy.deepcopy(bad_ecdsa_generalized_1),
]


def _Secp256r1Sig(r: str, s: str, message_hash: str, x: str,
                  y: str) -> paranoid_pb2.ECDSASignature:
  sig = paranoid_pb2.ECDSASignature()
  sig.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
  sig.ecdsa_sig_info.r = util.Hex2Bytes(r)
  sig.ecdsa_sig_info.s = util.Hex2Bytes(s)
  sig.ecdsa_sig_info.message_hash = util.Hex2Bytes(message_hash)
  sig.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256R1
  sig.issuer_key_info.x = util.Hex2Bytes(x)
  sig.issuer_key_info.y = util.Hex2Bytes(y)
  return sig


def _Secp256k1Sig(r: int, s: int, message_hash: bytes,
                  q: tuple[int, int]) -> paranoid_pb2.ECDSASignature:
  sig = paranoid_pb2.ECDSASignature()
  sig.ecdsa_sig_info.algorithm = paranoid_pb2.SignatureAlgorithm.ECDSA_WITH_SHA256
  sig.ecdsa_sig_info.r = util.Int2Bytes(r)
  sig.ecdsa_sig_info.s = util.Int2Bytes(s)
  sig.ecdsa_sig_info.message_hash = message_hash
  sig.issuer_key_info.curve_type = paranoid_pb2.CurveType.CURVE_SECP256K1
  sig.issuer_key_info.x = util.Int2Bytes(q[0])
  sig.issuer_key_info.y = util.Int2Bytes(q[1])
  return sig


# Two signatures of one key with the same nonce k.
_reuse_key_x = '775a7582a717bf46cbaf1f41c43ee0e6b78312a6359f61386e49ee92ef961a5f'
_reuse_key_y = 'a93f36b2abcff4476bc4fe1a93a6deb191fe502c1271cf317905dc91b70e3460'
bad_ecdsa_nonce_reuse = [
    _Secp256r1Sig(
        '9a24d4e30e96e30260335018e235863887e6c33e69ddec43e9379283efb7180c',
        '0928590056b83b6e3723d91793c88a255caf901bfc98a628d7b538a5a2880fec',
        '44d077a84b34cf76ebf4391348baa9da274efa74dff065a81a3d255880128933',
        _reuse_key_x, _reuse_key_y),
    _Secp256r1Sig(
        '9a24d4e30e96e30260335018e235863887e6c33e69ddec43e9379283efb7180c',
        'f9680bdbc0a493a52cf2cd36d28301c568c6133d7f8213b73866ce7a89e5f198',
        '47dc156ae636adc6534d951f54c5935dbfacdaa5cfa049e202d09db5633aa665',
        _reuse_key_x, _reuse_key_y),
]

# Two signatures of one key with nonces k and n - k, which share r.
_negated_key_x = 'ed1da2e458176f4d1efbc820940d5317cafde315d87ae4ccb9d3b4c86ca18781'
_negated_key_y = 'a8f33afe97af258d0e888f6f9f26e65d3ea9aa92c95a316a1fa6d4d77d526670'
bad_ecdsa_nonce_negated = [
    _Secp256r1Sig(
        '89a79ac2082ae554f14510a9d7ab1137cca34728f9041ef5a27d08b149c05eff',
        '5101dc22e01fb875d5b57db9c32463bd50295c1efe23c7ec398acb22894a0c8d',
        '4d55878139551fc4af8b914d6d6ffcdfedd1ca0995f8a3003796bf3cf09ba7d8',
        _negated_key_x, _negated_key_y),
    _Secp256r1Sig(
        '89a79ac2082ae554f14510a9d7ab1137cca34728f9041ef5a27d08b149c05eff',
        'fd1df073ca423b43bb001c3c29bad223b551a824727c01c9ce1b28203ed4c3ee',
        '039c540c801b382f9e876cba5bf864d34cf7c2ba3e4e0067ed2d1192f3aa784c',
        _negated_key_x, _negated_key_y),
]

# Trick to replace CheckECKeySmallDifference default max_diff (tests run faster)
ec_aggregate_checks.CheckECKeySmallDifference.__init__.__defaults__ = (2**8,)


class ParanoidECDSATest(paranoid_base_test.ParanoidBaseTest):

  def testCheckIssuerKey(self):
    check = ecdsa_sig_checks.CheckIssuerKey()
    self.assertTrue(check.Check(bad_ecdsa_sigs))
    self.assertResults(bad_ecdsa_sigs, check.check_name, True)

    # Assert severities now are the same of the failed key checks
    self.assertSeverities([bad_ecdsa_secp256r1_repeat], check.check_name,
                          paranoid_pb2.SeverityType.SEVERITY_CRITICAL)
    self.assertSeverities(
        [bad_ecdsa_secp256k1_diff1, bad_ecdsa_secp256k1_diff2],
        check.check_name, paranoid_pb2.SeverityType.SEVERITY_HIGH)

  def testCheckCr50U2f(self):
    check = ecdsa_sig_checks.CheckCr50U2f()
    self.assertTrue(check.Check(bad_ecdsa_cr50u2f))
    self.assertResults(bad_ecdsa_cr50u2f, check.check_name, True)

  def _Sign(self, d: int, k: int, message: bytes,
            flip: bool) -> paranoid_pb2.ECDSASignature:
    """Signs with private key d and nonce k on secp256k1; flip uses n - s."""
    curve = ec_util.CURVE_FACTORY[paranoid_pb2.CurveType.CURVE_SECP256K1]
    n = curve.n
    digest = hashlib.sha256(message).digest()
    z = curve.TransformOrderLen(util.Bytes2Int(digest), 256)
    r = curve.Multiply(curve.g, k)[0] % n
    s = int(gmpy.invert(k, n)) * (z + r * d) % n
    return _Secp256k1Sig(r, n - s if flip else s, digest,
                         curve.Multiply(curve.g, d))

  def _Secret(self, label: bytes) -> int:
    n = ec_util.CURVE_FACTORY[paranoid_pb2.CurveType.CURVE_SECP256K1].n
    return int.from_bytes(hashlib.sha256(label).digest(), 'big') % n

  def testCheckNonceReuseAcrossKeysSharedNonce(self):
    # One nonce under two keys: two equations, three unknowns. The keys are
    # not recovered, but the shared nonce is reported.
    d_a, d_b, k = (self._Secret(b'A'), self._Secret(b'B'),
                   self._Secret(b'k shared'))
    sigs = [self._Sign(d_a, k, b'a1', False), self._Sign(d_b, k, b'b1', True)]
    check = ecdsa_sig_checks.CheckNonceReuseAcrossKeys()
    self.assertTrue(check.Check(sigs))
    self.assertResults(sigs, check.check_name, True)
    self.assertSeverities(sigs, check.check_name,
                          paranoid_pb2.SeverityType.SEVERITY_HIGH)
    for sig in sigs:
      self.assertIsNone(
          util.GetAttachedInfo(sig.test_info, consts.INFO_NAME_DISCRETE_LOG))

  def testCheckNonceReuseAcrossKeysCycle(self):
    # Two keys sharing two nonces: four equations, four unknowns. One
    # signature is low-S normalized, which negates its nonce.
    d_a, d_b = self._Secret(b'cycle A'), self._Secret(b'cycle B')
    k1, k2 = self._Secret(b'cycle k1'), self._Secret(b'cycle k2')
    sigs = [self._Sign(d_a, k1, b'a1', False), self._Sign(d_a, k2, b'a2', False),
            self._Sign(d_b, k1, b'b1', True), self._Sign(d_b, k2, b'b2', False)]
    check = ecdsa_sig_checks.CheckNonceReuseAcrossKeys()
    self.assertTrue(check.Check(sigs))
    self.assertResults(sigs, check.check_name, True)
    self.assertSeverities(sigs, check.check_name,
                          paranoid_pb2.SeverityType.SEVERITY_CRITICAL)
    for sig, d in zip(sigs, (d_a, d_a, d_b, d_b)):
      self.assertEqual(
          util.GetAttachedInfo(sig.test_info,
                               consts.INFO_NAME_DISCRETE_LOG).value,
          format(d, 'x'))

  def testCheckNonceReuseAcrossKeysPropagation(self):
    # Key A reuses k1 itself, which reveals A. A's signature with k2 then
    # reveals k2, and so key B, which signed once with k2.
    d_a, d_b = self._Secret(b'prop A'), self._Secret(b'prop B')
    k1, k2 = self._Secret(b'prop k1'), self._Secret(b'prop k2')
    sigs = [self._Sign(d_a, k1, b'a1', False), self._Sign(d_a, k1, b'a2', True),
            self._Sign(d_a, k2, b'a3', False), self._Sign(d_b, k2, b'b1', False)]
    check = ecdsa_sig_checks.CheckNonceReuseAcrossKeys()
    self.assertTrue(check.Check(sigs))
    self.assertEqual(
        util.GetAttachedInfo(sigs[3].test_info,
                             consts.INFO_NAME_DISCRETE_LOG).value,
        format(d_b, 'x'))

  def testCheckNonceReuseAcrossKeysNegative(self):
    # Distinct nonces, and nonce reuse within one key only (that is
    # CheckNonceReuse's job), are not reported by this check.
    d_a, d_b = self._Secret(b'neg A'), self._Secret(b'neg B')
    distinct = [self._Sign(d_a, self._Secret(b'k1'), b'a1', False),
                self._Sign(d_b, self._Secret(b'k2'), b'b1', False)]
    k = self._Secret(b'k same key')
    same_key = [self._Sign(d_a, k, b'a1', False), self._Sign(d_a, k, b'a2', False)]
    check = ecdsa_sig_checks.CheckNonceReuseAcrossKeys()
    self.assertFalse(check.Check(distinct + same_key))
    self.assertResults(distinct + same_key, check.check_name, False)

  def testCheckECDSASignatureRange(self):
    n = ec_util.CURVE_FACTORY[paranoid_pb2.CurveType.CURVE_SECP256R1].n
    def WithValues(r, s):
      sig = copy.deepcopy(good_ecdsa_secp256r1)
      sig.ClearField('test_info')
      sig.ecdsa_sig_info.r = util.Int2Bytes(r)
      sig.ecdsa_sig_info.s = util.Int2Bytes(s)
      return sig
    good = WithValues(util.Bytes2Int(good_ecdsa_secp256r1.ecdsa_sig_info.r),
                      util.Bytes2Int(good_ecdsa_secp256r1.ecdsa_sig_info.s))
    # r = s = 0 verified for any message and key on Java 15 to 18
    # (CVE-2022-21449). Values of n or more are out of range too.
    out_of_range = [WithValues(0, 0), WithValues(0, 5), WithValues(n, 5),
                    WithValues(5, n), WithValues(5, n + 3)]
    in_range = [good, WithValues(1, n - 1), WithValues(n - 1, 1)]
    check = ecdsa_sig_checks.CheckECDSASignatureRange()
    self.assertTrue(check.Check(out_of_range + in_range))
    self.assertResults(out_of_range, check.check_name, True)
    self.assertResults(in_range, check.check_name, False)

  def testCheckNonceHalfHalf(self):
    # Each layout puts one half of the message hash z into one half of the
    # nonce, and a fixed half of the private key d into the other half, as in
    # the half-half Bitcoin nonces (ePrint 2023/841). Signatures use low-S.
    curve = ec_util.CURVE_FACTORY[paranoid_pb2.CurveType.CURVE_SECP256K1]
    n, half = curve.n, curve.n.bit_length() // 2
    low, high = lambda v: v % 2**half, lambda v: v >> half
    layouts = {
        'h_msb||d_msb': lambda z, d: high(z) * 2**half + high(d),
        'h_lsb||d_msb': lambda z, d: low(z) * 2**half + high(d),
        'd_msb||h_msb': lambda z, d: high(d) * 2**half + high(z),
        'd_msb||h_lsb': lambda z, d: high(d) * 2**half + low(z),
        'd_lsb||h_msb': lambda z, d: low(d) * 2**half + high(z),
    }
    for i, (name, nonce) in enumerate(layouts.items()):
      with self.subTest(name):
        d = int.from_bytes(hashlib.sha256(b'half-half %d' % i).digest(),
                           'big') % n
        q = curve.Multiply(curve.g, d)
        sigs = []
        for message in (b'first', b'second'):
          digest = hashlib.sha256(message + name.encode()).digest()
          z = curve.TransformOrderLen(util.Bytes2Int(digest), 256)
          k = nonce(z, d)
          r = curve.Multiply(curve.g, k)[0] % n
          s = int(gmpy.invert(k, n)) * (z + r * d) % n
          sigs.append(_Secp256k1Sig(r, min(s, n - s), digest, q))
        check = ecdsa_sig_checks.CheckNonceHalfHalf()
        self.assertTrue(check.Check(sigs))
        self.assertResults(sigs, check.check_name, True)
        self.assertEqual(
            util.GetAttachedInfo(sigs[0].test_info,
                                 consts.INFO_NAME_DISCRETE_LOG).value,
            format(d, 'x'))
    # Replacing s by n - s replaces k by -k. Every combination of signs for the
    # two signatures of one key must still recover it. The solver is called
    # directly: Check pairs signatures in set order, and swapping a pair swaps
    # which sign combination it needs.
    d = int.from_bytes(hashlib.sha256(b'half-half signs').digest(), 'big') % n
    raw = []
    for message in (b'first', b'second'):
      digest = hashlib.sha256(message).digest()
      z = curve.TransformOrderLen(util.Bytes2Int(digest), 256)
      k = layouts['h_msb||d_msb'](z, d)
      r = curve.Multiply(curve.g, k)[0] % n
      raw.append((r, int(gmpy.invert(k, n)) * (z + r * d) % n, z))
    for flip1 in (False, True):
      for flip2 in (False, True):
        with self.subTest(flip1=flip1, flip2=flip2):
          (r1, s1, z1), (r2, s2, z2) = [
              (r, n - s if flip else s, z)
              for (r, s, z), flip in zip(raw, (flip1, flip2))]
          self.assertIn(d, ecdsa_sig_checks._HalfHalfGuesses(
              r1, s1, z1, r2, s2, z2, curve))
    # Two signatures of one key with unrelated nonces are paired, and the key
    # is not recovered.
    d = int.from_bytes(hashlib.sha256(b'random nonces').digest(), 'big') % n
    q = curve.Multiply(curve.g, d)
    sigs = []
    for message in (b'first', b'second'):
      digest = hashlib.sha256(message).digest()
      z = curve.TransformOrderLen(util.Bytes2Int(digest), 256)
      k = int.from_bytes(hashlib.sha256(b'k' + message).digest(), 'big') % n
      r = curve.Multiply(curve.g, k)[0] % n
      sigs.append(_Secp256k1Sig(r, int(gmpy.invert(k, n)) * (z + r * d) % n,
                                digest, q))
    check = ecdsa_sig_checks.CheckNonceHalfHalf()
    self.assertFalse(check.Check(sigs))
    self.assertResults(sigs, check.check_name, False)

  def testCheckNonceReuse(self):
    check = ecdsa_sig_checks.CheckNonceReuse()
    sigs = bad_ecdsa_nonce_reuse + bad_ecdsa_nonce_negated
    self.assertTrue(check.Check(sigs))
    self.assertResults(sigs, check.check_name, True)
    # One signature per key cannot reveal a repeated nonce.
    check = ecdsa_sig_checks.CheckNonceReuse()
    single = copy.deepcopy(bad_ecdsa_nonce_reuse[0])
    self.assertFalse(check.Check([single]))

  def testCheckNonceReuseUnreducedIssuerKey(self):
    # One signer's key is encoded reduced in one signature, with x + p in the
    # second and with y + p in the third. They are one key, so the shared
    # nonce must be found and every signature flagged.
    reduced, x_unreduced = copy.deepcopy(bad_ecdsa_nonce_reuse)
    y_unreduced = copy.deepcopy(x_unreduced)
    mod = 2**256 - 2**224 + 2**192 + 2**96 - 1  # secp256r1 field prime
    x = util.Bytes2Int(x_unreduced.issuer_key_info.x)
    x_unreduced.issuer_key_info.x = util.Int2Bytes(x + mod)
    y = util.Bytes2Int(y_unreduced.issuer_key_info.y)
    y_unreduced.issuer_key_info.y = util.Int2Bytes(y + mod)
    sigs = [reduced, x_unreduced, y_unreduced]
    for sig in sigs:
      sig.ClearField('test_info')  # Do not inherit results of other tests.
    check = ecdsa_sig_checks.CheckNonceReuse()
    self.assertTrue(check.Check(sigs))
    self.assertResults(sigs, check.check_name, True)

  def testCheckIssuerKeySameCoordinatesOnTwoCurves(self):
    # Two issuer keys with the same coordinates on different curves are
    # different keys. The secp256k1 copy is not on that curve, so it is
    # invalid and its signature must be flagged.
    valid_sig = copy.deepcopy(good_ecdsa_secp256r1)
    other_curve_sig = copy.deepcopy(good_ecdsa_secp256r1)
    other_curve_sig.issuer_key_info.curve_type = (
        paranoid_pb2.CurveType.CURVE_SECP256K1)
    check = ecdsa_sig_checks.CheckIssuerKey()
    self.assertTrue(check.Check([valid_sig, other_curve_sig]))
    self.assertResults([valid_sig], check.check_name, False)
    self.assertResults([other_curve_sig], check.check_name, True)

  def testCheckIssuerKeyTestsUnreducedEncodingApart(self):
    # An issuer key encoded with x + p is invalid as encoded, so its signature
    # must be flagged, in either order, without flagging the signature that
    # carries the reduced encoding of the same key.
    mod = 2**256 - 2**224 + 2**192 + 2**96 - 1  # secp256r1 field prime
    for unreduced_first in (False, True):
      reduced_sig = copy.deepcopy(good_ecdsa_secp256r1)
      unreduced_sig = copy.deepcopy(good_ecdsa_secp256r1)
      x = util.Bytes2Int(unreduced_sig.issuer_key_info.x)
      unreduced_sig.issuer_key_info.x = util.Int2Bytes(x + mod)
      for sig in (reduced_sig, unreduced_sig):
        sig.ClearField('test_info')
      sigs = ([unreduced_sig, reduced_sig] if unreduced_first
              else [reduced_sig, unreduced_sig])
      check = ecdsa_sig_checks.CheckIssuerKey()
      self.assertTrue(check.Check(sigs))
      self.assertResults([reduced_sig], check.check_name, False)
      self.assertResults([unreduced_sig], check.check_name, True)

  def testCheckCr50U2fUnreducedIssuerKey(self):
    # Every nonce check groups issuer keys through the same reduced points, so
    # Cr50 signatures whose issuer keys are encoded with x + p are still found.
    sigs = copy.deepcopy(bad_ecdsa_cr50u2f)
    mod = 2**256 - 2**224 + 2**192 + 2**96 - 1  # secp256r1 field prime
    for sig in sigs:
      x = util.Bytes2Int(sig.issuer_key_info.x)
      sig.issuer_key_info.x = util.Int2Bytes(x + mod)
      sig.ClearField('test_info')
    check = ecdsa_sig_checks.CheckCr50U2f()
    self.assertTrue(check.Check(sigs))
    self.assertResults(sigs, check.check_name, True)

  def testCheckLCGNonceGMP(self):
    check = ecdsa_sig_checks.CheckLCGNonceGMP()
    self.assertTrue(check.Check(bad_ecdsa_lcg_gmp))
    self.assertResults(bad_ecdsa_lcg_gmp, check.check_name, True)

  def testCheckLCGNonceJavaUtilRandom(self):
    check = ecdsa_sig_checks.CheckLCGNonceJavaUtilRandom()
    self.assertTrue(check.Check(bad_ecdsa_lcg_java))
    self.assertResults(bad_ecdsa_lcg_java, check.check_name, True)

  def testCheckNonceMSB(self):
    check = ecdsa_sig_checks.CheckNonceMSB()
    self.assertTrue(check.Check(bad_ecdsa_msb))
    self.assertResults(bad_ecdsa_msb, check.check_name, True)

  def testCheckNonceCommonPrefix(self):
    check = ecdsa_sig_checks.CheckNonceCommonPrefix()
    self.assertTrue(check.Check(bad_ecdsa_common_prefix))
    self.assertResults(bad_ecdsa_common_prefix, check.check_name, True)

  def testCheckNonceCommonPostfix(self):
    check = ecdsa_sig_checks.CheckNonceCommonPostfix()
    self.assertTrue(check.Check(bad_ecdsa_common_postfix))
    self.assertResults(bad_ecdsa_common_postfix, check.check_name, True)

  def testCheckNonceGeneralized(self):
    check = ecdsa_sig_checks.CheckNonceGeneralized()
    self.assertTrue(check.Check(bad_ecdsa_generalized))
    self.assertResults(bad_ecdsa_generalized, check.check_name, True)

  def testCheckAllECDSASigs(self):
    self.assertFalse(paranoid.CheckAllECDSASigs(good_ecdsa_sigs))
    for ecdsa_check_name in paranoid.GetECDSAAllChecks():
      self.assertResults(good_ecdsa_sigs, ecdsa_check_name, False)

  def testCheckAllECDSASigsWithInvalidSignature(self):
    # s = 0 is not a valid ECDSA signature and has no modular inverse. The
    # nonce checks skip it without aborting the batch, and only the range check
    # reports it.
    invalid_sig = copy.deepcopy(good_ecdsa_secp256r1)
    invalid_sig.ClearField('test_info')
    invalid_sig.ecdsa_sig_info.s = util.Int2Bytes(0)
    good_sig = copy.deepcopy(good_ecdsa_secp256r1)
    good_sig.ClearField('test_info')
    self.assertTrue(paranoid.CheckAllECDSASigs([invalid_sig, good_sig]))
    for check_name in paranoid.GetECDSAAllChecks():
      self.assertResults([good_sig], check_name, False)
      self.assertResults([invalid_sig], check_name,
                         check_name == 'CheckECDSASignatureRange')

  def testImportBeforeParanoid(self):
    # This test module has already imported paranoid, so a fresh interpreter
    # is needed to import ecdsa_sig_checks first.
    subprocess.run(
        [sys.executable, '-c',
         'from paranoid_crypto.lib import ecdsa_sig_checks'],
        check=True)


if __name__ == '__main__':
  absltest.main()
