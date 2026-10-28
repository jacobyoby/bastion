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
"""Build the C++ extension and generated protobuf modules.

Project metadata lives in pyproject.toml. Protocol buffers are compiled with
the protoc bundled by grpcio-tools so the generated code matches the
protobuf 7 runtime and a system protoc is not required.
"""

import os
import platform

from grpc_tools import protoc
from pybind11.setup_helpers import Pybind11Extension
from pybind11.setup_helpers import build_ext
import setuptools

_PROJECT_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

_BM_CC_SOURCES = [
    'paranoid_crypto/lib/randomness_tests/cc_util/berlekamp_massey.cc',
    'paranoid_crypto/lib/randomness_tests/cc_util/pybind/berlekamp_massey.cc',
]

_BM_CC_HEADERS = [
    'paranoid_crypto/lib/randomness_tests/cc_util/berlekamp_massey.h',
]

# Paths are relative to the project root.
_PARANOID_PROTOS = (
    'paranoid_crypto/paranoid.proto',
    'paranoid_crypto/lib/data/data.proto',
)


def _generate_proto(source):
  """Compile one .proto to a _pb2.py next to it."""
  source_path = os.path.join(_PROJECT_BASE_DIR, source)
  if not os.path.exists(source_path):
    raise FileNotFoundError(
        'Cannot find required file: {}'.format(source_path))

  output_path = source_path.replace('.proto', '_pb2.py')
  if (os.path.exists(output_path) and
      os.path.getmtime(source_path) < os.path.getmtime(output_path)):
    return

  print('Generating {}...'.format(output_path))
  status = protoc.main([
      'grpc_tools.protoc',
      '-I{}'.format(_PROJECT_BASE_DIR),
      '--python_out={}'.format(_PROJECT_BASE_DIR),
      source_path,
  ])
  if status not in (0, None):
    raise RuntimeError(
        'protoc failed for {} with status {}'.format(source, status))


def _get_extra_compile_args():
  """Return extra compiler flags.

  The compiler flags enable the use of CPU instructions to speed up the code.
  In particular, the Berlekamp-Massey algorithm can be sped up significantly
  by using carryless multiplication.

  Returns:
    platform dependent compiler flags
  """
  if platform.system() == 'Windows':
    args = []
  else:
    args = ['-std=c++17']
  arch = platform.machine()
  if arch in ('x86_64', 'AMD64'):
    # Tries to use _mm_clmulepi64_si128 to speed up Berlekamp-Massey.
    args.append('-mpclmul')
  elif arch == 'aarch64':
    # Tries to use vmull_p64 to speed up Berlekamp-Massey.
    args.append('-march=armv8-a+crypto')
  return args


for _proto_file in _PARANOID_PROTOS:
  _generate_proto(_proto_file)

setuptools.setup(
    ext_modules=[
        Pybind11Extension(
            'paranoid_crypto.lib.randomness_tests.cc_util.pybind'
            '.berlekamp_massey',
            sources=_BM_CC_SOURCES,
            depends=_BM_CC_HEADERS,
            include_dirs=[_PROJECT_BASE_DIR],
            extra_compile_args=_get_extra_compile_args(),
        )
    ],
    cmdclass={'build_ext': build_ext},
)
