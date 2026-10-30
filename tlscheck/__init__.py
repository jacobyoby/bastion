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
"""Standalone TLS certificate checker.

Alpha. The tool opens TLS itself and checks the certificates the server
presented against a Mozilla root bundle shipped in certifi. It is not a
paranoid_crypto check and is not invoked by the paranoid runners.

Run it with the repository root on PYTHONPATH:

  PYTHONPATH=. python -m tlscheck HOST
  PYTHONPATH=. python -m tlscheck.web
"""

__version__ = '0.1.0a1'
