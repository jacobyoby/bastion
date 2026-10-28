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
"""Errors that abort a tlscheck run before a report exists."""


class TlscheckError(Exception):
  """The handshake, the saved chain, or an argument could not be used.

  exit_code is 2: connect, parse, and capture failures. Check failures are
  reported with exit code 1 and are not this exception.
  """

  def __init__(self, message: str):
    super().__init__(message)
    self.exit_code = 2
