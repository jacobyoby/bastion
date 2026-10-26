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
"""Parses OpenSSH public keys into RSAKey and ECKey protos.

Reads the lines of OpenSSH authorized_keys and known_hosts files, whose format
sshd(8) describes; ssh-keyscan prints known_hosts lines and *.pub files hold
authorized_keys lines. The key blobs are ssh-rsa (RFC 4253, section 6.6),
ecdsa-sha2-nistp256, -nistp384 and -nistp521 (RFC 5656, section 3.1), and
OpenSSH's FIDO security keys, sk-ecdsa-sha2-nistp256@openssh.com
(PROTOCOL.u2f).

Only the encoding is checked. OpenSSH and the cryptography library reject keys
such as RSA moduli under 1024 bits or points off the curve, which are what the
checks look for, so this parser keeps them. Like OpenSSH, it accepts only
uncompressed EC points.

Each key's origin_info holds the decoded key blob as raw_data and its SHA-256
as fingerprint, the hash that `ssh-keygen -l` prints after "SHA256:".

Usage:
  keys = ssh_keys.ParseKnownHosts(open('known_hosts').read())
  paranoid.CheckAllRSA(keys.rsa_keys)
  paranoid.CheckAllEC(keys.ec_keys)
"""

import base64
import hashlib
import re
from typing import Callable, NamedTuple, Union
from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import util

SshKey = Union[paranoid_pb2.RSAKey, paranoid_pb2.ECKey]


class _ECKeyType(NamedTuple):
  curve_name: bytes
  curve_type: int
  coordinate_bytes: int
  # Security keys append an application string to the point (PROTOCOL.u2f).
  has_application: bool


_RSA_KEY_TYPE = 'ssh-rsa'
_EC_KEY_TYPES = {
    'ecdsa-sha2-nistp256':
        _ECKeyType(b'nistp256', paranoid_pb2.CurveType.CURVE_SECP256R1, 32,
                   False),
    'ecdsa-sha2-nistp384':
        _ECKeyType(b'nistp384', paranoid_pb2.CurveType.CURVE_SECP384R1, 48,
                   False),
    'ecdsa-sha2-nistp521':
        _ECKeyType(b'nistp521', paranoid_pb2.CurveType.CURVE_SECP521R1, 66,
                   False),
    'sk-ecdsa-sha2-nistp256@openssh.com':
        _ECKeyType(b'nistp256', paranoid_pb2.CurveType.CURVE_SECP256R1, 32,
                   True),
}
_KNOWN_HOSTS_MARKERS = ('@cert-authority', '@revoked')
# Non-empty base64 with padding (RFC 4648, section 4).
_BASE64 = re.compile(r'(?:[A-Za-z0-9+/]{4})*'
                     r'(?:[A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)')
# A field and the blanks after it. OpenSSH separates fields by spaces and tabs.
_FIELD = re.compile(r'([^ \t]*)[ \t]*')


class UnsupportedKeyTypeError(Exception):
  """Raised for a well-formed key of a type the checks do not cover."""

  def __init__(self, key_type: str):
    super().__init__(f'unsupported SSH key type {key_type!r}')
    self.key_type = key_type


class UnsupportedKey(NamedTuple):
  """A key of an unsupported type, by its line number (from 1) in the file."""
  line_number: int
  key_type: str


class SshKeys(NamedTuple):
  """The keys in a file, split by the checks that test them."""
  rsa_keys: list[paranoid_pb2.RSAKey]
  ec_keys: list[paranoid_pb2.ECKey]
  unsupported: list[UnsupportedKey]


def _String(data: bytes) -> bytes:
  """Encodes data as an SSH string (RFC 4251, section 5)."""
  return len(data).to_bytes(4, 'big') + data


def _ReadString(blob: bytes, offset: int) -> tuple[bytes, int]:
  """Returns the SSH string at offset in blob and the offset after it."""
  end = offset + 4 + int.from_bytes(blob[offset:offset + 4], 'big')
  if end > len(blob):
    raise ValueError(f'SSH key blob is truncated: the string at offset '
                     f'{offset} ends at {end}, past the blob end {len(blob)}')
  return blob[offset + 4:end], end


def _ReadMpint(blob: bytes, offset: int) -> tuple[int, int]:
  """Returns the SSH mpint at offset in blob and the offset after it."""
  value, end = _ReadString(blob, offset)
  if value and value[0] & 0x80:
    raise ValueError(f'SSH key blob has a negative mpint at offset {offset}')
  return util.Bytes2Int(value), end


def _CheckConsumed(blob: bytes, offset: int) -> None:
  if offset != len(blob):
    raise ValueError(f'SSH key blob has {len(blob) - offset} bytes of trailing '
                     f'data after offset {offset}')


def _RSAKey(blob: bytes, offset: int) -> paranoid_pb2.RSAKey:
  """Returns the key from the fields of an ssh-rsa blob after its type."""
  e, offset = _ReadMpint(blob, offset)
  n, offset = _ReadMpint(blob, offset)
  _CheckConsumed(blob, offset)
  key = paranoid_pb2.RSAKey()
  key.rsa_info.e = util.Int2Bytes(e)
  key.rsa_info.n = util.Int2Bytes(n)
  return key


def _ECKey(key_type: str, blob: bytes, offset: int) -> paranoid_pb2.ECKey:
  """Returns the key from the fields of an ECDSA blob after its type."""
  ec_type = _EC_KEY_TYPES[key_type]
  curve_name, offset = _ReadString(blob, offset)
  if curve_name != ec_type.curve_name:
    raise ValueError(f'{key_type} key has curve {curve_name!r}, expected '
                     f'{ec_type.curve_name!r}')
  point, offset = _ReadString(blob, offset)
  if ec_type.has_application:
    _, offset = _ReadString(blob, offset)
  _CheckConsumed(blob, offset)
  size = ec_type.coordinate_bytes
  if len(point) != 1 + 2 * size or point[0] != 4:
    raise ValueError(f'{key_type} key point is not uncompressed: expected '
                     f'0x04 and {2 * size} bytes, got {len(point)} bytes '
                     f'starting {point[:1].hex()!r}')
  key = paranoid_pb2.ECKey()
  key.ec_info.curve_type = ec_type.curve_type
  key.ec_info.x = util.Int2Bytes(util.Bytes2Int(point[1:1 + size]))
  key.ec_info.y = util.Int2Bytes(util.Bytes2Int(point[1 + size:]))
  return key


def _SplitField(text: str) -> tuple[str, str]:
  """Returns the first field of text and the text after its blanks."""
  match = _FIELD.match(text)
  return match.group(1), text[match.end():]


def _KeyFields(text: str) -> tuple[str, str]:
  """Returns the key type and base64 blob fields at the start of text."""
  key_type, rest = _SplitField(text)
  blob_b64, _ = _SplitField(rest)
  return key_type, blob_b64


def _IsKeyAt(text: str) -> bool:
  """Returns whether text starts with a key type and a blob of that type."""
  key_type, blob_b64 = _KeyFields(text)
  # A first field with a quote is options split at a quoted blank, never a key
  # type, even if the text after the blank is a blob that names it.
  return '"' not in key_type and bool(
      _BASE64.fullmatch(blob_b64)) and base64.b64decode(
      blob_b64).startswith(_String(key_type.encode()))


def _KeyAt(text: str) -> SshKey:
  """Returns the key whose type and base64 blob fields start text."""
  key_type, blob_b64 = _KeyFields(text)
  if not _BASE64.fullmatch(blob_b64):
    raise ValueError(f'SSH key of type {key_type!r} has no base64 key blob: '
                     f'{blob_b64!r}')
  blob = base64.b64decode(blob_b64)
  blob_type, offset = _ReadString(blob, 0)
  if blob_type != key_type.encode():
    raise ValueError(f'SSH key type {key_type!r} does not match the type '
                     f'{blob_type!r} in its key blob')
  if key_type == _RSA_KEY_TYPE:
    key = _RSAKey(blob, offset)
  elif key_type in _EC_KEY_TYPES:
    key = _ECKey(key_type, blob, offset)
  else:
    raise UnsupportedKeyTypeError(key_type)
  key.origin_info.raw_data = blob
  key.origin_info.fingerprint = hashlib.sha256(blob).digest()
  return key


def _LineText(line: str) -> str:
  """Returns line without its leading blanks and line ending."""
  return line.rstrip('\r\n').lstrip(' \t')


def _SkipOptions(text: str) -> str:
  """Returns text after its authorized_keys options field and blanks.

  Follows OpenSSH's sshkey_advance_past_options: blanks end the field except
  inside double quotes, and \\" never opens or closes a quote.

  Args:
    text: an authorized_keys line that starts with options.
  """
  quoted = False
  i = 0
  while i < len(text) and (quoted or text[i] not in ' \t'):
    if text[i] == '\\' and text[i + 1:i + 2] == '"':
      i += 1
    elif text[i] == '"':
      quoted = not quoted
    i += 1
  if quoted:
    raise ValueError(f'authorized_keys options have an unterminated quote: '
                     f'{text!r}')
  return _SplitField(text[i:])[1]


def ParseAuthorizedKeysLine(line: str) -> SshKey:
  """Returns the key in one line of an authorized_keys or *.pub file.

  The line holds optional options, the key type, the base64 key blob and an
  optional comment. As in OpenSSH, the line starts with options unless its
  first two fields are a key type and a blob of that type.

  Args:
    line: the line, with or without its line ending.

  Raises:
    UnsupportedKeyTypeError: the key is well-formed but not RSA or ECDSA.
    ValueError: the line holds no well-formed key, as comment and blank lines
      do not.
  """
  text = _LineText(line)
  if not _IsKeyAt(text):
    text = _SkipOptions(text)
    if not _IsKeyAt(text):
      raise ValueError(f'authorized_keys line has no SSH key: {line!r}')
  return _KeyAt(text)


def ParseKnownHostsLine(line: str) -> SshKey:
  """Returns the key in one line of a known_hosts file or ssh-keyscan output.

  The line holds an optional @cert-authority or @revoked marker, the host
  names, the key type, the base64 key blob and an optional comment.

  Args:
    line: the line, with or without its line ending.

  Raises:
    UnsupportedKeyTypeError: the key is well-formed but not RSA or ECDSA.
    ValueError: the line holds no well-formed key, as comment and blank lines
      do not.
  """
  text = _LineText(line)
  if text.startswith('@'):
    marker, text = _SplitField(text)
    if marker not in _KNOWN_HOSTS_MARKERS:
      raise ValueError(f'known_hosts line has marker {marker!r}, expected one '
                       f'of {_KNOWN_HOSTS_MARKERS}')
    if text.startswith('@'):
      raise ValueError(f'known_hosts line has more than one marker: {line!r}')
  _, text = _SplitField(text)
  return _KeyAt(text)


def _ParseFile(text: str, parse_line: Callable[[str], SshKey]) -> SshKeys:
  """Returns the keys in text, parsing each key line with parse_line.

  Skips blank lines and lines whose first non-blank character is #, as
  OpenSSH does.

  Args:
    text: the file contents.
    parse_line: ParseAuthorizedKeysLine or ParseKnownHostsLine.

  Raises:
    ValueError: a line holds no well-formed key; the message names the line.
  """
  keys = SshKeys([], [], [])
  for line_number, line in enumerate(text.split('\n'), 1):
    line_text = _LineText(line)
    if not line_text or line_text.startswith('#'):
      continue
    try:
      key = parse_line(line)
    except UnsupportedKeyTypeError as e:
      keys.unsupported.append(UnsupportedKey(line_number, e.key_type))
      continue
    except ValueError as e:
      raise ValueError(f'line {line_number}: {e}') from e
    if isinstance(key, paranoid_pb2.RSAKey):
      keys.rsa_keys.append(key)
    else:
      keys.ec_keys.append(key)
  return keys


def ParseAuthorizedKeys(text: str) -> SshKeys:
  """Returns the keys in the contents of an authorized_keys file.

  Args:
    text: the file contents.

  Raises:
    ValueError: a line holds no well-formed key; the message names the line.
  """
  return _ParseFile(text, ParseAuthorizedKeysLine)


def ParseKnownHosts(text: str) -> SshKeys:
  """Returns the keys in the contents of a known_hosts file or ssh-keyscan.

  Args:
    text: the file contents or ssh-keyscan output.

  Raises:
    ValueError: a line holds no well-formed key; the message names the line.
  """
  return _ParseFile(text, ParseKnownHostsLine)
