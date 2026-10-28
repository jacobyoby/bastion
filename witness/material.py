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
"""Parse public certificates and public keys. Private keys are skipped."""

import hashlib
import os
import re
import warnings
from dataclasses import dataclass, field
from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import ed448
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import x448

from paranoid_crypto import paranoid_pb2
from paranoid_crypto.lib import util

from witness.scan import SourceRead
from witness.scan import parse_sources

# A file larger than this is not loaded. System bundles use a separate cap.
MAX_FILE_BYTES = 1024 * 1024

_BEGIN = re.compile(br'-----BEGIN ([A-Z0-9 ]+)-----')
_CERT_LABELS = frozenset(
    ('CERTIFICATE', 'X509 CERTIFICATE', 'TRUSTED CERTIFICATE'))
_PUBLIC_LABELS = frozenset(('PUBLIC KEY', 'RSA PUBLIC KEY', 'EC PUBLIC KEY'))
_SSH_NAMES = frozenset(('authorized_keys', 'known_hosts'))
_SSH_EXTS = frozenset(('.pub',))

_CURVE_BY_NAME = {
    'secp192r1': paranoid_pb2.CurveType.CURVE_SECP192R1,
    'secp224r1': paranoid_pb2.CurveType.CURVE_SECP224R1,
    'secp256r1': paranoid_pb2.CurveType.CURVE_SECP256R1,
    'secp384r1': paranoid_pb2.CurveType.CURVE_SECP384R1,
    'secp521r1': paranoid_pb2.CurveType.CURVE_SECP521R1,
    'secp256k1': paranoid_pb2.CurveType.CURVE_SECP256K1,
    'brainpoolp256r1': paranoid_pb2.CurveType.CURVE_BRAINPOOLP256R1,
    'brainpoolp384r1': paranoid_pb2.CurveType.CURVE_BRAINPOOLP384R1,
    'brainpoolp512r1': paranoid_pb2.CurveType.CURVE_BRAINPOOLP512R1,
    'sect163k1': paranoid_pb2.CurveType.CURVE_SECT163K1,
    'sect233k1': paranoid_pb2.CurveType.CURVE_SECT233K1,
    'sect283k1': paranoid_pb2.CurveType.CURVE_SECT283K1,
    'sect409k1': paranoid_pb2.CurveType.CURVE_SECT409K1,
    'sect571k1': paranoid_pb2.CurveType.CURVE_SECT571K1,
    'sect163r2': paranoid_pb2.CurveType.CURVE_SECT163R2,
    'sect233r1': paranoid_pb2.CurveType.CURVE_SECT233R1,
    'sect283r1': paranoid_pb2.CurveType.CURVE_SECT283R1,
    'sect409r1': paranoid_pb2.CurveType.CURVE_SECT409R1,
    'sect571r1': paranoid_pb2.CurveType.CURVE_SECT571R1,
}


@dataclass
class KeyMaterial:
  """One public key ready for Bastion, plus where it was found."""

  section: str
  group: str
  path: str
  subject: str | None
  key: Any


@dataclass
class ParsedFile:
  """Public material extracted from one file. Private files have no keys."""

  private: bool = False
  cert_count: int = 0
  keys: list[tuple[Any, str | None]] = field(default_factory=list)
  unsupported: list[str] = field(default_factory=list)
  error: str | None = None


def _int_to_bytes(value: int) -> bytes:
  """Encode an integer the way Bastion expects. Zero is a single 0x00 byte."""
  encoded = util.Int2Bytes(value)
  if encoded:
    return encoded
  return b'\x00'


def looks_like_private_key(data: bytes) -> bool:
  """True when the file header is a PEM or OpenSSH private key."""
  if data.startswith(b'openssh-key-v1'):
    return True
  # Match the header even if the matching END line is missing.
  for match in _BEGIN.finditer(data):
    label = match.group(1).decode('ascii', errors='replace')
    if 'PRIVATE KEY' in label:
      return True
  return False


def _pem_blocks(data: bytes):
  for match in _BEGIN.finditer(data):
    label = match.group(1).decode('ascii', errors='replace')
    end_token = b'-----END ' + match.group(1) + b'-----'
    end = data.find(end_token, match.end())
    if end < 0:
      continue
    yield label, data[match.start():end + len(end_token)]


def _load_pem_cert(block: bytes) -> x509.Certificate:
  # Some roots in ca-certificates.crt have a zero serial. Cryptography warns
  # and still returns the certificate; counting them should stay quiet.
  with warnings.catch_warnings():
    warnings.simplefilter('ignore', CryptographyDeprecationWarning)
    return x509.load_pem_x509_certificate(block)


def _load_der_cert(data: bytes) -> x509.Certificate:
  with warnings.catch_warnings():
    warnings.simplefilter('ignore', CryptographyDeprecationWarning)
    return x509.load_der_x509_certificate(data)


def _subject(cert: x509.Certificate) -> str:
  try:
    text = cert.subject.rfc4514_string()
  except ValueError:
    return ''
  if len(text) > 300:
    return text[:300] + '...'
  return text


def _stamp(key, raw: bytes) -> None:
  key.origin_info.raw_data = raw
  key.origin_info.fingerprint = hashlib.sha256(raw).digest()


def _from_public_key(public_key, raw: bytes) -> tuple[Any | None, str | None]:
  """Return a paranoid proto, or (None, reason) when the type is unsupported."""
  if isinstance(public_key, rsa.RSAPublicKey):
    numbers = public_key.public_numbers()
    key = paranoid_pb2.RSAKey()
    key.rsa_info.n = _int_to_bytes(numbers.n)
    key.rsa_info.e = _int_to_bytes(numbers.e)
    _stamp(key, raw)
    return key, None
  if isinstance(public_key, ec.EllipticCurvePublicKey):
    curve_type = _CURVE_BY_NAME.get(public_key.curve.name.lower())
    if curve_type is None:
      return None, f'unsupported EC curve {public_key.curve.name}'
    numbers = public_key.public_numbers()
    key = paranoid_pb2.ECKey()
    key.ec_info.curve_type = curve_type
    key.ec_info.x = _int_to_bytes(numbers.x)
    key.ec_info.y = _int_to_bytes(numbers.y)
    _stamp(key, raw)
    return key, None
  if isinstance(public_key, (dsa.DSAPublicKey, ed25519.Ed25519PublicKey,
                             ed448.Ed448PublicKey, x25519.X25519PublicKey,
                             x448.X448PublicKey)):
    return None, f'unsupported public key type {type(public_key).__name__}'
  return None, f'unsupported public key type {type(public_key).__name__}'


def _add_cert(parsed: ParsedFile, cert: x509.Certificate) -> None:
  parsed.cert_count += 1
  try:
    public_key = cert.public_key()
    raw = cert.public_bytes(serialization.Encoding.DER)
  except (ValueError, UnsupportedAlgorithm) as exc:
    parsed.unsupported.append(str(exc))
    return
  key, reason = _from_public_key(public_key, raw)
  if key is None:
    parsed.unsupported.append(reason or 'unsupported certificate key')
    return
  parsed.keys.append((key, _subject(cert)))


def _add_public_pem(parsed: ParsedFile, block: bytes) -> None:
  try:
    public_key = serialization.load_pem_public_key(block)
  except (ValueError, UnsupportedAlgorithm) as exc:
    parsed.unsupported.append(str(exc))
    return
  try:
    raw = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
  except (ValueError, UnsupportedAlgorithm) as exc:
    parsed.unsupported.append(str(exc))
    return
  key, reason = _from_public_key(public_key, raw)
  if key is None:
    parsed.unsupported.append(reason or 'unsupported public key')
    return
  parsed.keys.append((key, None))


def _ssh_kind(path: str) -> str:
  base = os.path.basename(path)
  if base == 'known_hosts' or base.endswith('_known_hosts'):
    return 'known_hosts'
  return 'authorized_keys'


def _looks_like_ssh(text: str) -> bool:
  for line in text.splitlines():
    stripped = line.strip()
    if not stripped or stripped.startswith('#'):
      continue
    if stripped.startswith(('ssh-', 'ecdsa-', 'sk-ecdsa-', 'sk-ssh-')):
      return True
    if stripped.startswith('@') and 'ssh-' in stripped:
      return True
  return False


def _wants_ssh(path: str, text: str) -> bool:
  base = os.path.basename(path)
  if base in _SSH_NAMES or os.path.splitext(base)[1].lower() in _SSH_EXTS:
    return True
  return _looks_like_ssh(text)


def _add_ssh(parsed: ParsedFile, path: str, text: str) -> None:
  read = SourceRead(path, _ssh_kind(path), 'ok', None, text)
  sources, merged = parse_sources([read])
  entry = sources[0]
  if entry.get('parse_error'):
    parsed.error = entry['parse_error']
    return
  for key in list(merged.rsa_keys) + list(merged.ec_keys):
    parsed.keys.append((key, None))
  for item in merged.unsupported:
    parsed.unsupported.append(
        f'{item.key_type} (line {item.line_number})')


def count_certificates(data: bytes) -> int:
  """Count PEM certificates. Does not build Bastion keys."""
  count = 0
  for label, block in _pem_blocks(data):
    if label not in _CERT_LABELS:
      continue
    try:
      _load_pem_cert(block)
    except ValueError:
      continue
    count += 1
  return count


def inspect_bytes(path: str, data: bytes) -> ParsedFile:
  """Extract public keys from file bytes. Private-key files yield nothing."""
  parsed = ParsedFile()
  if looks_like_private_key(data):
    parsed.private = True
    return parsed
  for label, block in _pem_blocks(data):
    if label in _CERT_LABELS:
      try:
        cert = _load_pem_cert(block)
      except ValueError as exc:
        parsed.unsupported.append(str(exc))
        continue
      _add_cert(parsed, cert)
    elif label in _PUBLIC_LABELS:
      _add_public_pem(parsed, block)
  if parsed.keys or parsed.cert_count:
    return parsed
  ext = os.path.splitext(path)[1].lower()
  if ext in ('.crt', '.cer', '.pem') or data[:1] == b'\x30':
    try:
      cert = _load_der_cert(data)
    except ValueError:
      cert = None
    if cert is not None:
      _add_cert(parsed, cert)
      return parsed
  if _wants_ssh(path, ''):
    text = data.decode('utf-8', errors='replace')
    _add_ssh(parsed, path, text)
    return parsed
  text = data.decode('utf-8', errors='replace')
  if _looks_like_ssh(text):
    _add_ssh(parsed, path, text)
  return parsed


def read_bounded(path: str, limit: int) -> tuple[bytes | None, str | None]:
  """Read up to `limit` bytes. Returns (None, reason) when the file is skipped."""
  try:
    size = os.path.getsize(path)
  except OSError as exc:
    return None, exc.strerror or str(exc)
  if size > limit:
    return None, f'file is {size} bytes, over the {limit} byte cap'
  try:
    with open(path, 'rb') as handle:
      data = handle.read(limit + 1)
  except OSError as exc:
    return None, exc.strerror or str(exc)
  if len(data) > limit:
    return None, f'file is over the {limit} byte cap'
  return data, None
