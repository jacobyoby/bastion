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
"""Capture the certificates a TLS server presents.

Verification is disabled for the handshake so an expired, untrusted, or
name-mismatched server still yields a Certificate message. The OS trust
store is not loaded. Chain checks happen afterwards, against the caller's
store.

OCSP stapling is not exposed by the ssl module on Python 3.11 and 3.12.
The status_request extension is enabled, and the stapled response is read,
through OpenSSL's SSL_ctrl on the SSL object inside CPython's _ssl socket.
"""

import ctypes
import ctypes.util
import ipaddress
import socket
import ssl

import _ssl

from tlscheck.certs import a_label
from tlscheck.certs import load_certificates
from tlscheck.errors import TlscheckError

# SSL_ctrl commands from openssl/ssl.h and openssl/tls1.h.
_SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE = 65
_SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP = 70
_TLSEXT_STATUSTYPE_OCSP = 1

# PySSLSocket starts with PyObject_HEAD (ob_refcnt, ob_type), then the
# Socket weakref, then SSL *ssl. Index 3 is that SSL pointer on CPython
# 3.11 through 3.13. SSL_get_version is compared with the socket's version
# before the pointer is used to read a staple.
_SSL_POINTER_INDEX = 3

_CONNECT_TIMEOUT_SECONDS = 10

_LIBSSL = None


class Capture:
  """What the handshake actually produced."""

  def __init__(self, peer_ip: str, peer_port: int, tls_version: str,
               sni: str, certificates: list, staple: bytes):
    self.peer_ip = peer_ip
    self.peer_port = peer_port
    self.tls_version = tls_version
    self.sni = sni
    self.certificates = certificates
    self.staple = staple


def _libssl():
  global _LIBSSL
  if _LIBSSL is not None:
    return _LIBSSL
  path = ctypes.util.find_library('ssl')
  if not path:
    raise TlscheckError('OpenSSL libssl was not found; cannot capture TLS')
  library = ctypes.CDLL(path)
  library.SSL_ctrl.argtypes = [
      ctypes.c_void_p, ctypes.c_int, ctypes.c_long, ctypes.c_void_p]
  library.SSL_ctrl.restype = ctypes.c_long
  library.SSL_get_version.argtypes = [ctypes.c_void_p]
  library.SSL_get_version.restype = ctypes.c_char_p
  _LIBSSL = library
  return library


def _ssl_pointer(sslobj):
  raw = ctypes.cast(id(sslobj), ctypes.POINTER(ctypes.c_void_p))
  return raw[_SSL_POINTER_INDEX]


def _request_ocsp_stapling(sslobj) -> None:
  pointer = _ssl_pointer(sslobj)
  if not pointer:
    raise TlscheckError('could not locate the OpenSSL session')
  result = _libssl().SSL_ctrl(
      pointer, _SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE,
      _TLSEXT_STATUSTYPE_OCSP, None)
  if result != 1:
    raise TlscheckError('could not request an OCSP staple')


def _read_staple(sslobj, tls_version: str):
  pointer = _ssl_pointer(sslobj)
  if not pointer:
    raise TlscheckError('could not locate the OpenSSL session')
  reported = _libssl().SSL_get_version(pointer)
  if reported != tls_version.encode('ascii'):
    raise TlscheckError(
        'OpenSSL session pointer did not match the negotiated version')
  buffer = ctypes.c_void_p()
  length = _libssl().SSL_ctrl(
      pointer, _SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP, 0,
      ctypes.byref(buffer))
  # -1 is OpenSSL's "no OCSP response data", not an error.
  if length is None or length <= 0 or not buffer.value:
    return None
  return ctypes.string_at(buffer.value, length)


def _peer_cert_der(item) -> bytes:
  if isinstance(item, (bytes, bytearray, memoryview)):
    return bytes(item)
  encoding = getattr(_ssl, 'ENCODING_DER', None)
  if encoding is not None and hasattr(item, 'public_bytes'):
    data = item.public_bytes(encoding)
    if isinstance(data, str):
      return ssl.PEM_cert_to_DER_cert(data)
    return bytes(data)
  if hasattr(item, 'public_bytes'):
    data = item.public_bytes()
    if isinstance(data, str):
      return ssl.PEM_cert_to_DER_cert(data)
    return bytes(data)
  raise TlscheckError('TLS stack returned a certificate in an unknown form')


def _sni_for(host: str, sni: str):
  chosen = sni if sni is not None else host
  if not chosen:
    return None
  try:
    ipaddress.ip_address(chosen)
  except ValueError:
    return a_label(chosen)
  if sni is None:
    return None
  return chosen


def _unverified_chain(sslsock):
  if hasattr(sslsock, 'get_unverified_chain'):
    return sslsock.get_unverified_chain()
  sslobj = getattr(sslsock, '_sslobj', None)
  if sslobj is None or not hasattr(sslobj, 'get_unverified_chain'):
    raise TlscheckError(
        'this Python build cannot report the peer certificate chain')
  return sslobj.get_unverified_chain()


def capture_tls(host: str, port: int, sni: str = None,
                ip: str = None) -> Capture:
  """Handshake with verification off and return the presented certificates.

  Connects to ip when given, otherwise to host. SNI defaults to host when
  host is a domain name.
  """
  if port < 1 or port > 65535:
    raise TlscheckError(f'port {port} is outside 1..65535')
  server_name = _sni_for(host, sni)
  destination = ip or host
  # PROTOCOL_TLS_CLIENT does not load system trust anchors by itself.
  # create_default_context would, so it is not used. CERT_NONE keeps the
  # handshake alive for certificates we will reject ourselves.
  context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
  context.check_hostname = False
  context.verify_mode = ssl.CERT_NONE
  try:
    raw = socket.create_connection(
        (destination, port), timeout=_CONNECT_TIMEOUT_SECONDS)
  except OSError as exc:
    raise TlscheckError(
        f'could not connect to {destination}:{port}: {exc}') from exc
  sslsock = None
  try:
    sslsock = context.wrap_socket(
        raw, server_hostname=server_name, do_handshake_on_connect=False)
    _request_ocsp_stapling(sslsock._sslobj)
    try:
      sslsock.do_handshake()
    except ssl.SSLError as exc:
      raise TlscheckError(f'TLS handshake failed: {exc}') from exc
    except OSError as exc:
      raise TlscheckError(f'TLS handshake failed: {exc}') from exc
    version = sslsock.version()
    if not version:
      raise TlscheckError('TLS handshake did not negotiate a version')
    peer = sslsock.getpeername()
    raw_chain = _unverified_chain(sslsock)
    if not raw_chain:
      raise TlscheckError('server sent no certificates')
    try:
      der_certs = [_peer_cert_der(item) for item in raw_chain]
      certificates = []
      for der in der_certs:
        certificates.extend(load_certificates(der))
    except TlscheckError:
      raise
    except ValueError as exc:
      raise TlscheckError(f'could not parse peer certificates: {exc}') from exc
    if not certificates:
      raise TlscheckError('server sent no certificates')
    staple = _read_staple(sslsock._sslobj, version)
  finally:
    if sslsock is not None:
      try:
        sslsock.close()
      except OSError:
        pass
    else:
      raw.close()
  return Capture(
      peer_ip=str(peer[0]),
      peer_port=int(peer[1]),
      tls_version=version,
      sni=server_name,
      certificates=certificates,
      staple=staple)
