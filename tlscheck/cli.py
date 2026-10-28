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
"""Command line for `python -m tlscheck`."""

import argparse
import sys

from tlscheck import __version__
from tlscheck.capture import capture_tls
from tlscheck.certs import load_certificate_file
from tlscheck.certs import parse_time
from tlscheck.errors import TlscheckError
from tlscheck.path import mozilla_trust_store
from tlscheck.report import render_json
from tlscheck.report import render_text
from tlscheck.run import run_check


def _parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
      prog='tlscheck',
      description=(
          'Check a TLS server certificate against the Mozilla roots shipped '
          f'in certifi. Alpha {__version__}. Does not use the OS trust store.'))
  parser.add_argument('host', help='hostname to check, and the default SNI')
  parser.add_argument('--port', type=int, default=443)
  parser.add_argument('--sni', default=None, help='SNI to send, if not HOST')
  parser.add_argument(
      '--ip', default=None,
      help='connect to this address instead of resolving HOST')
  parser.add_argument(
      '--name', default=None,
      help='hostname to match; defaults to HOST')
  parser.add_argument(
      '--chain', default=None,
      help='PEM file of a saved presented chain; do not connect')
  parser.add_argument(
      '--at', default=None,
      help='check time as ISO-8601; default is now')
  parser.add_argument(
      '--ocsp', choices=('staple', 'fetch', 'off'), default='staple',
      help='staple checks a handshake staple only (default); '
           'fetch also queries OCSP; off skips OCSP')
  parser.add_argument(
      '--crl', choices=('off', 'fetch'), default='off')
  parser.add_argument(
      '--pin', action='append', default=None,
      help='SPKI SHA-256 hex pin; repeat to accept any one match')
  parser.add_argument(
      '--allow-fetched', action='store_true',
      help='require the AIA-fetched path instead of the presented path')
  parser.add_argument(
      '--json', action='store_true',
      help='print one JSON object instead of the text report')
  return parser


def main(argv=None) -> int:
  parser = _parser()
  args = parser.parse_args(argv)
  try:
    when = parse_time(args.at) if args.at else None
    trust = mozilla_trust_store()
    if args.chain:
      certificates = load_certificate_file(args.chain)
      report = run_check(
          certificates,
          host=args.host,
          trust=trust,
          port=args.port,
          name=args.name,
          when=when,
          ocsp_mode=args.ocsp,
          crl_mode=args.crl,
          staple=None,
          pins=args.pin,
          allow_fetched=args.allow_fetched,
          peer_ip=None,
          peer_port=None,
          tls_version=None,
          sni=args.sni)
    else:
      captured = capture_tls(args.host, args.port, sni=args.sni, ip=args.ip)
      report = run_check(
          captured.certificates,
          host=args.host,
          trust=trust,
          port=args.port,
          name=args.name,
          when=when,
          ocsp_mode=args.ocsp,
          crl_mode=args.crl,
          staple=captured.staple,
          pins=args.pin,
          allow_fetched=args.allow_fetched,
          peer_ip=captured.peer_ip,
          peer_port=captured.peer_port,
          tls_version=captured.tls_version,
          sni=captured.sni)
  except TlscheckError as exc:
    print(f'tlscheck: {exc}', file=sys.stderr)
    return exc.exit_code
  if args.json:
    print(render_json(report))
  else:
    print(render_text(report))
  return report.exit_code
