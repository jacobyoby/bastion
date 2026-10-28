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
"""Size-capped HTTP fetches for AIA, OCSP, and CRLs.

Redirects are not followed. Only http and https are requested. A transport
failure or a non-200 response is unanswered, which callers must not treat
as a successful check.
"""

import urllib.error
import urllib.parse
import urllib.request

from tlscheck import __version__

_MAX_BYTES = 1024 * 1024
_TIMEOUT_SECONDS = 5


class FetchResponse:
  """Body of one HTTP exchange, or a note that nothing usable came back."""

  def __init__(self, body: bytes = None, unanswered: bool = False,
               note: str = ''):
    self.body = body
    self.unanswered = unanswered
    self.note = note


class _RedirectRefused(urllib.error.HTTPError):
  """Raised so urllib does not follow a 3xx."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
  """Refuse every redirect. The alpha does not follow them."""

  def redirect_request(self, req, fp, code, msg, headers, newurl):
    raise _RedirectRefused(newurl, code, msg, headers, fp)


def fetch_url(url: str, method: str = 'GET', body: bytes = None,
              content_type: str = None) -> FetchResponse:
  """GET or POST url. Never follows a redirect. Caps the body at 1 MiB."""
  parsed = urllib.parse.urlparse(url)
  if parsed.scheme not in ('http', 'https'):
    return FetchResponse(
        unanswered=True,
        note=f'unsupported URL scheme {parsed.scheme or "(none)"}')
  headers = {'User-Agent': f'tlscheck/{__version__}'}
  if content_type:
    headers['Content-Type'] = content_type
  request = urllib.request.Request(
      url, data=body, headers=headers, method=method)
  opener = urllib.request.build_opener(_NoRedirect)
  try:
    with opener.open(request, timeout=_TIMEOUT_SECONDS) as response:
      payload = response.read(_MAX_BYTES + 1)
      status = getattr(response, 'status', 200)
  except _RedirectRefused:
    return FetchResponse(unanswered=True, note='redirect was not followed')
  except urllib.error.HTTPError as exc:
    return FetchResponse(
        unanswered=True, note=f'HTTP {exc.code}')
  except Exception as exc:
    return FetchResponse(unanswered=True, note=str(exc))
  if status != 200:
    return FetchResponse(unanswered=True, note=f'HTTP {status}')
  if len(payload) > _MAX_BYTES:
    return FetchResponse(
        unanswered=False, note='response exceeds 1 MiB')
  if not payload:
    return FetchResponse(unanswered=True, note='empty response')
  return FetchResponse(body=payload, note='ok')
