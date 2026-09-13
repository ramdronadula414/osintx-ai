"""Bounded public HTTP JSON requests with secret-free error categories."""
from __future__ import annotations

import json
import time
import requests
from urllib3.response import HTTPResponse
from urllib3.exceptions import HTTPError, TimeoutError as TransportTimeout
from core.schema import ResultStatus


class SourceError(Exception):
    def __init__(self, status: ResultStatus, message: str):
        super().__init__(message)
        self.status = status


def request_json(method: str, url: str, *, timeout: float = 15, max_bytes: int = 2 * 1024 * 1024, **kwargs):
    start = time.monotonic()
    try:
        with requests.request(method, url, timeout=(min(5, timeout), timeout),
                              allow_redirects=False, stream=True, **kwargs) as response:
            code = response.status_code
            if code != 200:
                status = {401: ResultStatus.PERMISSION_ERROR, 403: ResultStatus.PERMISSION_ERROR,
                          404: ResultStatus.NOT_FOUND, 429: ResultStatus.RATE_LIMITED,
                          408: ResultStatus.TIMEOUT, 504: ResultStatus.TIMEOUT}.get(code, ResultStatus.API_ERROR)
                if code == 403 and response.headers.get('X-RateLimit-Remaining') == '0':
                    status = ResultStatus.RATE_LIMITED
                raise SourceError(status, f'HTTP {code}; no findings accepted')
            body = bytearray()
            # read1 returns available bytes rather than waiting to fill a chunk.
            # This lets the total deadline catch a server that trickles bytes forever.
            chunks = iter(lambda: response.raw.read1(65536, decode_content=True), b'') if isinstance(response.raw, HTTPResponse) else response.iter_content(chunk_size=1)
            for chunk in chunks:
                if time.monotonic() - start > timeout:
                    raise SourceError(ResultStatus.TIMEOUT, 'HTTP response exceeded time budget')
                body.extend(chunk)
                if len(body) > max_bytes:
                    raise SourceError(ResultStatus.API_ERROR, 'HTTP response exceeded size limit')
            try:
                return json.loads(body)
            except (ValueError, UnicodeError) as exc:
                raise SourceError(ResultStatus.API_ERROR, 'Malformed JSON response') from exc
    except (requests.Timeout, TransportTimeout) as exc:
        raise SourceError(ResultStatus.TIMEOUT, 'HTTP request timed out') from exc
    except requests.ConnectionError as exc:
        raise SourceError(ResultStatus.NETWORK_ERROR, 'Network unavailable or connection failed') from exc
    except (requests.RequestException, HTTPError) as exc:
        raise SourceError(ResultStatus.NETWORK_ERROR, 'HTTP transport failed') from exc
