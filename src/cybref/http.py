"""HTTP downloads: retries with backoff, resume of interrupted transfers, per-host limits,
conditional requests."""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger("cybref.http")

DEFAULT_UA = "Cybref/2.0 (+https://github.com/skouedlabs/Cybref)"
PER_HOST = 2  # flaky hosts (IEEE...) fail when hammered by parallel requests
_RETRY_STATUS = {408, 418, 425, 429, 500, 502, 503, 504, 520, 521, 522, 524}
_MAX_DELAY = 120.0

_host_locks: dict[str, asyncio.Semaphore] = defaultdict(lambda: asyncio.Semaphore(PER_HOST))


class NotModified(Exception):
    """Server answered 304: the stored copy is still current."""


class IncompleteDownload(httpx.TransportError):
    pass


@dataclass
class FetchMeta:
    url: str
    etag: str | None = None
    last_modified: str | None = None


def make_client() -> httpx.AsyncClient:
    _host_locks.clear()  # semaphores are bound to the running event loop
    return httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(connect=30.0, read=180.0, write=60.0, pool=None),
        headers={"User-Agent": DEFAULT_UA},
        limits=httpx.Limits(max_connections=32, max_keepalive_connections=16),
    )


def _host(url: str) -> str:
    return urlsplit(url).hostname or ""


def _backoff(attempt: int, resp: httpx.Response | None = None) -> float:
    if resp is not None:
        try:
            return min(float(resp.headers.get("Retry-After", "")), _MAX_DELAY)
        except ValueError:
            pass
    return min(5.0 * 2 ** (attempt - 1), _MAX_DELAY)  # 5, 10, 20, 40...


async def download(
    client: httpx.AsyncClient,
    url: str,
    dest: Path,
    *,
    headers: dict[str, str] | None = None,
    etag: str | None = None,
    last_modified: str | None = None,
    attempts: int = 5,
) -> FetchMeta:
    """Stream *url* to *dest*.

    - retries transport errors / 5xx / 429 with exponential backoff (honours Retry-After);
    - an interrupted transfer resumes with a Range request when the server supports it;
    - a body shorter than Content-Length is treated as a transport error.
    Raises NotModified on 304, httpx errors once attempts are exhausted.
    """
    base_headers = dict(headers or {})
    if etag:
        base_headers["If-None-Match"] = etag
    if last_modified:
        base_headers["If-Modified-Since"] = last_modified
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.unlink(missing_ok=True)
    resumable = False
    meta: FetchMeta | None = None

    async with _host_locks[_host(url)]:
        for attempt in range(1, attempts + 1):
            req_headers = dict(base_headers)
            offset = dest.stat().st_size if resumable and dest.exists() else 0
            if offset:
                req_headers["Range"] = f"bytes={offset}-"
                req_headers.pop("If-None-Match", None)
                req_headers.pop("If-Modified-Since", None)
            try:
                async with client.stream("GET", url, headers=req_headers) as resp:
                    if resp.status_code == 304:
                        raise NotModified(url)
                    if resp.status_code in _RETRY_STATUS and attempt < attempts:
                        wait = _backoff(attempt, resp)
                        logger.warning("%s -> HTTP %d, retry %d/%d in %.0fs",
                                       url, resp.status_code, attempt, attempts - 1, wait)
                        await asyncio.sleep(wait)
                        continue
                    resp.raise_for_status()

                    append = offset and resp.status_code == 206
                    if offset and not append:
                        logger.info("%s: server ignored Range, restarting from 0", url)
                    if not offset:
                        meta = FetchMeta(str(resp.url), resp.headers.get("ETag"),
                                         resp.headers.get("Last-Modified"))
                    resumable = (resp.headers.get("Accept-Ranges") == "bytes"
                                 and "Content-Encoding" not in resp.headers)
                    expected = _expected_length(resp)
                    received = 0
                    with dest.open("ab" if append else "wb") as fh:
                        async for chunk in resp.aiter_bytes(1 << 20):
                            fh.write(chunk)
                            received += len(chunk)
                    if expected is not None and received < expected:
                        raise IncompleteDownload(f"got {received} of {expected} bytes")
                    return meta or FetchMeta(str(resp.url))
            except (httpx.TransportError, httpx.DecodingError) as exc:
                if attempt >= attempts:
                    raise
                wait = _backoff(attempt)
                logger.warning("%s -> %s (%s), retry %d/%d in %.0fs%s", url, type(exc).__name__,
                               exc, attempt, attempts - 1, wait, " (will resume)" if resumable else "")
                await asyncio.sleep(wait)
    raise RuntimeError("unreachable")


def _expected_length(resp: httpx.Response) -> int | None:
    """Body length to expect, only when it is not transfer-encoded."""
    if "Content-Encoding" in resp.headers:
        return None
    try:
        return int(resp.headers["Content-Length"])
    except (KeyError, ValueError):
        return None


async def get_text(client: httpx.AsyncClient, url: str, **kwargs) -> str:
    return (await _get(client, url, **kwargs)).text


async def get_bytes(client: httpx.AsyncClient, url: str, **kwargs) -> bytes:
    return (await _get(client, url, **kwargs)).content


async def _get(client: httpx.AsyncClient, url: str, attempts: int = 5, **kwargs) -> httpx.Response:
    async with _host_locks[_host(url)]:
        for attempt in range(1, attempts + 1):
            try:
                resp = await client.get(url, **kwargs)
                if resp.status_code in _RETRY_STATUS and attempt < attempts:
                    await asyncio.sleep(_backoff(attempt, resp))
                    continue
                resp.raise_for_status()
                return resp
            except httpx.TransportError:
                if attempt >= attempts:
                    raise
                await asyncio.sleep(_backoff(attempt))
    raise RuntimeError("unreachable")
