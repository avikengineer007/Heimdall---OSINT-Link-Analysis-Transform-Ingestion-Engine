"""
Resilient Non-Blocking Asynchronous HTTP Transport for OSINT Collection.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Any, Dict, Optional
import httpx

logger = logging.getLogger("heimdall.transport")


class ResilientAsyncTransport:
    """
    Robust HTTP client engine enforcing strict timeouts, adaptive concurrency,
    exponential backoff with jitter, and automatic HTTP 429 Retry-After handling.
    """

    def __init__(
        self,
        client: Optional[httpx.AsyncClient] = None,
        max_concurrency: int = 20,
        default_timeout: float = 5.0,
        max_retries: int = 3,
        base_delay: float = 0.5,
        max_delay: float = 10.0,
        user_agent: str = "Heimdall-LinkAnalysis/1.0 (+https://github.com/heimdall-osint)",
    ):
        self._external_client = client is not None
        self._client = client
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.default_timeout = default_timeout
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.user_agent = user_agent

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.default_timeout, connect=3.0),
                follow_redirects=True,
                headers={"User-Agent": self.user_agent, "Accept-Encoding": "gzip, deflate"},
                limits=httpx.Limits(max_keepalive_connections=50, max_connections=100),
            )
        return self._client

    async def close(self) -> None:
        """Closes internal client if not externally managed."""
        if not self._external_client and self._client and not self._client.is_closed:
            await self._client.aclose()

    async def __aenter__(self) -> ResilientAsyncTransport:
        await self._get_client()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Any] = None,
        timeout: Optional[float] = None,
    ) -> Optional[httpx.Response]:
        """
        Executes an HTTP request within concurrency semaphore and retry loop.
        """
        client = await self._get_client()
        req_timeout = timeout or self.default_timeout
        delay = self.base_delay

        async with self.semaphore:
            for attempt in range(1, self.max_retries + 1):
                try:
                    response = await client.request(
                        method=method,
                        url=url,
                        params=params,
                        headers=headers,
                        json=json_body,
                        timeout=req_timeout,
                    )

                    # Handle Rate Limiting
                    if response.status_code == 429:
                        retry_after_hdr = response.headers.get("Retry-After")
                        if retry_after_hdr and retry_after_hdr.strip().isdigit():
                            wait_seconds = float(retry_after_hdr.strip())
                        else:
                            wait_seconds = min(delay + random.uniform(0.1, 0.5), self.max_delay)

                        logger.warning(
                            f"[429 Rate-Limited] {url} -> Waiting {wait_seconds:.2f}s "
                            f"(Attempt {attempt}/{self.max_retries})"
                        )
                        await asyncio.sleep(wait_seconds)
                        delay = min(delay * 2, self.max_delay)
                        continue

                    # Handle Ephemeral Server Errors
                    if response.status_code in (500, 502, 503, 504):
                        logger.warning(
                            f"[{response.status_code} Server Error] {url} "
                            f"(Attempt {attempt}/{self.max_retries})"
                        )
                        if attempt < self.max_retries:
                            await asyncio.sleep(delay + random.uniform(0.05, 0.2))
                            delay = min(delay * 2, self.max_delay)
                            continue

                    return response

                except (
                    httpx.ConnectTimeout,
                    httpx.ReadTimeout,
                    httpx.WriteTimeout,
                    httpx.ConnectError,
                    httpx.RemoteProtocolError,
                ) as exc:
                    logger.debug(
                        f"[Network Exception] {type(exc).__name__} for {url} "
                        f"(Attempt {attempt}/{self.max_retries})"
                    )
                    if attempt == self.max_retries:
                        return None
                    await asyncio.sleep(delay + random.uniform(0.05, 0.2))
                    delay = min(delay * 2, self.max_delay)

                except Exception as exc:
                    logger.error(f"[Unhandled Transport Error] {url}: {exc}")
                    return None

        return None

    async def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Optional[httpx.Response]:
        """Performs a GET request with resilience."""
        return await self.request("GET", url, params=params, headers=headers, timeout=timeout)

    async def get_json(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Optional[Any]:
        """Convenience method returning parsed JSON or None."""
        resp = await self.get(url, params=params, headers=headers, timeout=timeout)
        if resp and resp.status_code == 200:
            try:
                return resp.json()
            except Exception:
                return None
        return None

    async def get_text(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Optional[str]:
        """Convenience method returning plain-text response body or None."""
        resp = await self.get(url, params=params, headers=headers, timeout=timeout)
        if resp and resp.status_code == 200:
            return resp.text
        return None
