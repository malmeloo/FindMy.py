"""Module to simplify asynchronous HTTP calls. For internal use only."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from aiohttp import BasicAuth, ClientResponse, ClientSession, ClientTimeout

logging.getLogger(__name__)


class HttpResponse:
    """Response of a request made by `HttpSession`."""

    def __init__(self, resp: ClientResponse) -> None:
        """Initialize the response."""
        self._resp: ClientResponse = resp


class HttpSession:
    """Asynchronous HTTP session manager. For internal use only."""

    def __init__(self) -> None:  # noqa: D107
        self._session: ClientSession | None = None

    async def _ensure_session(self) -> None:
        if self._session is None:
            logging.debug("Creating aiohttp session")
            self._session = ClientSession(timeout=ClientTimeout(total=5))

    async def close(self) -> None:
        """Close the underlying session. Should be called when session will no longer be used."""
        if self._session is not None:
            logging.debug("Closing aiohttp session")
            await self._session.close()
            self._session = None

    def __del__(self) -> None:
        """Attempt to gracefully close the session.

        Ideally this should be done by manually calling close().
        """
        if self._session is None:
            return

        try:
            loop = asyncio.get_running_loop()
            loop.call_soon_threadsafe(loop.create_task, self.close())
        except RuntimeError:  # cannot await closure
            pass

    async def request(
        self,
        method: str,
        url: str,
        auth: tuple[str] | None = None,
        **kwargs: Any,
    ) -> ClientResponse:
        """Make an HTTP request.

        Keyword arguments will directly be passed to `aiohttp.ClientSession.request`.
        """
        await self._ensure_session()

        basic_auth = None
        if auth is not None:
            basic_auth = BasicAuth(auth[0], auth[1])

        return await self._session.request(method, url, auth=basic_auth, ssl=False, **kwargs)

    async def get(self, url: str, **kwargs: Any) -> ClientResponse:
        """Alias for `HttpSession.request("GET", ...)`."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> ClientResponse:
        """Alias for `HttpSession.request("POST", ...)`."""
        return await self.request("POST", url, **kwargs)
