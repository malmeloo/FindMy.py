"""Module to simplify asynchronous HTTP calls."""
from __future__ import annotations

import json
import logging
from typing import Any, TypedDict

from aiohttp import BasicAuth, ClientSession, ClientTimeout
from typing_extensions import Unpack, override

from .closable import Closable
from .parsers import decode_plist

logging.getLogger(__name__)


class _HttpRequestOptions(TypedDict, total=False):
    json: dict[str, Any] | None
    headers: dict[str, str]
    auth: tuple[str, str] | BasicAuth
    data: bytes


class HttpResponse:
    """Response of a request made by `HttpSession`."""

    def __init__(self, status_code: int, content: bytes) -> None:
        """Initialize the response."""
        self._status_code = status_code
        self._content = content

    @property
    def status_code(self) -> int:
        """HTTP status code of the response."""
        return self._status_code

    @property
    def ok(self) -> bool:
        """Whether the status code is "OK" (2xx)."""
        return str(self._status_code).startswith("2")

    def text(self) -> str:
        """Response content as a UTF-8 encoded string."""
        return self._content.decode("utf-8")

    def json(self) -> dict[Any, Any]:
        """Response content as a dict, obtained by JSON-decoding the response content."""
        return json.loads(self.text())

    def plist(self) -> dict[Any, Any]:
        """Response content as a dict, obtained by Plist-decoding the response content."""
        data = decode_plist(self._content)
        if not isinstance(data, dict):
            msg = f"Unknown Plist-encoded data type: {data}. This is a bug, please report it."
            raise TypeError(msg)

        return data


class HttpSession(Closable):
    """Asynchronous HTTP session manager. For internal use only."""

    def __init__(self) -> None:  # noqa: D107
        super().__init__()

        self._session: ClientSession | None = None

    async def _get_session(self) -> ClientSession:
        if self._session is not None:
            return self._session

        logging.debug("Creating aiohttp session")
        self._session = ClientSession(timeout=ClientTimeout(total=5))
        return self._session

    @override
    async def close(self) -> None:
        """Close the underlying session. Should be called when session will no longer be used."""
        if self._session is not None:
            logging.debug("Closing aiohttp session")
            await self._session.close()
            self._session = None

    async def request(
        self,
        method: str,
        url: str,
        **kwargs: Unpack[_HttpRequestOptions],
    ) -> HttpResponse:
        """
        Make an HTTP request.

        Keyword arguments will directly be passed to `aiohttp.ClientSession.request`.
        """
        session = await self._get_session()

        auth = kwargs.get("auth")
        if isinstance(auth, tuple):
            kwargs["auth"] = BasicAuth(auth[0], auth[1])

        async with await session.request(
            method,
            url,
            ssl=False,
            **kwargs,
        ) as r:
            return HttpResponse(r.status, await r.content.read())

    async def get(self, url: str, **kwargs: Unpack[_HttpRequestOptions]) -> HttpResponse:
        """Alias for `HttpSession.request("GET", ...)`."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Unpack[_HttpRequestOptions]) -> HttpResponse:
        """Alias for `HttpSession.request("POST", ...)`."""
        return await self.request("POST", url, **kwargs)
