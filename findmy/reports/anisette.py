"""Module for Anisette header providers."""
from __future__ import annotations

import base64
import locale
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone

from findmy.util import HttpSession


def _gen_meta_headers(
    user_id: str,
    device_id: str,
    serial: str = "0",
) -> dict[str, str]:
    now = datetime.now(tz=timezone.utc)
    locale_str = locale.getdefaultlocale()[0] or "en_US"

    return {
        "X-Apple-I-Client-Time": now.replace(microsecond=0).isoformat() + "Z",
        "X-Apple-I-TimeZone": str(now.astimezone().tzinfo),
        "loc": locale_str,
        "X-Apple-Locale": locale_str,
        "X-Apple-I-MD-RINFO": "17106176",
        "X-Apple-I-MD-LU": base64.b64encode(str(user_id).upper().encode()).decode(),
        "X-Mme-Device-Id": str(device_id).upper(),
        "X-Apple-I-SRL-NO": serial,
    }


class BaseAnisetteProvider(ABC):
    """Abstract base class for Anisette providers."""

    @abstractmethod
    async def _get_base_headers(self) -> dict[str, str]:
        raise NotImplementedError

    @abstractmethod
    async def close(self) -> None:
        """Close any underlying sessions. Call when the provider will no longer be used."""
        raise NotImplementedError

    async def get_headers(
        self,
        user_id: str,
        device_id: str,
        serial: str = "0",
    ) -> dict[str, str]:
        """
        Retrieve a complete dictionary of Anisette headers.

        Consider using `BaseAppleAccount.get_anisette_headers` instead.
        """
        base_headers = await self._get_base_headers()
        base_headers.update(_gen_meta_headers(user_id, device_id, serial))

        return base_headers


class RemoteAnisetteProvider(BaseAnisetteProvider):
    """Anisette provider. Fetches headers from a remote Anisette server."""

    def __init__(self, server_url: str) -> None:
        """Initialize the provider with URL to te remote server."""
        self._server_url = server_url

        self._http = HttpSession()

        logging.info("Using remote anisette server: %s", self._server_url)

    async def _get_base_headers(self) -> dict[str, str]:
        r = await self._http.get(self._server_url)
        headers = r.json()

        return {
            "X-Apple-I-MD": headers["X-Apple-I-MD"],
            "X-Apple-I-MD-M": headers["X-Apple-I-MD-M"],
        }

    async def close(self) -> None:
        """See `AnisetteProvider.close`."""
        await self._http.close()


# TODO(malmeloo): implement using pyprovision
# https://github.com/malmeloo/FindMy.py/issues/2
class LocalAnisetteProvider(BaseAnisetteProvider):
    """Anisette provider. Generates headers without a remote server using pyprovision."""

    def __init__(self) -> None:
        """Initialize the provider."""

    async def _get_base_headers(self) -> dict[str, str]:
        return NotImplemented

    async def close(self) -> None:
        """See `AnisetteProvider.close`."""
