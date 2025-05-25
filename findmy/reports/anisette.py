"""Module for Anisette header providers."""

from __future__ import annotations

import base64
import locale
import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone

from typing_extensions import override

from findmy.util.closable import Closable
from findmy.util.http import HttpSession

logger = logging.getLogger(__name__)


class BaseAnisetteProvider(Closable, ABC):
    """
    Abstract base class for Anisette providers.

    Generously derived from https://github.com/nythepegasus/grandslam/blob/main/src/grandslam/gsa.py#L41.
    """

    @property
    @abstractmethod
    def otp(self) -> str:
        """
        A seemingly random base64 string containing 28 bytes.

        TODO: Figure out how to generate this.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def machine(self) -> str:
        """
        A base64 encoded string of 60 'random' bytes.

        We're not sure how this is generated, we have to rely on the server.
        TODO: Figure out how to generate this.
        """
        raise NotImplementedError

    @property
    def timestamp(self) -> str:
        """Current timestamp in ISO 8601 format."""
        return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat() + "Z"

    @property
    def timezone(self) -> str:
        """Abbreviation of the timezone of the device."""
        return str(datetime.now().astimezone().tzinfo)

    @property
    def locale(self) -> str:
        """Locale of the device (e.g. en_US)."""
        return locale.getdefaultlocale()[0] or "en_US"

    @property
    def router(self) -> str:
        """
        A number, either 17106176 or 50660608.

        It doesn't seem to matter which one we use.
        - 17106176 is used by Sideloadly and Provision (android) based servers.
        - 50660608 is used by Windows iCloud based servers.
        """
        return "17106176"

    @property
    def client(self) -> str:
        """
        Client string.

        The format is as follows:
        <%MODEL%> <%OS%;%MAJOR%.%MINOR%(%SPMAJOR%,%SPMINOR%);%BUILD%>
         <%AUTHKIT_BUNDLE_ID%/%AUTHKIT_VERSION% (%APP_BUNDLE_ID%/%APP_VERSION%)>

        Where:
            MODEL: The model of the device (e.g. MacBookPro15,1 or 'PC'
            OS: The OS of the device (e.g. Mac OS X or Windows)
            MAJOR: The major version of the OS (e.g. 10)
            MINOR: The minor version of the OS (e.g. 15)
            SPMAJOR: The major version of the service pack (e.g. 0) (Windows only)
            SPMINOR: The minor version of the service pack (e.g. 0) (Windows only)
            BUILD: The build number of the OS (e.g. 19C57)
            AUTHKIT_BUNDLE_ID: The bundle ID of the AuthKit framework (e.g. com.apple.AuthKit)
            AUTHKIT_VERSION: The version of the AuthKit framework (e.g. 1)
            APP_BUNDLE_ID: The bundle ID of the app (e.g. com.apple.dt.Xcode)
            APP_VERSION: The version of the app (e.g. 3594.4.19)
        """
        return (
            "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> "
            "<com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>"
        )

    async def get_headers(
        self,
        user_id: str,
        device_id: str,
        serial: str = "0",
        with_client_info: bool = False,
    ) -> dict[str, str]:
        """
        Generate a complete dictionary of Anisette headers.

        Consider using `BaseAppleAccount.get_anisette_headers` instead.
        """
        headers = {
            # Current Time
            "X-Apple-I-Client-Time": self.timestamp,
            "X-Apple-I-TimeZone": self.timezone,
            # Locale
            "loc": self.locale,
            "X-Apple-Locale": self.locale,
            # 'One Time Password'
            "X-Apple-I-MD": self.otp,
            # 'Local User ID'
            "X-Apple-I-MD-LU": base64.b64encode(str(user_id).encode()).decode(),
            # 'Machine ID'
            "X-Apple-I-MD-M": self.machine,
            # 'Routing Info', some implementations convert this to an integer
            "X-Apple-I-MD-RINFO": self.router,
            # 'Device Unique Identifier'
            "X-Mme-Device-Id": str(device_id).upper(),
            # 'Device Serial Number'
            "X-Apple-I-SRL-NO": serial,
        }

        if with_client_info:
            headers["X-Mme-Client-Info"] = self.client
            headers["X-Apple-App-Info"] = "com.apple.gs.xcode.auth"
            headers["X-Xcode-Version"] = "11.2 (11B41)"

        return headers

    async def get_cpd(
        self,
        user_id: str,
        device_id: str,
        serial: str = "0",
    ) -> dict[str, str]:
        """
        Generate a complete dictionary of CPD data.

        Intended for internal use.
        """
        cpd = {
            "bootstrap": True,
            "icscrec": True,
            "pbe": False,
            "prkgen": True,
            "svct": "iCloud",
        }
        cpd.update(await self.get_headers(user_id, device_id, serial))

        return cpd


class RemoteAnisetteProvider(BaseAnisetteProvider):
    """Anisette provider. Fetches headers from a remote Anisette server."""

    _ANISETTE_DATA_VALID_FOR = 30

    def __init__(self, server_url: str) -> None:
        """Initialize the provider with URL to te remote server."""
        super().__init__()

        self._server_url = server_url

        self._http = HttpSession()

        self._anisette_data: dict[str, str] | None = None
        self._anisette_data_expires_at: float = 0

    @property
    @override
    def otp(self) -> str:
        """See `BaseAnisetteProvider.otp`_."""
        otp = (self._anisette_data or {}).get("X-Apple-I-MD")
        if otp is None:
            logger.warning("X-Apple-I-MD header not found! Returning fallback...")
        return otp or ""

    @property
    @override
    def machine(self) -> str:
        """See `BaseAnisetteProvider.machine`_."""
        machine = (self._anisette_data or {}).get("X-Apple-I-MD-M")
        if machine is None:
            logger.warning("X-Apple-I-MD-M header not found! Returning fallback...")
        return machine or ""

    @override
    async def get_headers(
        self,
        user_id: str,
        device_id: str,
        serial: str = "0",
        with_client_info: bool = False,
    ) -> dict[str, str]:
        """See `BaseAnisetteProvider.get_headers`_."""
        if self._anisette_data is None or time.time() >= self._anisette_data_expires_at:
            logger.info("Fetching anisette data from %s", self._server_url)

            r = await self._http.get(self._server_url, auto_retry=True)
            self._anisette_data = r.json()
            self._anisette_data_expires_at = time.time() + self._ANISETTE_DATA_VALID_FOR

        return await super().get_headers(user_id, device_id, serial, with_client_info)

    @override
    async def close(self) -> None:
        """See `AnisetteProvider.close`."""
        await self._http.close()


# TODO(malmeloo): implement using pyprovision
# https://github.com/malmeloo/FindMy.py/issues/2
class LocalAnisetteProvider(BaseAnisetteProvider):
    """Anisette provider. Generates headers without a remote server using pyprovision."""

    @property
    @override
    def otp(self) -> str:
        """See `BaseAnisetteProvider.otp`_."""
        raise NotImplementedError

    @property
    @override
    def machine(self) -> str:
        """See `BaseAnisetteProvider.machine`_."""
        raise NotImplementedError

    @override
    async def close(self) -> None:
        """See `BaseAnisetteProvider.close`_."""
