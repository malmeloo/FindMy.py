import base64
import locale
import logging
from abc import ABC, abstractmethod
from datetime import datetime

from .http import HttpSession


def _gen_meta_headers(user_id: str, device_id: str, serial: str = '0'):
    now = datetime.utcnow()
    locale_str = locale.getdefaultlocale()[0] or "en_US"

    return {
        "X-Apple-I-Client-Time": now.replace(microsecond=0).isoformat() + "Z",
        "X-Apple-I-TimeZone": str(now.astimezone().tzinfo),
        "loc": locale_str,
        "X-Apple-Locale": locale_str,

        "X-Apple-I-MD-RINFO": "17106176",
        "X-Apple-I-MD-LU": base64.b64encode(str(user_id).upper().encode()).decode(),
        "X-Mme-Device-Id": str(device_id).upper(),
        "X-Apple-I-SRL-NO": serial
    }


class AnisetteProvider(ABC):
    @abstractmethod
    async def _get_base_headers(self) -> dict[str, str]:
        return NotImplemented

    @abstractmethod
    async def close(self):
        return NotImplemented

    async def get_headers(self, user_id: str, device_id: str, serial: str = '0') -> dict[str, str]:
        base_headers = await self._get_base_headers()
        base_headers.update(_gen_meta_headers(user_id, device_id, serial))

        return base_headers


class RemoteAnisetteProvider(AnisetteProvider):
    def __init__(self, server_url: str):
        self._server_url = server_url

        self._http = HttpSession()

        logging.info(f"Using remote anisette server: {self._server_url}")

    async def _get_base_headers(self) -> dict[str, str]:
        async with await self._http.get(self._server_url) as r:
            headers = await r.json()

        return {"X-Apple-I-MD": headers["X-Apple-I-MD"], "X-Apple-I-MD-M": headers["X-Apple-I-MD-M"]}

    async def close(self):
        await self._http.close()


# TODO: implement using pyprovision
class LocalAnisetteProvider(AnisetteProvider):
    def __init__(self):
        pass

    async def _get_base_headers(self) -> dict[str, str]:
        return NotImplemented

    async def close(self):
        pass
