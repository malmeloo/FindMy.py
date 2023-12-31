import logging
from typing import Optional
import asyncio

from aiohttp import ClientSession, BasicAuth, ClientTimeout

logging.getLogger(__name__)


class HttpSession:
    def __init__(self):
        self._session: Optional[ClientSession] = None

    async def _ensure_session(self):
        if self._session is None:
            logging.debug("Creating aiohttp session")
            self._session = ClientSession(timeout=ClientTimeout(total=5))

    async def close(self):
        if self._session is not None:
            logging.debug("Closing aiohttp session")
            await self._session.close()
            self._session = None

    def __del__(self) -> None:
        try:
            loop = asyncio.get_running_loop()
            loop.call_soon_threadsafe(loop.create_task, self.close())
        except RuntimeError:  # cannot await closure
            pass

    async def request(self, method: str, url: str, auth: tuple[str] = None, **kwargs):
        await self._ensure_session()

        basic_auth = None
        if auth is not None:
            basic_auth = BasicAuth(auth[0], auth[1])

        return self._session.request(method, url, auth=basic_auth, ssl=False, **kwargs)

    async def get(self, url: str, **kwargs):
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs):
        return await self.request("POST", url, **kwargs)
