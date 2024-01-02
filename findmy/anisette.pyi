import abc
from abc import ABC, abstractmethod

class BaseAnisetteProvider(ABC, metaclass=abc.ABCMeta):
    @abstractmethod
    async def close(self) -> None: ...
    async def get_headers(
        self,
        user_id: str,
        device_id: str,
        serial: str = "0",
    ) -> dict[str, str]: ...

class RemoteAnisetteProvider(BaseAnisetteProvider):
    def __init__(self, server_url: str) -> None: ...
    async def close(self) -> None: ...

class LocalAnisetteProvider(BaseAnisetteProvider):
    def __init__(self) -> None: ...
    async def close(self) -> None: ...
