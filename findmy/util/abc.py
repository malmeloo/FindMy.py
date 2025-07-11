"""Various utility ABCs for internal and external classes."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod

logging.getLogger(__name__)


class Closable(ABC):
    """ABC for async classes that need to be cleaned up before exiting."""

    def __init__(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        """
        Initialize the ``Closable``.

        If an event loop is given, the ``Closable`` will attempt to close itself
        using the loop when it is garbage collected.
        """
        self._loop: asyncio.AbstractEventLoop | None = loop

    @abstractmethod
    async def close(self) -> None:
        """Clean up."""
        raise NotImplementedError

    def __del__(self) -> None:
        """Attempt to automatically clean up when garbage collected."""
        try:
            loop = self._loop or asyncio.get_running_loop()
            if loop.is_running():
                loop.call_soon_threadsafe(loop.create_task, self.close())
            else:
                loop.run_until_complete(self.close())
        except RuntimeError:
            pass


class Serializable(ABC):
    """ABC for serializable classes."""

    @abstractmethod
    def serialize(self) -> dict:
        """Serialize the object to a JSON-serializable dictionary."""
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def deserialize(cls, data: dict) -> Serializable:
        """Deserialize the object from a JSON-serializable dictionary."""
        raise NotImplementedError
