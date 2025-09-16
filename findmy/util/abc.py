"""Various utility ABCs for internal and external classes."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import TYPE_CHECKING, Generic, TypeVar

from typing_extensions import Self

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


class Closable(ABC):
    """ABC for async classes that need to be cleaned up before exiting."""

    def __init__(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        """
        Initialize the :class:`Closable`.

        If an event loop is given, the :class:`Closable` will attempt to close itself
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


_T = TypeVar("_T", bound=Mapping)


class Serializable(ABC, Generic[_T]):
    """ABC for serializable classes."""

    @abstractmethod
    def to_json(self, dst: str | Path | None = None, /) -> _T:
        """
        Export the current state of the object as a JSON-serializable dictionary.

        If an argument is provided, the output will also be written to that file.

        The output of this method is guaranteed to be JSON-serializable, and passing
        the return value of this function as an argument to :meth:`Serializable.from_json`
        will always result in an exact copy of the internal state as it was when exported.

        You are encouraged to save and load object states to and from disk whenever possible,
        to prevent unnecessary API calls or otherwise unexpected behavior.
        """
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def from_json(cls, val: str | Path | _T, /) -> Self:
        """
        Restore state from a previous :meth:`Closable.to_json` export.

        If given a str or Path, it must point to a json file from :meth:`Serializable.to_json`.
        Otherwise, it should be the Mapping itself.

        See :meth:`Serializable.to_json` for more information.
        """
        raise NotImplementedError
