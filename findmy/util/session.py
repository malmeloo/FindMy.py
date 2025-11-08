"""Logic related to serializable classes."""

from __future__ import annotations

import random
from typing import TYPE_CHECKING, Any, Generic, TypeVar

from typing_extensions import Self

from .abc import Closable, Serializable

if TYPE_CHECKING:
    from pathlib import Path
    from types import TracebackType

_S = TypeVar("_S", bound=Serializable)
_SC = TypeVar("_SC", bound=Serializable | Closable)


class _BaseSessionManager(Generic[_SC]):
    """Base class for session managers."""

    def __init__(self) -> None:
        self._sessions: dict[_SC, str | Path | None] = {}

    def _add(self, obj: _SC, path: str | Path | None) -> None:
        self._sessions[obj] = path

    def remove(self, obj: _SC) -> None:
        self._sessions.pop(obj, None)

    def save(self) -> None:
        for obj, path in self._sessions.items():
            if isinstance(obj, Serializable):
                obj.to_json(path)

    async def close(self) -> None:
        for obj in self._sessions:
            if isinstance(obj, Closable):
                await obj.close()

    async def save_and_close(self) -> None:
        for obj, path in self._sessions.items():
            if isinstance(obj, Serializable):
                obj.to_json(path)
            if isinstance(obj, Closable):
                await obj.close()

    def get_random(self) -> _SC:
        if not self._sessions:
            msg = "No objects in the session manager."
            raise ValueError(msg)
        return random.choice(list(self._sessions.keys()))  # noqa: S311

    def __len__(self) -> int:
        return len(self._sessions)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_val: BaseException | None,
        _exc_tb: TracebackType | None,
    ) -> None:
        self.save()


class MixedSessionManager(_BaseSessionManager[Serializable | Closable]):
    """Allows any Serializable or Closable object."""

    def new(
        self,
        c_type: type[_SC],
        path: str | Path | None = None,
        /,
        *args: Any,  # noqa: ANN401
        **kwargs: Any,  # noqa: ANN401
    ) -> _SC:
        """Add an object to the manager by instantiating it using its constructor."""
        obj = c_type(*args, **kwargs)
        if isinstance(obj, Serializable) and path is not None:
            obj.to_json(path)
        self._add(obj, path)
        return obj

    def add_from_json(
        self,
        c_type: type[_S],
        path: str | Path,
        /,
        **kwargs: Any,  # noqa: ANN401
    ) -> _S:
        """Add an object to the manager by deserializing it from its JSON representation."""
        obj = c_type.from_json(path, **kwargs)
        self._add(obj, path)
        return obj

    def add(self, obj: Serializable | Closable, path: str | Path | None = None, /) -> None:
        """Add an object to the session manager."""
        self._add(obj, path)


class UniformSessionManager(_BaseSessionManager[_SC], Generic[_SC]):
    """Only allows a single type of Serializable object."""

    def __init__(self, obj_type: type[_SC]) -> None:
        """Create a new session manager."""
        super().__init__()
        self._obj_type = obj_type

    def new(
        self,
        path: str | Path | None = None,
        /,
        *args: Any,  # noqa: ANN401
        **kwargs: Any,  # noqa: ANN401
    ) -> _SC:
        """Add an object to the manager by instantiating it using its constructor."""
        obj = self._obj_type(*args, **kwargs)
        if isinstance(obj, Serializable) and path is not None:
            obj.to_json(path)
        self._add(obj, path)
        return obj

    def add_from_json(
        self,
        path: str | Path,
        /,
        **kwargs: Any,  # noqa: ANN401
    ) -> _SC:
        """Add an object to the manager by deserializing it from its JSON representation."""
        if not issubclass(self._obj_type, Serializable):
            msg = "Can only add objects of type Serializable."
            raise TypeError(msg)
        obj = self._obj_type.from_json(path, **kwargs)
        self._add(obj, path)
        return obj

    def add(self, obj: _SC, path: str | Path | None = None, /) -> None:
        """Add an object to the session manager."""
        if not isinstance(obj, self._obj_type):
            msg = f"Object must be of type {self._obj_type.__name__}"
            raise TypeError(msg)
        self._add(obj, path)
