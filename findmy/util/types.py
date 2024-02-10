"""Utility types."""

from typing import Coroutine, TypeVar

T = TypeVar("T")

MaybeCoro = T | Coroutine[None, None, T]
