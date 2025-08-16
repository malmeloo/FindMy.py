"""Utility types."""

from collections.abc import Coroutine
from typing import TypeVar

_T = TypeVar("_T")

MaybeCoro = _T | Coroutine[None, None, _T]
