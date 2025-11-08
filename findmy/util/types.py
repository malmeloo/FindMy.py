"""Utility types."""

from collections.abc import Coroutine
from typing import TypeAlias, TypeVar

_T = TypeVar("_T")

MaybeCoro: TypeAlias = _T | Coroutine[None, None, _T]
