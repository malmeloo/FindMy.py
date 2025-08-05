"""Utility types."""

from collections.abc import Coroutine
from typing import TypeVar, Union

_T = TypeVar("_T")

# Cannot use `|` operator (PEP 604) in python 3.9,
# even with __future__ import since it is evaluated directly
MaybeCoro = Union[_T, Coroutine[None, None, _T]]
