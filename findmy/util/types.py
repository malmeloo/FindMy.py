"""Utility types."""

from collections.abc import Coroutine
from typing import TypeVar, Union

T = TypeVar("T")

# Cannot use `|` operator (PEP 604) in python 3.9,
# even with __future__ import since it is evaluated directly
MaybeCoro = Union[T, Coroutine[None, None, T]]
