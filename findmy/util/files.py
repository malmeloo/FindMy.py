"""Utilities to simplify reading and writing data from and to files."""

from __future__ import annotations

import io
import json
import plistlib
from collections.abc import Mapping
from pathlib import Path
from typing import TypeVar, cast

_T = TypeVar("_T", bound=Mapping)


def save_and_return_json(data: _T, dst: str | Path | io.TextIOBase | None) -> _T:
    """Save and return a JSON-serializable data structure."""
    if dst is None:
        return data

    if isinstance(dst, str):
        dst = Path(dst)

    if isinstance(dst, io.IOBase):
        json.dump(data, dst, indent=4)
    elif isinstance(dst, Path):
        dst.write_text(json.dumps(data, indent=4))

    return data


def read_data_json(val: str | Path | io.TextIOBase | io.BufferedIOBase | _T) -> _T:
    """Read JSON data from a file if a path is passed, or return the argument itself."""
    if isinstance(val, str):
        val = Path(val)

    if isinstance(val, Path):
        val = cast("_T", json.loads(val.read_text()))

    if isinstance(val, io.IOBase):
        val = cast("_T", json.load(val))

    return val


def save_and_return_plist(data: _T, dst: str | Path | io.BufferedIOBase | None) -> _T:
    """Save and return a Plist file."""
    if dst is None:
        return data

    if isinstance(dst, str):
        dst = Path(dst)

    if isinstance(dst, io.IOBase):
        dst.write(plistlib.dumps(data))
    elif isinstance(dst, Path):
        dst.write_bytes(plistlib.dumps(data))

    return data


def read_data_plist(val: str | Path | io.BufferedIOBase | _T | bytes) -> _T:
    """Read Plist data from a file if a path is passed, or return the argument itself."""
    if isinstance(val, str):
        val = Path(val)

    if isinstance(val, Path):
        val = val.read_bytes()

    if isinstance(val, bytes):
        val = cast("_T", plistlib.loads(val))

    if isinstance(val, io.IOBase):
        val = cast("_T", plistlib.loads(val.read()))

    return val
