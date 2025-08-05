"""Utilities to simplify reading and writing data from and to files."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import TypeVar, cast

_T = TypeVar("_T", bound=Mapping)


def save_and_return_json(data: _T, dst: str | Path | None) -> _T:
    """Save and return a JSON-serializable data structure."""
    if dst is None:
        return data

    if isinstance(dst, str):
        dst = Path(dst)

    dst.write_text(json.dumps(data, indent=4))

    return data


def read_data_json(val: str | Path | _T) -> _T:
    """Read JSON data from a file if a path is passed, or return the argument itself."""
    if isinstance(val, str):
        val = Path(val)

    if isinstance(val, Path):
        val = cast("_T", json.loads(val.read_text()))

    return val
