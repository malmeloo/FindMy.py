"""Parsers for various forms of data formats."""

import plistlib
from typing import Any


def decode_plist(data: bytes) -> Any:  # noqa: ANN401
    """Decode a plist file."""
    plist_header = (
        b"<?xml version='1.0' encoding='UTF-8'?>"
        b"<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>"
    )

    if not data.startswith(b"<?xml"):  # append header ourselves
        data = plist_header + data

    return plistlib.loads(data)


def format_hex_byte(byte: int) -> str:
    """Format a byte as a two character hex string in uppercase."""
    return f"{byte:02x}".upper()
