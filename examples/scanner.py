from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path

from findmy import (
    FindMyAccessory,
    KeyPair,
    OfflineFindingScanner,
)

logging.basicConfig(level=logging.INFO)


async def scan(check_key: KeyPair | FindMyAccessory | None = None) -> bool:
    scanner = await OfflineFindingScanner.create()

    print("Scanning for FindMy-devices...")
    print()

    scan_device = None

    async for device in scanner.scan_for(10, extend_timeout=True, print_summary=True):
        if check_key and device.is_from(check_key):
            scan_device = device

    print()
    if scan_device:
        print("Device was found in scan results! :D")
    elif check_key:
        print("Device was not found in scan results... :c")

    return scan_device is not None and check_key is not None


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--private_key", type=str)
    group.add_argument("--airtag_file", type=Path)
    args = parser.parse_args()

    dev: KeyPair | FindMyAccessory | None = None
    if args.private_key:
        dev = KeyPair.from_b64(args.private_key)
    elif args.airtag_file:
        dev = FindMyAccessory.from_json(args.airtag_file)

    device_found = asyncio.run(scan(dev))

    if device_found and isinstance(dev, FindMyAccessory):
        print("Current scan results were used to align the accessory.")
        print(f'Updated alignment will be saved to "{args.airtag_file}".')
        dev.to_json(args.airtag_file)
