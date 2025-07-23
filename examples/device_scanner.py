from __future__ import annotations

import asyncio
import logging
import sys

from findmy import KeyPair
from findmy.scanner import (
    NearbyOfflineFindingDevice,
    OfflineFindingScanner,
    SeparatedOfflineFindingDevice,
)

logging.basicConfig(level=logging.INFO)


def _print_nearby(device: NearbyOfflineFindingDevice) -> None:
    print(f"NEARBY Device - {device.mac_address}")
    print(f"  Status byte:  {device.status:x}")
    print("  Extra data:")
    for k, v in sorted(device.additional_data.items()):
        print(f"    {k:20}: {v}")
    print()


def _print_separated(device: SeparatedOfflineFindingDevice) -> None:
    print(f"SEPARATED Device - {device.mac_address}")
    print(f"  Public key:   {device.adv_key_b64}")
    print(f"  Lookup key:   {device.hashed_adv_key_b64}")
    print(f"  Status byte:  {device.status:x}")
    print(f"  Hint byte:    {device.hint:x}")
    print("  Extra data:")
    for k, v in sorted(device.additional_data.items()):
        print(f"    {k:20}: {v}")
    print()


async def scan(check_key: KeyPair | None = None) -> None:
    scanner = await OfflineFindingScanner.create()

    print("Scanning for FindMy-devices...")
    print()

    scan_device = None

    async for device in scanner.scan_for(10, extend_timeout=True):
        if isinstance(device, NearbyOfflineFindingDevice):
            _print_nearby(device)
        elif isinstance(device, SeparatedOfflineFindingDevice):
            _print_separated(device)
        else:
            print(f"Unknown device: {device}")
            print()
            continue

        if check_key and device.is_from(check_key):
            scan_device = device

    if scan_device:
        print("Key or accessory was found in scan results! :D")
    elif check_key:
        print("Selected key or accessory was not found in scan results... :c")


if __name__ == "__main__":
    key = None
    if len(sys.argv) >= 2:
        key = KeyPair.from_b64(sys.argv[1])

    asyncio.run(scan(key))
