import asyncio
import logging

from findmy.scanner import OfflineFindingScanner

logging.basicConfig(level=logging.INFO)


async def scan():
    scanner = await OfflineFindingScanner.create()

    print("Scanning for FindMy-devices...")
    print()

    async for device in scanner.scan_for(10, extend_timeout=True):
        print(f"Device - {device.mac_address}")
        print(f"  Public key:   {device.adv_key_b64}")
        print(f"  Lookup key:   {device.hashed_adv_key_b64}")
        print(f"  Status byte:  {device.status:x}")
        print(f"  Hint byte:    {device.hint:x}")
        print(f"  Extra data:")
        for k, v in sorted(device.additional_data.items()):
            print(f"    {k:20}: {v}")
        print()


if __name__ == "__main__":
    asyncio.run(scan())
