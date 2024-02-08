"""
Example showing how to retrieve the primary key of your own AirTag, or any other FindMy-accessory.

This key can be used to retrieve the device's location for a single day.
"""
import plistlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from findmy import FindMyAccessory

# PUBLIC key that the accessory is broadcasting or has previously broadcast.
# For nearby devices, you can use `device_scanner.py` to find it.
PUBLIC_KEY = ""
# Path to a .plist dumped from the Find My app.
PLIST_PATH = Path("airtag.plist")

# == The variables below are auto-filled from the plist!! ==

with PLIST_PATH.open("rb") as f:
    device_data = plistlib.load(f)

# PRIVATE master key. 28 (?) bytes.
MASTER_KEY = device_data["privateKey"]["key"]["data"][-28:]

# "Primary" shared secret. 32 bytes.
SKN = device_data["sharedSecret"]["key"]["data"]

# "Secondary" shared secret. 32 bytes.
SKS = device_data["secondarySharedSecret"]["key"]["data"]


def main() -> None:
    paired_at = device_data["pairingDate"].replace(tzinfo=timezone.utc)
    airtag = FindMyAccessory(MASTER_KEY, SKN, SKS, paired_at)

    now = datetime.now(tz=timezone.utc)
    lookup_time = paired_at.replace(
        minute=paired_at.minute // 15 * 15,
        second=0,
        microsecond=0,
    ) + timedelta(minutes=15)

    while lookup_time < now:
        keys = airtag.keys_at(lookup_time)
        for key in keys:
            if key.adv_key_b64 != PUBLIC_KEY:
                continue

            print("KEY FOUND!!")
            print("KEEP THE BELOW KEY SECRET! IT CAN BE USED TO RETRIEVE THE DEVICE'S LOCATION!")
            print(f"  - Key:           {key.private_key_b64}")
            print(f"  - Approx. Time:  {lookup_time}")
            print(f"  - Type:          {key.key_type}")
            return

        lookup_time += timedelta(minutes=15)

    print("No match found! :(")


if __name__ == "__main__":
    main()
