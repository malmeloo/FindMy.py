# ruff: noqa: T201, D103, S101
"""
Example showing how to retrieve the primary key of your own AirTag, or any other FindMy-accessory.

This key can be used to retrieve the device's location for a single day.
"""
import plistlib
from datetime import datetime

from findmy import FindMyAccessory

# PUBLIC key that the accessory is broadcasting or has previously broadcast.
# For nearby devices, you can use `device_scanner.py` to find it.
PUBLIC_KEY = ""
# Path to a .plist dumped from the Find My app.
PLIST_PATH = "airtag.plist"

# == The variables below are auto-filled from the plist!! ==

with open(PLIST_PATH, "rb") as f:
    device_data = plistlib.load(f)

# PRIVATE master key. 28 (?) bytes.
MASTER_KEY = device_data["privateKey"]["key"]["data"][-28:]

# "Primary" shared secret. 32 bytes.
SKN = device_data["sharedSecret"]["key"]["data"]

# "Secondary" shared secret. 32 bytes.
SKS = device_data["secondarySharedSecret"]["key"]["data"]

# Lookahead in time slots. Each time slot is 15 minutes.
# Should be AT LEAST the time that has passed since you paired the accessory!
delta = datetime.now() - device_data["pairingDate"]
MAX_LOOKAHEAD = int(delta.total_seconds() / (15 * 60)) + 1


def main() -> None:
    airtag = FindMyAccessory(MASTER_KEY, SKN, SKS)

    for i in range(MAX_LOOKAHEAD):
        prim_key, sec_key = airtag.keys_at(i)
        if PUBLIC_KEY in (prim_key.adv_key_b64, sec_key.adv_key_b64):
            print("KEY FOUND!!")
            print(f"This key was found at index {i}."
                  f" It was likely paired approximately {i * 15} minutes ago.")
            print()
            print("KEEP THE BELOW KEY SECRET! IT CAN BE USED TO RETRIEVE THE DEVICE'S LOCATION!")
            if prim_key.adv_key_b64 == PUBLIC_KEY:
                print(f"PRIMARY key: {prim_key.private_key_b64}")
            else:
                print(f"SECONDARY key: {sec_key.private_key_b64}")
            break
    else:
        print("No match found! :(")


if __name__ == "__main__":
    main()
