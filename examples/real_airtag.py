"""
Example showing how to fetch locations of an AirTag, or any other FindMy accessory.
"""
from __future__ import annotations

import plistlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from _login import get_account_sync

from findmy import FindMyAccessory, KeyPair
from findmy.reports import RemoteAnisetteProvider

# URL to (public or local) anisette server
ANISETTE_SERVER = "http://localhost:6969"

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

# "Paired at" timestamp (UTC)
PAIRED_AT = device_data["pairingDate"].replace(tzinfo=timezone.utc)


def _gen_keys(airtag: FindMyAccessory, _from: datetime, to: datetime) -> set[KeyPair]:
    keys = set()
    while _from < to:
        keys.update(airtag.keys_at(_from))

        _from += timedelta(minutes=15)

    return keys


def main() -> None:
    # Step 0: create an accessory key generator
    airtag = FindMyAccessory(MASTER_KEY, SKN, SKS, PAIRED_AT)

    # Step 1: log into an Apple account
    print("Logging into account")
    anisette = RemoteAnisetteProvider(ANISETTE_SERVER)
    acc = get_account_sync(anisette)

    # step 2: fetch reports!
    print("Fetching reports")
    reports = acc.fetch_last_reports(airtag)

    # step 3: print 'em
    print()
    print("Location reports:")
    for report in reports:
        print(f" - {report}")


if __name__ == "__main__":
    main()
