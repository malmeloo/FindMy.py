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

    # Step 1: Generate the accessory's private keys,
    # starting from 7 days ago until now (12 hour margin)
    fetch_to = datetime.now(tz=timezone.utc).astimezone() + timedelta(hours=12)
    fetch_from = fetch_to - timedelta(days=8)

    print(f"Generating keys from {fetch_from} to {fetch_to} ...")
    lookup_keys = _gen_keys(airtag, fetch_from, fetch_to)

    print(f"Generated {len(lookup_keys)} keys")

    # Step 2: log into an Apple account
    print("Logging into account")
    anisette = RemoteAnisetteProvider(ANISETTE_SERVER)
    acc = get_account_sync(anisette)

    # step 3: fetch reports!
    print("Fetching reports")
    reports = acc.fetch_reports(list(lookup_keys), fetch_from, fetch_to)

    # step 4: print 'em
    # reports are in {key: [report]} format, but we only really care about the reports
    print()
    print("Location reports:")
    reports = sorted([r for rs in reports.values() for r in rs])
    for report in reports:
        print(f" - {report}")


if __name__ == "__main__":
    main()
