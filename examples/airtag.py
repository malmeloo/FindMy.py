"""
Example showing how to fetch locations of an AirTag, or any other FindMy accessory.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from _login import get_account_sync

from findmy import FindMyAccessory
from findmy.accessory import RollingKeyPairSource
from findmy.keys import HasHashedPublicKey

# Default path where login session will be stored.
# This is necessary to avoid generating a new session every time we log in.
DEFAULT_STORE_PATH = "account.json"

# URL to LOCAL anisette server. Set to None to use built-in Anisette generator instead (recommended)
# IF YOU USE A PUBLIC SERVER, DO NOT COMPLAIN THAT YOU KEEP RUNNING INTO AUTHENTICATION ERRORS!
# If you change this value, make sure to remove the account store file.
ANISETTE_SERVER = None

# Path where Anisette libraries will be stored.
# This is only relevant when using the built-in Anisette server.
# It can be omitted (set to None) to avoid saving to disk,
# but specifying a path is highly recommended to avoid downloading the bundle on every run.
ANISETTE_LIBS_PATH = "ani_libs.bin"

logging.basicConfig(level=logging.INFO)

BATTERY_LEVEL = {0b00: "Full", 0b01: "Medium", 0b10: "Low", 0b11: "Very Low"}


def get_battery_level(status: int) -> str:
    """Extract battery level from status byte."""
    battery_id = (status >> 6) & 0b11
    return BATTERY_LEVEL.get(battery_id, "Unknown")


def get_airtag_name(airtag: HasHashedPublicKey | RollingKeyPairSource, path: Path) -> str:
    """Get a human-readable name for an airtag, with fallbacks."""
    if isinstance(airtag, FindMyAccessory):
        if airtag.name:
            return airtag.name
        if airtag.identifier:
            return airtag.identifier
    return path.stem  # filename without extension


def main(airtag_paths: list[Path], store_path: str) -> int:
    # Step 0: create accessory key generators for all paths
    airtags = [FindMyAccessory.from_json(path) for path in airtag_paths]
    airtag_to_path: dict[HasHashedPublicKey | RollingKeyPairSource, Path] = dict(zip(airtags, airtag_paths))

    # Step 1: log into an Apple account
    acc = get_account_sync(store_path, ANISETTE_SERVER, ANISETTE_LIBS_PATH)
    print(f"Logged in as: {acc.account_name} ({acc.first_name} {acc.last_name})")

    # step 2: fetch reports!
    locations = acc.fetch_location(airtags)

    # step 3: print 'em
    print("Last known locations:")
    for airtag, path in airtag_to_path.items():
        location = locations.get(airtag)  # type: ignore[union-attr]
        name = get_airtag_name(airtag, path)
        if location:
            battery = get_battery_level(location.status)
            print(f" - {name}: {location} (Battery: {battery})")
        else:
            print(f" - {name}: No location found")

    # step 4: save current account state to disk
    acc.to_json(store_path)
    for airtag, path in zip(airtags, airtag_paths):
        airtag.to_json(path)

    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("airtag_paths", type=Path, nargs='+')
    parser.add_argument("--store-path", type=str, default=DEFAULT_STORE_PATH,
                        help=f"Path to account session file (default: {DEFAULT_STORE_PATH})")
    args = parser.parse_args()

    sys.exit(main(args.airtag_paths, args.store_path))
