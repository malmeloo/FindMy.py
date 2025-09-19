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

# Path where login session will be stored.
# This is necessary to avoid generating a new session every time we log in.
STORE_PATH = "account.json"

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


def main(airtag_path: Path) -> int:
    # Step 0: create an accessory key generator
    airtag = FindMyAccessory.from_json(airtag_path)

    # Step 1: log into an Apple account
    acc = get_account_sync(STORE_PATH, ANISETTE_SERVER, ANISETTE_LIBS_PATH)
    print(f"Logged in as: {acc.account_name} ({acc.first_name} {acc.last_name})")

    # step 2: fetch reports!
    location = acc.fetch_location(airtag)

    # step 3: print 'em
    print("Last known location:")
    print(f" - {location}")

    # step 4: save current account state to disk
    acc.to_json(STORE_PATH)
    airtag.to_json(airtag_path)

    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("airtag_path", type=Path)
    args = parser.parse_args()

    sys.exit(main(args.airtag_path))
