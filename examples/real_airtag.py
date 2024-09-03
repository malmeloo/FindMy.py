"""
Example showing how to fetch locations of an AirTag, or any other FindMy accessory.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from _login import get_account_sync

from findmy import FindMyAccessory
from findmy.reports import RemoteAnisetteProvider

# URL to (public or local) anisette server
ANISETTE_SERVER = "http://localhost:6969"

logging.basicConfig(level=logging.INFO)


def main(plist_path: str) -> int:
    # Step 0: create an accessory key generator
    with Path(plist_path).open("rb") as f:
        airtag = FindMyAccessory.from_plist(f)

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
    for report in sorted(reports):
        print(f" - {report}")

    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path to accessory plist>", file=sys.stderr)
        print(file=sys.stderr)
        print("The plist file should be dumped from MacOS's FindMy app.", file=sys.stderr)
        sys.exit(1)

    sys.exit(main(sys.argv[1]))
