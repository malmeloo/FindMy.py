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
from findmy.reports import RemoteAnisetteProvider

# URL to (public or local) anisette server
ANISETTE_SERVER = "http://localhost:6969"

logging.basicConfig(level=logging.INFO)


def main(plist_path: Path, alignment_plist_path: Path | None) -> int:
    # Step 0: create an accessory key generator
    with plist_path.open("rb") as f:
        f2 = alignment_plist_path.open("rb") if alignment_plist_path else None

        airtag = FindMyAccessory.from_plist(f, f2)

        if f2:
            f2.close()

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
    parser = argparse.ArgumentParser()
    parser.add_argument("plist_path", type=Path)
    parser.add_argument("--alignment_plist_path", default=None, type=Path)
    args = parser.parse_args()

    sys.exit(main(args.plist_path, args.alignment_plist_path))
