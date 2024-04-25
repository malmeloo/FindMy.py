"""
Example showing how to fetch locations of an AirTag, or any other FindMy accessory.
"""
from __future__ import annotations

from pathlib import Path

from _login import get_account_sync

from findmy import FindMyAccessory
from findmy.reports import RemoteAnisetteProvider

# URL to (public or local) anisette server
ANISETTE_SERVER = "http://localhost:6969"

# Path to a .plist dumped from the Find My app.
PLIST_PATH = Path("airtag.plist")


def main() -> None:
    # Step 0: create an accessory key generator
    with PLIST_PATH.open("rb") as f:
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
    for report in reports:
        print(f" - {report}")


if __name__ == "__main__":
    main()
