import logging
import sys

from _login import get_account_sync

from findmy import KeyPair
from findmy.reports import RemoteAnisetteProvider

# URL to (public or local) anisette server
ANISETTE_SERVER = "http://localhost:6969"

logging.basicConfig(level=logging.INFO)


def fetch_reports(priv_key: str) -> int:
    key = KeyPair.from_b64(priv_key)
    acc = get_account_sync(
        RemoteAnisetteProvider(ANISETTE_SERVER),
    )

    print(f"Logged in as: {acc.account_name} ({acc.first_name} {acc.last_name})")

    # It's that simple!
    reports = acc.fetch_last_reports(key)
    for report in sorted(reports):
        print(report)

    return 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <private key>", file=sys.stderr)
        print(file=sys.stderr)
        print("The private key should be base64-encoded.", file=sys.stderr)
        sys.exit(1)

    sys.exit(fetch_reports(sys.argv[1]))
