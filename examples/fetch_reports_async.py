import asyncio
import logging
import sys

from _login import get_account_async

from findmy import KeyPair
from findmy.reports import RemoteAnisetteProvider

# URL to (public or local) anisette server
ANISETTE_SERVER = "http://localhost:6969"

logging.basicConfig(level=logging.INFO)


async def fetch_reports(priv_key: str) -> int:
    key = KeyPair.from_b64(priv_key)
    acc = await get_account_async(
        RemoteAnisetteProvider(ANISETTE_SERVER),
    )

    try:
        print(f"Logged in as: {acc.account_name} ({acc.first_name} {acc.last_name})")

        # It's that simple!
        reports = await acc.fetch_last_reports(key)
        for report in sorted(reports):
            print(report)
    finally:
        await acc.close()

    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <private key>", file=sys.stderr)
        print(file=sys.stderr)
        print("The private key should be base64-encoded.", file=sys.stderr)
        sys.exit(1)

    asyncio.run(fetch_reports(sys.argv[1]))
