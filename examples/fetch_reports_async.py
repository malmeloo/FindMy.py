import asyncio
import logging
import sys

from _login import get_account_async

from findmy import KeyPair

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


async def fetch_reports(priv_key: str) -> int:
    key = KeyPair.from_b64(priv_key)
    acc = await get_account_async(STORE_PATH, ANISETTE_SERVER, ANISETTE_LIBS_PATH)

    try:
        print(f"Logged in as: {acc.account_name} ({acc.first_name} {acc.last_name})")

        # It's that simple!
        reports = await acc.fetch_last_reports(key)
        for report in sorted(reports):
            print(report)
    finally:
        await acc.close()

        # Make sure to save account state when you're done!
        acc.to_json(STORE_PATH)

    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <private key>", file=sys.stderr)
        print(file=sys.stderr)
        print("The private key should be base64-encoded.", file=sys.stderr)
        sys.exit(1)

    asyncio.run(fetch_reports(sys.argv[1]))
