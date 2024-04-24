import asyncio
import logging

from _login import get_account_async

from findmy import KeyPair
from findmy.reports import RemoteAnisetteProvider

# URL to (public or local) anisette server
ANISETTE_SERVER = "http://localhost:6969"

# Private base64-encoded key to look up
KEY_PRIV = ""

# Optional, to verify that advertisement key derivation works for your key
KEY_ADV = ""

logging.basicConfig(level=logging.DEBUG)


async def fetch_reports(lookup_key: KeyPair) -> None:
    anisette = RemoteAnisetteProvider(ANISETTE_SERVER)

    acc = await get_account_async(anisette)

    try:
        print(f"Logged in as: {acc.account_name} ({acc.first_name} {acc.last_name})")

        # It's that simple!
        reports = await acc.fetch_last_reports([lookup_key])
        print(reports)

    finally:
        await acc.close()


if __name__ == "__main__":
    key = KeyPair.from_b64(KEY_PRIV)
    if KEY_ADV:  # verify that your adv key is correct :D
        assert key.adv_key_b64 == KEY_ADV

    asyncio.run(fetch_reports(key))
