import asyncio
import json
import logging
from pathlib import Path

from findmy import KeyPair
from findmy.reports import (
    AsyncAppleAccount,
    LoginState,
    RemoteAnisetteProvider,
    SmsSecondFactorMethod,
)

# URL to (public or local) anisette server
ANISETTE_SERVER = "http://localhost:6969"

# Apple account details
ACCOUNT_EMAIL = "test@test.com"
ACCOUNT_PASS = ""

# Private base64-encoded key to look up
KEY_PRIV = ""

# Optional, to verify that advertisement key derivation works for your key
KEY_ADV = ""

logging.basicConfig(level=logging.DEBUG)


async def login(account: AsyncAppleAccount) -> None:
    state = await account.login(ACCOUNT_EMAIL, ACCOUNT_PASS)

    if state == LoginState.REQUIRE_2FA:  # Account requires 2FA
        # This only supports SMS methods for now
        methods = await account.get_2fa_methods()

        # Print the (masked) phone numbers
        for method in methods:
            if isinstance(method, SmsSecondFactorMethod):
                print(method.phone_number)

        # Just take the first one to keep things simple
        method = methods[0]
        await method.request()
        code = input("Code: ")

        # This automatically finishes the post-2FA login flow
        await method.submit(code)


async def fetch_reports(lookup_key: KeyPair) -> None:
    anisette = RemoteAnisetteProvider(ANISETTE_SERVER)
    acc = AsyncAppleAccount(anisette)

    try:
        acc_store = Path("account.json")
        try:
            with acc_store.open() as f:
                acc.restore(json.load(f))
        except FileNotFoundError:
            await login(acc)
            with acc_store.open("w+") as f:
                json.dump(acc.export(), f)

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
