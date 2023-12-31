import asyncio
import json
import logging
import os

from findmy import (
    AsyncAppleAccount,
    LoginState,
    SmsSecondFactor,
    RemoteAnisetteProvider,
)
from findmy import keys

# URL to (public or local) anisette server
ANISETTE_SERVER = "http://localhost:6969"

# Apple account details
ACCOUNT_EMAIL = "test@test.com"
ACCOUNT_PASS = "1234"

# Private base64-encoded key to look up
KEY_PRIV = ""

# Optional, to verify that advertisement key derivation works for your key
KEY_ADV = ""

logging.basicConfig(level=logging.DEBUG)


async def login(account: AsyncAppleAccount):
    state = await account.login(ACCOUNT_EMAIL, ACCOUNT_PASS)

    if state == LoginState.REQUIRE_2FA:  # Account requires 2FA
        # This only supports SMS methods for now
        methods = await account.get_2fa_methods()

        # Print the (masked) phone numbers
        for method in methods:
            if isinstance(method, SmsSecondFactor):
                print(method.phone_number)

        # Just take the first one to keep things simple
        method = methods[0]
        await method.request()
        code = input("Code: ")

        # This automatically finishes the post-2FA login flow
        await method.submit(code)

    return account


async def fetch_reports(lookup_key):
    anisette = RemoteAnisetteProvider(ANISETTE_SERVER)
    acc = AsyncAppleAccount(anisette)

    try:
        # Save / restore account logic
        if os.path.isfile("account.json"):
            with open("account.json", "r") as f:
                acc.restore(json.load(f))
        else:
            await login(acc)
            with open("account.json", "w+") as f:
                json.dump(acc.export(), f)

        print(f"Logged in as: {acc.account_name} ({acc.first_name} {acc.last_name})")

        # It's that simple!
        reports = await acc.fetch_last_reports([lookup_key])
        print(reports)

    finally:
        await acc.close()


if __name__ == "__main__":
    key = keys.KeyPair.from_b64(KEY_PRIV)
    if KEY_ADV:  # verify that your adv key is correct :D
        assert key.adv_key_b64 == KEY_ADV

    asyncio.run(fetch_reports(key))
