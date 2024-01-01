import json
import logging
import os

from findmy import (
    AppleAccount,
    LoginState,
    RemoteAnisetteProvider,
    SmsSecondFactor,
    keys,
)

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


def login(account: AppleAccount):
    state = account.login(ACCOUNT_EMAIL, ACCOUNT_PASS)

    if state == LoginState.REQUIRE_2FA:  # Account requires 2FA
        # This only supports SMS methods for now
        methods = account.get_2fa_methods()

        # Print the (masked) phone numbers
        for method in methods:
            if isinstance(method, SmsSecondFactor):
                print(method.phone_number)

        # Just take the first one to keep things simple
        method = methods[0]
        method.request()
        code = input("Code: ")

        # This automatically finishes the post-2FA login flow
        method.submit(code)

    return account


def fetch_reports(lookup_key):
    anisette = RemoteAnisetteProvider(ANISETTE_SERVER)
    acc = AppleAccount(anisette)

    # Save / restore account logic
    if os.path.isfile("account.json"):
        with open("account.json") as f:
            acc.restore(json.load(f))
    else:
        login(acc)
        with open("account.json", "w+") as f:
            json.dump(acc.export(), f)

    print(f"Logged in as: {acc.account_name} ({acc.first_name} {acc.last_name})")

    # It's that simple!
    reports = acc.fetch_last_reports([lookup_key])
    print(reports)


if __name__ == "__main__":
    key = keys.KeyPair.from_b64(KEY_PRIV)
    if KEY_ADV:  # verify that your adv key is correct :D
        assert key.adv_key_b64 == KEY_ADV

    fetch_reports(key)
