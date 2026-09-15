# Apple hardware-security-key login

Related: [FindMy.py #159](https://github.com/malmeloo/FindMy.py/issues/159) and
[OpenTagViewer #18](https://github.com/parawanderer/OpenTagViewer/issues/18).

FindMy.py now exposes Apple's **HSA2 FIDO2/WebAuthn hardware-key second factor**
through its normal account and second-factor model:

- `AsyncAppleAccount.get_2fa_methods()` may return
  `AsyncSecurityKeySecondFactor`;
- `AppleAccount.get_2fa_methods()` may return `SyncSecurityKeySecondFactor`;
- `SecurityKeyChallenge` and `SecurityKeyAssertion` are dependency-free values;
- a security-key factor uses `authenticate(signer)`, rather than forcing an
  assertion through the code-oriented `submit(code)` method.

Apple challenge parsing, assertion validation/encoding, continuation headers and
post-key GrandSlam/MobileMe state transitions live in the library. The files in
this directory are only an optional Linux USB adapter and a private example CLI.
Ordinary FindMy.py users do not need `python-fido2`.

## Evidence and limitations

The original adapter was exercised with **one real Apple account protected by a
Yubico USB Security Key on Linux**. The key endpoint accepted the assertion, the
subsequent GrandSlam exchange authenticated, MobileMe issued a FindMy session,
and the session was saved without a password. A separate private integration
subsequently reused that session and fetched an owned accessory's location. No
private integration or account data is part of this contribution.

The native extraction is tested offline against current upstream source. It does
not claim an additional real-account trial, universal key compatibility or
Apple support. It implements HSA2 hardware keys after password/SRP only. Legacy
FSA1/U2F and primary passkey/passwordless flows are out of scope.

## Native API shape

For the synchronous API:

```python
from findmy import SyncSecurityKeySecondFactor

methods = account.get_2fa_methods()
method = next(item for item in methods if isinstance(item, SyncSecurityKeySecondFactor))
state = method.authenticate(signer)
```

The signer receives `SecurityKeyChallenge` and returns `SecurityKeyAssertion`.
The async factor follows the same model but awaits an async signer callback. A
method object is single-use after authentication starts. `request()` refreshes
its challenge before use; `submit(code)` intentionally rejects security keys.

## Optional Linux USB example

Use a Linux machine with the USB key physically connected and appropriate user
access to its FIDO HID interface. An ordinary SSH connection does not forward
USB. Do not run as root to work around permissions, record the terminal, put
credentials in arguments/environment variables, or paste session files into
issues. Never guess or repeatedly retry a security-key PIN.

From a checkout of this branch:

```sh
uv sync --group dev
uv run python examples/security_key/login.py --help
# Anonymous verified-TLS probe: USB enumeration and GET /auth only.
uv run python examples/security_key/login.py --preflight
# One explicit login attempt:
uv run python examples/security_key/login.py --login
```

The CLI uses the normal `AsyncAppleAccount`, selects its native
`AsyncSecurityKeySecondFactor`, and supplies an async wrapper around the optional
`python-fido2` USB signer. PIN entry and touch share the authenticator's
90-second timeout. The challenge expires after 120 seconds.

Every attempt gets a new user-owned `data/login-*` directory. A successful
`session.json` has mode 0600 under a 0700 directory. Previous attempts are not
read or overwritten. The password is removed from the saved SDK serialization;
the file still contains sensitive session credentials and identity metadata.
Private files are ignored by Git. The example does not export accessory keys or
query locations.

## Protocol and safety boundaries

- The library uses its verified-TLS Apple trust context, rejects redirects for
  second-factor requests, bounds responses and does not enable automatic retry.
- The parser accepts explicit `fsa2_hsa2` and the observed direct
  `fsaVerification.fsaChallenge` layout, while rejecting unknown extensions,
  referrer redirects, duplicate fields and oversized input.
- RP/origin, challenge, selected credential, RP-ID hash, user-presence flag,
  extension output and challenge age are validated before submission.
- Apple's HSA2-specific base64 conventions are retained; the similar primary
  FSA2 endpoint and payload are not substituted.
- Security-key endpoint acceptance is not login success. The library requires
  post-key GrandSlam `AUTHENTICATED` and MobileMe `LOGGED_IN` transitions.
- PIN errors and dependency exceptions are reduced to static codes/messages at
  the example CLI boundary. No assertion, identity token or server body is
  printed.

See [PROTOCOL.md](PROTOCOL.md) for public-source references and wire details.

## Offline verification

```sh
uv run --group test pytest -q
uv run ruff check .
uv run ruff format --check .
uv run basedpyright
uv run pre-commit run --all-files
```

Tests use synthetic challenges, credentials, assertions, accounts and HTTP
responses. A CTAP test drives real `python-fido2` and ECDSA verification against
an explicitly synthetic authenticator. They do not contact Apple or use a
physical key.

## Attribution

Contributed by Olafejs with AI-assisted implementation and testing. Built on
FindMy.py's GrandSlam/MobileMe flow, Yubico's `python-fido2` and Apple's publicly
served protocol behavior. Dependencies retain their licenses. No Apple frontend
bundle, account response, key material, home configuration or location data is
included.
