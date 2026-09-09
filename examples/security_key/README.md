# Experimental Apple hardware-security-key login

Related: [FindMy.py #159](https://github.com/malmeloo/FindMy.py/issues/159) and
[OpenTagViewer #18](https://github.com/parawanderer/OpenTagViewer/issues/18).

This opt-in Linux example adds Apple's **HSA2 FIDO2/WebAuthn hardware-key second
factor** to the existing FindMy password/SRP login. It does not modify the default
CLI, SMS/trusted-device second factors, or the installed package's public API.
`FidoAppleAccount` is an example-local subclass of `AsyncAppleAccount`, currently
coupled to the internals of FindMy 0.10.1. It is not a drop-in report-fetching client:
its replacement HTTP transport permits authentication endpoints only.

## Evidence and limitations

The original adapter was exercised with **one real Apple account protected by a
Yubico USB Security Key on Linux**. The key endpoint accepted the assertion, the
subsequent GrandSlam exchange authenticated, MobileMe issued a FindMy session,
and the session was saved without a password. A separate private integration
subsequently reused the session and successfully fetched an owned accessory's
location. Those private integrations and data are **not** part of this contribution.

This public extraction is tested offline against the upstream source. It does not
claim a second real-account trial, universal key compatibility, official Apple
support, or a completed stable SDK integration. No account-security changes,
removal of security keys, macOS SIP/AMFI changes, or passwordless/passkey login are
required or implemented. Legacy FSA1/U2F and primary-FSA2 login are out of scope.

## Run explicitly, in a private terminal

Use a Linux machine with the USB key physically connected and appropriate user
access to its FIDO HID interface. An ordinary SSH connection does not forward USB.
Do not run as root merely to work around device permissions, record the terminal,
put credentials in arguments/environment variables, or paste session files into
issues. **Never guess or repeatedly retry a security-key PIN.**

From a checkout of this branch:

```sh
uv sync --group dev
uv run python examples/security_key/login.py --help
# Explicit anonymous network probe: USB enumeration and verified-TLS GET /auth.
# No account login, PIN prompt, or session creation.
uv run python examples/security_key/login.py --preflight
# One human-approved login attempt:
uv run python examples/security_key/login.py --login
```

`--preflight` is only successful when exactly one USB authenticator is accessible
and the anonymous Apple endpoint returns the expected 401. It is not an offline
check and is not run by pytest. `--login` asks for `YES`, Apple ID/password, and the
key PIN/touch as required. PIN entry plus touch share a 90-second operation timeout.
Local Anisette may download its required libraries and provision a client identity
with Apple: the consent prompt explicitly discloses this. No remote public Anisette
server is used. Anisette's own transport is a separate dependency boundary from
the checked account-authentication HTTP adapter here.

Every attempt gets a new user-owned `data/login-*` directory beneath this example.
Successful `session.json` has mode 0600 under a 0700 directory. No previous attempt
is read or overwritten. The password is removed from the saved SDK serialization;
the file still contains sensitive session credentials and identity metadata.
Private files are ignored by Git. This command neither exports accessory keys nor
queries locations. A session file is not a reusable public fixture.

Optional `--diagnose-auth` performs one separately approved password-auth attempt
and reads only the Apple auth-page **schema**. Its bounded output contains
allowlisted field names/types, not raw HTML, dynamic field names, challenges,
credential IDs, signatures or tokens. It does not sign, finish login, or save a
session. It is for unsupported schema review, not automatic retry.

## Protocol and safety boundaries

- Exact endpoint allowlist, verified TLS, redirects rejected, no automatic retry.
- Apple Root CA is pinned and loaded into an instance-local GSA context; standard
  roots are used for iCloud. Nothing is installed into system trust. The bundled
  PEM is a **public CA certificate**, not a private key.
- Parse the explicit `fsa2_hsa2` layout or the observed direct
  `fsaVerification.fsaChallenge` layout. Refuse unknown factors, extensions,
  nonempty `referrerQuery`, duplicate JSON keys and oversized input.
- Verify RP/origin, challenge, selected credential, RP-ID hash, user-presence flag,
  extension output and challenge age before sending an assertion.
- Match Apple's HSA2-specific base64 conventions; do not substitute primary-FSA2
  endpoint spelling or a generic passkey request body.
- Key-endpoint acceptance alone is not success: require post-key GrandSlam and
  MobileMe state transitions and a FindMy token before saving.
- Suppress third-party exception bodies. The example disables Python logging only
  in its explicit CLI entry point, never at module import.
- PIN errors, verification blocks and ambiguous responses stop the attempt.

See [PROTOCOL.md](PROTOCOL.md) for public-source references and wire details.

## Offline tests

```sh
uv run --group test pytest -q
uv run --group test pytest -q tests/security_key
uv run ruff check examples/security_key tests/security_key
uv run ruff format --check examples/security_key tests/security_key
uv run basedpyright
```

The added 104 tests use synthetic accounts, challenges, credentials, signatures
and transport responses. One test drives real python-fido2 against an explicitly
synthetic CTAP2 authenticator and checks ECDSA signatures. Other tests exercise
RP/origin/encoding rejection, stale challenges, TLS and response limits, single-use
attempts, secret-free diagnostics, session-file permissions, password exclusion
and noninteractive login refusal. They do not contact Apple or access a physical
key. Existing upstream tests remain unchanged.

The fido2 dependency is pinned in development/test groups only, not made a new
mandatory dependency for ordinary FindMy users. Small per-file style exceptions
are documented for intentional internal-SDK access, fail-closed boundaries and
synthetic mocks; typing, lint, formatting and behavioral tests still run.

## Attribution

Contributed by Olafejs with AI-assisted implementation and testing (Patrycja).
Built on FindMy.py's existing GrandSlam/MobileMe flow, Yubico's python-fido2 and
Apple's publicly served protocol behavior. No proprietary Apple JavaScript bundle,
account response, exported key material, home configuration or location data is
included. This contribution follows the repository's MIT license; dependencies
retain their own licenses. The example is intended as a reviewable starting point
for the library's native second-factor API, not a claim of ownership over upstream.
