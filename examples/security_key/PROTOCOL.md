# Apple HSA2 security-key protocol notes

## Public references

Inspected public frontend assets (content-addressed observations; Apple may retire URLs):

- https://appleid.cdn-apple.com/appleauth/static/module-assets/home-76bd5c25830b7078b52d.js
  SHA256 `4780584db5095b3d338291478e94cda4cbd591b9719443369a81aa6643f799bd`.
- https://appleid.cdn-apple.com/appleauth/static/module-assets/hsa2-56a31aafc0c6434ca05c.js
  SHA256 `a2380046ba6974e119b487739c1312868a68c6f9cf63a90431eaa67bee2bae21`.
- https://www.apple.com/appleca/AppleIncRootCertificate.cer
  DER SHA256 `b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024`.

Only the public CA certificate is included, not Apple's JavaScript bundles. Asset
inspection is evidence of frontend behavior, not by itself proof of real login.
The original adapter's one-account real test is described separately in README.md.

## Distinct flows

1. HSA2 hardware-key second factor: `fsa2_hsa2`, `/auth/verify/security/key`.
2. Primary FSA2 login: `/auth/verify/securitykey`, different spelling and codec.
3. Device passkey login: `/auth/verify/device/key`, possible PRF/largeBlob behavior.

Only the first flow is implemented. Legacy FSA1/U2F is not supported.

## Exchange

After normal SRP reaches REQUIRE_2FA, retain the existing ADSID/identity token and
Anisette headers. Read `https://gsa.apple.com/auth`, extract the unique
`script.boot_args`, and accept either an explicit first factor `fsa2_hsa2` under
`direct`/`direct.twoSV`, or the observed direct `fsaVerification.fsaChallenge`
layout without an `authFactors` member. A nested twoSV without factors is rejected.

Required fields: `challenge`, `rpId`, `keyHandles`. The origin is the actual GSA
origin; only `apple.com` and `gsa.apple.com` RPs pass the explicit allowlist and
normal python-fido2 RP validation. Pass `userVerification=preferred` and the USB
credential allowlist to the authenticator. The request has a 90-second timeout;
the local challenge expires after 120 seconds. Extensions/referrerQuery are not
silently accepted.

HSA2 payload (not the primary-FSA2 payload):

| Field | Encoding |
| --- | --- |
| challenge | standard base64, without padding |
| clientData | standard base64, padded |
| signatureData | standard base64, padded |
| authenticatorData | standard base64, padded |
| credentialID | standard base64, without padding |
| userHandle | standard base64, without padding; empty if absent |
| rpId | validated RP ID |

The HSA2 caller leaves `requestId` undefined; JSON serialization omits it.
POST the validated assertion to `/auth/verify/security/key`, preserving known
continuation headers. Frontend terminal acceptance statuses are 200/204/250;
202/409 are not treated as success. Do not log identity tokens or assertions.

Then explicitly repeat GrandSlam authentication and complete MobileMe login.
Check AUTHENTICATED, LOGGED_IN and presence of the search-party session token.
Only then save a private session with its password removed. This does not prove
that arbitrary downstream callers use verified TLS; the example's checked
transport intentionally only permits authentication URLs.
