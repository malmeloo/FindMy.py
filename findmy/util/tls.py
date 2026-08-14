"""
The trust store this library verifies Apple's servers against.

**`gsa.apple.com` presents a chain rooted at the 2006 "Apple Root CA", which most trust
stores do not carry.** It is absent from certifi's bundle entirely, so anywhere that bundle
is in use -- which is most Linux deployments and every container built from one -- the
authentication host fails verification while every other Apple host this library talks to
verifies fine:

    ssl.SSLCertVerificationError: certificate verify failed: self-signed certificate in
    certificate chain

That one host is the whole reason verification used to be disabled process-wide, on every
request the library makes. The rest -- CloudKit, the setup delegate, the iCloud gateway --
verify fine today and were being sent unverified for no reason at all, carrying a login
among other things.

So the fix is to **add** the missing root rather than to stop checking: a context built
from the platform defaults, with Apple's root loaded on top. Adding a trust anchor does not
weaken the ones already there, and this is strictly stricter than what a bare
`create_default_context()` gives on a machine whose store happens to include it.

Note what this deliberately is *not*. It does not pin a leaf or an intermediate: a general
TLS path has to survive certificate rotation, and a client that pins one breaks on a day
Apple chooses. Adding a root is the right strength here.
"""

from __future__ import annotations

import hashlib
import logging
import ssl
from functools import lru_cache

logger = logging.getLogger(__name__)

APPLE_ROOT_CA_PEM = """-----BEGIN CERTIFICATE-----
MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzET
MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0
MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBw
bGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx
FjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg+
+FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1
XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9w
tj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IW
q6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKM
aLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8E
BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3
R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAE
ggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93
d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNl
IG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0
YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBj
b25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZp
Y2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBc
NplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQP
y3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7
R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4Fg
xhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oP
IQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AX
UKqK1drk/NAJBzewdXUh
-----END CERTIFICATE-----
"""
"""
Apple Root CA, serial 2, valid from 2006 to 2035.

Published by Apple at <https://www.apple.com/appleca/>. Checked against its SHA-256 at
import, so a mangled copy fails immediately rather than at the first handshake.
"""

APPLE_ROOT_CA_SHA256 = bytes.fromhex(
    "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",
)
"""What the root above must hash to. A certificate is only a trust anchor once it does."""


class TlsError(Exception):
    """Raised when the trust store cannot be built."""


def _verified_root() -> str:
    """Return the bundled root, having checked it is the certificate it claims to be."""
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(APPLE_ROOT_CA_PEM)).digest()
    if digest != APPLE_ROOT_CA_SHA256:
        msg = (
            f"The bundled Apple root hashes to {digest.hex()}, not"
            f" {APPLE_ROOT_CA_SHA256.hex()}. Refusing to trust it."
        )
        raise TlsError(msg)
    return APPLE_ROOT_CA_PEM


@lru_cache(maxsize=1)
def apple_trust_context() -> ssl.SSLContext:
    """
    Build the context every request to Apple is verified against.

    The platform's own trust store plus Apple's 2006 root, which most stores lack and which
    `gsa.apple.com` chains to. Cached because constructing one reads certificates from disk,
    and that is blocking work best not done per request.
    """
    context = ssl.create_default_context()
    try:
        context.load_verify_locations(cadata=_verified_root())
    except ssl.SSLError as e:
        msg = f"Could not load the bundled Apple root: {e}"
        raise TlsError(msg) from None

    return context


def tls_setting(*, verify: bool) -> ssl.SSLContext | bool:
    """
    Resolve what to pass as aiohttp's `ssl` argument.

    :param verify: False disables certificate verification entirely, which makes the
        connection interceptable by anything on the network path. There is exactly one
        legitimate reason to do it -- an Anisette server of one's own with a self-signed
        certificate -- and it is exposed there and nowhere else.
    """
    if verify:
        return apple_trust_context()

    logger.warning(
        "TLS certificate verification is disabled for this session. Anything on the"
        " network path can read and alter these requests.",
    )
    return False
