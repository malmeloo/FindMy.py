"""Pure-python NIST P-224 Elliptic Curve cryptography. Used for some Apple algorithms."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF

ECPoint = tuple[float, float]

P224_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D


def x963_kdf(value: bytes, si: bytes, length: int) -> bytes:
    """Single pass of X9.63 KDF with SHA1."""
    return X963KDF(
        algorithm=hashes.SHA256(),
        sharedinfo=si,
        length=length,
    ).derive(value)


def bytes_to_int(value: bytes) -> int:
    """Convert bytes in big-endian format to int."""
    return int.from_bytes(value, "big")


def derive_ps_key(privkey: bytes, sk: bytes) -> bytes:
    """
    Derive a primary or secondary key used by an accessory.

    :param privkey: Private key generated during pairing
    :param sk: Current secret key for this time period.
               Use SKN to derive the primary key, SKS for secondary.
    """
    priv_int = bytes_to_int(privkey)

    at = x963_kdf(sk, b"diversify", 72)
    u = bytes_to_int(at[:36]) % (P224_N - 1) + 1
    v = bytes_to_int(at[36:]) % (P224_N - 1) + 1

    key = (u * priv_int + v) % P224_N
    return key.to_bytes(28, "big")
