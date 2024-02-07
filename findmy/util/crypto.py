"""Pure-python NIST P-224 Elliptic Curve cryptography. Used for some Apple algorithms."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF

ECPoint = tuple[float, float]

P224_A = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE
P224_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D
P224_G = (
    0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21,
    0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34,
)
P224_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001


# Old code. Remove if replacement is confirmed to be working.
# ruff: noqa: ERA001
#
# def _ec_add_points(p1: ECPoint, p2: ECPoint) -> ECPoint:
#     """
#     Add two points on a P-224 elliptic curve. (0, 0) is identity.
#
#     https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_addition
#     """
#     (x1, y1), (x2, y2) = p1, p2
#
#     if p1 == (0, 0):  # identity case 1
#         return p2
#     if p2 == (0, 0):  # identity case 2
#         return p1
#     if x1 == x2 and y1 == -1 * y2:  # additive inverse
#         return 0, 0
#
#     if p1 == p2:  # point doubling using limit
#         slope = (3 * x1 ** 2 + P224_A) / (2 * y1)
#     else:
#         slope = (y2 - y1) / (x2 - x1)
#
#     x = slope ** 2 - x1 - x2
#     y = slope * (x1 - x) - y1
#
#     return x, y
#
#
# def _ec_scalar_mul(scalar: int, p: ECPoint) -> ECPoint:
#     """
#     Scalar multiplication on a point on a P-224 elliptic curve.
#
#     https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Double-and-add
#     """
#     res = (0, 0)
#     cur = p
#     while scalar > 0:
#         if scalar & 1:
#             res = _ec_add_points(res, cur)
#         cur = _ec_add_points(cur, cur)
#         scalar >>= 1
#     return res
#
#
# def derive_ps_key(pubkey: ECPoint, sk: bytes) -> ECPoint:
#     at = _x963_kdf(sk, b"diversify", 72)
#     u = int.from_bytes(at[:36], "big") % (P224_N - 1) + 1
#     v = int.from_bytes(at[36:], "big") % (P224_N - 1) + 1
#
#     return _ec_add_points(_ec_scalar_mul(u, pubkey), _ec_scalar_mul(v, P224_G))


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


def _get_pubkey(privkey: int) -> ECPoint:
    key = ec.derive_private_key(privkey, ec.SECP224R1())
    pubkey = key.public_key().public_numbers()
    return pubkey.x, pubkey.y
