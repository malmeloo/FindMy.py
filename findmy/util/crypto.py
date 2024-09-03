"""Pure-python NIST P-224 Elliptic Curve cryptography. Used for some Apple algorithms."""

import hashlib
import hmac

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF

P224_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D


def encrypt_password(password: str, salt: bytes, iterations: int, protocol: str) -> bytes:
    """Encrypt password using PBKDF2-HMAC."""
    assert protocol in ["s2k", "s2k_fo"]
    p = hashlib.sha256(password.encode("utf-8")).digest()
    if protocol == "s2k_fo":
        p = p.hex().encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(p)


def decrypt_spd_aes_cbc(session_key: bytes, data: bytes) -> bytes:
    """Decrypt SPD data using SRP session key."""
    extra_data_key = hmac.new(session_key, b"extra data key:", hashlib.sha256).digest()
    extra_data_iv = hmac.new(session_key, b"extra data iv:", hashlib.sha256).digest()
    # Get only the first 16 bytes of the iv
    extra_data_iv = extra_data_iv[:16]

    # Decrypt with AES CBC
    cipher = Cipher(algorithms.AES(extra_data_key), modes.CBC(extra_data_iv))
    decryptor = cipher.decryptor()
    data = decryptor.update(data) + decryptor.finalize()
    # Remove PKCS#7 padding
    padder = padding.PKCS7(128).unpadder()
    return padder.update(data) + padder.finalize()


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
