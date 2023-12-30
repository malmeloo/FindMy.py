import base64
import secrets

from cryptography.hazmat.backends import default_backend
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec


class KeyPair:
    def __init__(self, private_key: bytes):
        priv_int = int.from_bytes(private_key, "big")
        self._priv_key = ec.derive_private_key(
            priv_int, ec.SECP224R1(), default_backend()
        )

    @classmethod
    def generate(cls) -> "KeyPair":
        return cls(secrets.token_bytes(28))

    @classmethod
    def from_b64(cls, key_b64: str) -> "KeyPair":
        return cls(base64.b64decode(key_b64))

    @property
    def private_key_bytes(self) -> bytes:
        key_bytes = self._priv_key.private_numbers().private_value
        return int.to_bytes(key_bytes, 28, "big")

    @property
    def private_key_b64(self) -> str:
        return base64.b64encode(self.private_key_bytes).decode("ascii")

    @property
    def adv_key_bytes(self) -> bytes:
        key_bytes = self._priv_key.public_key().public_numbers().x
        return int.to_bytes(key_bytes, 28, "big")

    @property
    def adv_key_b64(self) -> str:
        return base64.b64encode(self.adv_key_bytes).decode("ascii")

    @property
    def hashed_adv_key_bytes(self) -> bytes:
        return hashlib.sha256(self.adv_key_bytes).digest()

    @property
    def hashed_adv_key_b64(self) -> str:
        return base64.b64encode(self.hashed_adv_key_bytes).decode("ascii")

    def dh_exchange(self, other_pub_key: ec.EllipticCurvePublicKey) -> bytes:
        return self._priv_key.exchange(ec.ECDH(), other_pub_key)
