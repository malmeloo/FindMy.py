"""Module to work with private and public keys as used in FindMy accessories."""

import base64
import hashlib
import secrets
from abc import ABC, abstractmethod

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec


class HasPublicKey(ABC):
    """
    ABC for anything that has a public FindMy-key.

    Also called an "advertisement" key, since it is the key that is advertised by findable devices.
    """

    @property
    @abstractmethod
    def adv_key_bytes(self) -> bytes:
        """Return the advertised (public) key as bytes."""
        raise NotImplementedError

    @property
    def adv_key_b64(self) -> str:
        """Return the advertised (public) key as a base64-encoded string."""
        return base64.b64encode(self.adv_key_bytes).decode("ascii")

    @property
    def hashed_adv_key_bytes(self) -> bytes:
        """Return the hashed advertised (public) key as bytes."""
        return hashlib.sha256(self.adv_key_bytes).digest()

    @property
    def hashed_adv_key_b64(self) -> str:
        """Return the hashed advertised (public) key as a base64-encoded string."""
        return base64.b64encode(self.hashed_adv_key_bytes).decode("ascii")


class KeyPair(HasPublicKey):
    """A private-public keypair for a trackable FindMy accessory."""

    def __init__(self, private_key: bytes) -> None:
        """Initialize the `KeyPair` with the private key bytes."""
        priv_int = int.from_bytes(private_key, "big")
        self._priv_key = ec.derive_private_key(
            priv_int,
            ec.SECP224R1(),
            default_backend(),
        )

    @classmethod
    def generate(cls) -> "KeyPair":
        """Generate a new random `KeyPair`."""
        return cls(secrets.token_bytes(28))

    @classmethod
    def from_b64(cls, key_b64: str) -> "KeyPair":
        """
        Import an existing `KeyPair` from its base64-encoded representation.

        Same format as returned by `KeyPair.private_key_b64`.
        """
        return cls(base64.b64decode(key_b64))

    @property
    def private_key_bytes(self) -> bytes:
        """Return the private key as bytes."""
        key_bytes = self._priv_key.private_numbers().private_value
        return int.to_bytes(key_bytes, 28, "big")

    @property
    def private_key_b64(self) -> str:
        """
        Return the private key as a base64-encoded string.

        Can be re-imported using `KeyPair.from_b64`.
        """
        return base64.b64encode(self.private_key_bytes).decode("ascii")

    @property
    def adv_key_bytes(self) -> bytes:
        """Return the advertised (public) key as bytes."""
        key_bytes = self._priv_key.public_key().public_numbers().x
        return int.to_bytes(key_bytes, 28, "big")

    def dh_exchange(self, other_pub_key: ec.EllipticCurvePublicKey) -> bytes:
        """Do a Diffie-Hellman key exchange using another EC public key."""
        return self._priv_key.exchange(ec.ECDH(), other_pub_key)
