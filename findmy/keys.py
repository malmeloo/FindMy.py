"""Module to work with private and public keys as used in FindMy accessories."""

from __future__ import annotations

import base64
import hashlib
import secrets
from abc import ABC, abstractmethod
from enum import Enum
from typing import TYPE_CHECKING, Generic, TypeVar, overload

from cryptography.hazmat.primitives.asymmetric import ec
from typing_extensions import override

from .util import crypto, parsers

if TYPE_CHECKING:
    from collections.abc import Generator


class KeyType(Enum):
    """Enum of possible key types."""

    UNKNOWN = 0
    PRIMARY = 1
    SECONDARY = 2


class HasHashedPublicKey(ABC):
    """
    ABC for anything that has a public, hashed FindMy-key.

    Also called a "hashed advertisement" key or "lookup" key.
    """

    @property
    @abstractmethod
    def hashed_adv_key_bytes(self) -> bytes:
        """Return the hashed advertised (public) key as bytes."""
        raise NotImplementedError

    @property
    def hashed_adv_key_b64(self) -> str:
        """Return the hashed advertised (public) key as a base64-encoded string."""
        return base64.b64encode(self.hashed_adv_key_bytes).decode("ascii")

    @override
    def __hash__(self) -> int:
        return crypto.bytes_to_int(self.hashed_adv_key_bytes)

    @override
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, HasHashedPublicKey):
            return NotImplemented

        return self.hashed_adv_key_bytes == other.hashed_adv_key_bytes


class HasPublicKey(HasHashedPublicKey, ABC):
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
    def mac_address(self) -> str:
        """Get the mac address from the public key."""
        first_byte = (self.adv_key_bytes[0] | 0b11000000).to_bytes(1)
        return ":".join([parsers.format_hex_byte(x) for x in first_byte + self.adv_key_bytes[1:6]])

    @property
    @override
    def hashed_adv_key_bytes(self) -> bytes:
        """See `HasHashedPublicKey.hashed_adv_key_bytes`."""
        return hashlib.sha256(self.adv_key_bytes).digest()


class KeyPair(HasPublicKey):
    """A private-public keypair for a trackable FindMy accessory."""

    def __init__(
        self,
        private_key: bytes,
        key_type: KeyType = KeyType.UNKNOWN,
        name: str | None = None,
    ) -> None:
        """Initialize the `KeyPair` with the private key bytes."""
        priv_int = crypto.bytes_to_int(private_key)
        self._priv_key = ec.derive_private_key(
            priv_int,
            ec.SECP224R1(),
        )

        self._key_type = key_type
        self._name = name

    @property
    def key_type(self) -> KeyType:
        """Type of this key."""
        return self._key_type

    @property
    def name(self) -> str | None:
        """Name of this KeyPair."""
        return self._name

    @name.setter
    def name(self, name: str | None) -> None:
        self._name = name

    @classmethod
    def new(cls) -> KeyPair:
        """Generate a new random `KeyPair`."""
        return cls(secrets.token_bytes(28))

    @classmethod
    def from_b64(cls, key_b64: str) -> KeyPair:
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
    @override
    def adv_key_bytes(self) -> bytes:
        """Return the advertised (public) key as bytes."""
        key_bytes = self._priv_key.public_key().public_numbers().x
        return int.to_bytes(key_bytes, 28, "big")

    def dh_exchange(self, other_pub_key: ec.EllipticCurvePublicKey) -> bytes:
        """Do a Diffie-Hellman key exchange using another EC public key."""
        return self._priv_key.exchange(ec.ECDH(), other_pub_key)

    @override
    def __repr__(self) -> str:
        return f'KeyPair(name="{self.name}", public_key="{self.adv_key_b64}", type={self.key_type})'


K = TypeVar("K")


class KeyGenerator(ABC, Generic[K]):
    """KeyPair generator."""

    @abstractmethod
    def __iter__(self) -> KeyGenerator:
        return NotImplemented

    @abstractmethod
    def __next__(self) -> K:
        return NotImplemented

    @overload
    @abstractmethod
    def __getitem__(self, val: int) -> K: ...

    @overload
    @abstractmethod
    def __getitem__(self, val: slice) -> Generator[K, None, None]: ...

    @abstractmethod
    def __getitem__(self, val: int | slice) -> K | Generator[K, None, None]:
        return NotImplemented
