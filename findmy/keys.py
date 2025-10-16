"""Module to work with private and public keys as used in FindMy accessories."""

from __future__ import annotations

import base64
import hashlib
import secrets
from abc import ABC, abstractmethod
from enum import Enum
from typing import TYPE_CHECKING, Generic, Literal, TypedDict, TypeVar, overload

from cryptography.hazmat.primitives.asymmetric import ec
from typing_extensions import override

from findmy.util.abc import Serializable
from findmy.util.files import read_data_json, save_and_return_json

from .util import crypto, parsers

if TYPE_CHECKING:
    import io
    from collections.abc import Generator
    from pathlib import Path


class KeyPairType(Enum):
    """Enum of possible key types."""

    UNKNOWN = 0
    PRIMARY = 1
    SECONDARY = 2


class KeyPairMapping(TypedDict):
    """JSON mapping representing a KeyPair."""

    type: Literal["keypair"]

    private_key: str
    key_type: int
    name: str | None


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
    @override
    def hashed_adv_key_bytes(self) -> bytes:
        """See :meth:`HasHashedPublicKey.hashed_adv_key_bytes`."""
        return hashlib.sha256(self.adv_key_bytes).digest()

    @property
    def mac_address(self) -> str:
        """Get the mac address from the public key."""
        first_byte = (self.adv_key_bytes[0] | 0b11000000).to_bytes(1)
        return ":".join([parsers.format_hex_byte(x) for x in first_byte + self.adv_key_bytes[1:6]])

    def adv_data(self, status: int = 0, hint: int = 0) -> bytes:
        """Get the BLE advertisement data that should be broadcast to advertise this key."""
        return bytes(
            [
                # apple company id
                0x4C,
                0x00,
            ],
        ) + self.of_data(status, hint)

    def of_data(self, status: int = 0, hint: int = 0) -> bytes:
        """Get the Offline Finding data that should be broadcast to advertise this key."""
        return bytes(
            [
                # offline finding
                0x12,
                # offline finding data length
                25,
                status,
                # remaining public key bytes
                *self.adv_key_bytes[6:],
                self.adv_key_bytes[0] >> 6,
                hint,
            ],
        )


class KeyPair(HasPublicKey, Serializable[KeyPairMapping]):
    """A private-public keypair for a trackable FindMy accessory."""

    def __init__(
        self,
        private_key: bytes,
        key_type: KeyPairType = KeyPairType.UNKNOWN,
        name: str | None = None,
    ) -> None:
        """Initialize the :meth:`KeyPair` with the private key bytes."""
        priv_int = crypto.bytes_to_int(private_key)
        self._priv_key = ec.derive_private_key(
            priv_int,
            ec.SECP224R1(),
        )

        self._key_type = key_type
        self._name = name

    @property
    def key_type(self) -> KeyPairType:
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
        """Generate a new random :meth:`KeyPair`."""
        return cls(secrets.token_bytes(28))

    @classmethod
    def from_b64(cls, key_b64: str) -> KeyPair:
        """
        Import an existing :meth:`KeyPair` from its base64-encoded representation.

        Same format as returned by :meth:`KeyPair.private_key_b64`.
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

        Can be re-imported using :meth:`KeyPair.from_b64`.
        """
        return base64.b64encode(self.private_key_bytes).decode("ascii")

    @property
    @override
    def adv_key_bytes(self) -> bytes:
        """Return the advertised (public) key as bytes."""
        key_bytes = self._priv_key.public_key().public_numbers().x
        return int.to_bytes(key_bytes, 28, "big")

    @override
    def to_json(self, dst: str | Path | io.TextIOBase | None = None, /) -> KeyPairMapping:
        return save_and_return_json(
            {
                "type": "keypair",
                "private_key": base64.b64encode(self.private_key_bytes).decode("ascii"),
                "key_type": self._key_type.value,
                "name": self.name,
            },
            dst,
        )

    @classmethod
    @override
    def from_json(
        cls, val: str | Path | io.TextIOBase | io.BufferedIOBase | KeyPairMapping, /
    ) -> KeyPair:
        val = read_data_json(val)
        assert val["type"] == "keypair"

        try:
            return cls(
                private_key=base64.b64decode(val["private_key"]),
                key_type=KeyPairType(val["key_type"]),
                name=val["name"],
            )
        except KeyError as e:
            msg = f"Failed to restore KeyPair data: {e}"
            raise ValueError(msg) from None

    def dh_exchange(self, other_pub_key: ec.EllipticCurvePublicKey) -> bytes:
        """Do a Diffie-Hellman key exchange using another EC public key."""
        return self._priv_key.exchange(ec.ECDH(), other_pub_key)

    @override
    def __repr__(self) -> str:
        return f'KeyPair(name="{self.name}", public_key="{self.adv_key_b64}", type={self.key_type})'


_K = TypeVar("_K")


class KeyGenerator(ABC, Generic[_K]):
    """KeyPair generator."""

    @abstractmethod
    def __iter__(self) -> KeyGenerator:
        return NotImplemented

    @abstractmethod
    def __next__(self) -> _K:
        return NotImplemented

    @overload
    @abstractmethod
    def __getitem__(self, val: int) -> _K: ...

    @overload
    @abstractmethod
    def __getitem__(self, val: slice) -> Generator[_K, None, None]: ...

    @abstractmethod
    def __getitem__(self, val: int | slice) -> _K | Generator[_K, None, None]:
        return NotImplemented
