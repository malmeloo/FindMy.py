"""
Module to interact with accessories that implement Find My.

Accessories could be anything ranging from AirTags to iPhones.
"""
from __future__ import annotations

import logging
import plistlib
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import IO, Generator, overload

from typing_extensions import override

from .keys import KeyGenerator, KeyPair, KeyType
from .util import crypto

logging.getLogger(__name__)


class RollingKeyPairSource(ABC):
    """A class that generates rolling `KeyPair`s."""

    @property
    @abstractmethod
    def interval(self) -> timedelta:
        """KeyPair rollover interval."""

    @abstractmethod
    def keys_at(self, ind: int | datetime) -> set[KeyPair]:
        """Generate potential key(s) occurring at a certain index or timestamp."""
        raise NotImplementedError

    @overload
    def keys_between(self, start: int, end: int) -> set[KeyPair]:
        pass

    @overload
    def keys_between(self, start: datetime, end: datetime) -> set[KeyPair]:
        pass

    def keys_between(self, start: int | datetime, end: int | datetime) -> set[KeyPair]:
        """Generate potential key(s) occurring between two indices or timestamps."""
        keys: set[KeyPair] = set()

        if isinstance(start, int) and isinstance(end, int):
            while start < end:
                keys.update(self.keys_at(start))

                start += 1
        elif isinstance(start, datetime) and isinstance(end, datetime):
            while start < end:
                keys.update(self.keys_at(start))

                start += self.interval
        else:
            msg = "Invalid start/end type"
            raise TypeError(msg)

        return keys


class FindMyAccessory(RollingKeyPairSource):
    """A findable Find My-accessory using official key rollover."""

    def __init__(  # noqa: PLR0913
        self,
        master_key: bytes,
        skn: bytes,
        sks: bytes,
        paired_at: datetime,
        name: str | None = None,
    ) -> None:
        """
        Initialize a FindMyAccessory. These values are usually obtained during pairing.

        :param master_key: The private master key.
        :param skn: The SKN for the primary key.
        :param sks: The SKS for the secondary key.
        """
        self._primary_gen = AccessoryKeyGenerator(master_key, skn, KeyType.PRIMARY)
        self._secondary_gen = AccessoryKeyGenerator(master_key, sks, KeyType.SECONDARY)
        self._paired_at: datetime = paired_at
        if self._paired_at.tzinfo is None:
            self._paired_at = self._paired_at.astimezone()
            logging.warning(
                "Pairing datetime is timezone-naive. Assuming system tz: %s.",
                self._paired_at.tzname(),
            )

        self._name = name

    @property
    @override
    def interval(self) -> timedelta:
        """Official FindMy accessory rollover interval (15 minutes)."""
        return timedelta(minutes=15)

    @override
    def keys_at(self, ind: int | datetime) -> set[KeyPair]:
        """Get the potential primary and secondary keys active at a certain time or index."""
        if isinstance(ind, datetime) and ind < self._paired_at:
            return set()
        if isinstance(ind, int) and ind < 0:
            return set()

        secondary_offset = 0

        if isinstance(ind, datetime):
            # number of 15-minute slots since pairing time
            ind = (
                int(
                    (ind - self._paired_at).total_seconds() / (15 * 60),
                )
                + 1
            )
            # number of slots until first 4 am
            first_rollover = self._paired_at.astimezone().replace(
                hour=4,
                minute=0,
                second=0,
                microsecond=0,
            )
            if first_rollover < self._paired_at:  # we rolled backwards, so increment the day
                first_rollover += timedelta(days=1)
            secondary_offset = (
                int(
                    (first_rollover - self._paired_at).total_seconds() / (15 * 60),
                )
                + 1
            )

        possible_keys = set()
        # primary key can always be determined
        possible_keys.add(self._primary_gen[ind])

        # when the accessory has been rebooted, it will use the following secondary key
        possible_keys.add(self._secondary_gen[ind // 96 + 1])

        if ind > secondary_offset:
            # after the first 4 am after pairing, we need to account for the first day
            possible_keys.add(self._secondary_gen[(ind - secondary_offset) // 96 + 2])

        return possible_keys

    @classmethod
    def from_plist(cls, plist: IO[bytes]) -> FindMyAccessory:
        """Create a FindMyAccessory from a .plist file dumped from the FindMy app."""
        device_data = plistlib.load(plist)

        # PRIVATE master key. 28 (?) bytes.
        master_key = device_data["privateKey"]["key"]["data"][-28:]

        # "Primary" shared secret. 32 bytes.
        skn = device_data["sharedSecret"]["key"]["data"]

        # "Secondary" shared secret. 32 bytes.
        if "secondarySharedSecret" in device_data:
            # AirTag
            sks = device_data["secondarySharedSecret"]["key"]["data"]
        else:
            # iDevice
            sks = device_data["secureLocationsSharedSecret"]["key"]["data"]

        # "Paired at" timestamp (UTC)
        paired_at = device_data["pairingDate"].replace(tzinfo=timezone.utc)

        return cls(master_key, skn, sks, paired_at)


class AccessoryKeyGenerator(KeyGenerator[KeyPair]):
    """KeyPair generator. Uses the same algorithm internally as FindMy accessories do."""

    def __init__(
        self,
        master_key: bytes,
        initial_sk: bytes,
        key_type: KeyType = KeyType.UNKNOWN,
    ) -> None:
        """
        Initialize the key generator.

        :param master_key: Private master key. Usually obtained during pairing.
        :param initial_sk: Initial secret key. Can be the SKN to generate primary keys,
                           or the SKS to generate secondary ones.
        """
        if len(master_key) != 28:
            msg = "The master key must be 28 bytes long"
            raise ValueError(msg)
        if len(initial_sk) != 32:
            msg = "The sk must be 32 bytes long"
            raise ValueError(msg)

        self._master_key = master_key
        self._initial_sk = initial_sk
        self._key_type = key_type

        self._cur_sk = initial_sk
        self._cur_sk_ind = 0

        self._iter_ind = 0

    def _get_sk(self, ind: int) -> bytes:
        if ind < self._cur_sk_ind:  # behind us; need to reset :(
            self._cur_sk = self._initial_sk
            self._cur_sk_ind = 0

        for _ in range(self._cur_sk_ind, ind):
            self._cur_sk = crypto.x963_kdf(self._cur_sk, b"update", 32)
            self._cur_sk_ind += 1
        return self._cur_sk

    def _get_keypair(self, ind: int) -> KeyPair:
        sk = self._get_sk(ind)
        privkey = crypto.derive_ps_key(self._master_key, sk)
        return KeyPair(privkey, self._key_type)

    def _generate_keys(self, start: int, stop: int | None) -> Generator[KeyPair, None, None]:
        ind = start
        while stop is None or ind < stop:
            yield self._get_keypair(ind)

            ind += 1

    @override
    def __iter__(self) -> KeyGenerator:
        self._iter_ind = -1
        return self

    @override
    def __next__(self) -> KeyPair:
        self._iter_ind += 1

        return self._get_keypair(self._iter_ind)

    @overload
    def __getitem__(self, val: int) -> KeyPair:
        ...

    @overload
    def __getitem__(self, val: slice) -> Generator[KeyPair, None, None]:
        ...

    @override
    def __getitem__(self, val: int | slice) -> KeyPair | Generator[KeyPair, None, None]:
        if isinstance(val, int):
            if val < 0:
                msg = "The key index must be non-negative"
                raise ValueError(msg)

            return self._get_keypair(val)
        if isinstance(val, slice):
            start, stop = val.start or 0, val.stop
            if start < 0 or (stop is not None and stop < 0):
                msg = "The key index must be non-negative"
                raise ValueError(msg)

            return self._generate_keys(start, stop)

        return NotImplemented
