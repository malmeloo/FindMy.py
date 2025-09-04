"""
Module to interact with accessories that implement Find My.

Accessories could be anything ranging from AirTags to iPhones.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Literal, TypedDict, overload

from typing_extensions import override

from findmy.util.abc import Serializable
from findmy.util.files import read_data_json, read_data_plist, save_and_return_json

from .keys import KeyGenerator, KeyPair, KeyType
from .util import crypto

if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path

    from findmy.reports.reports import LocationReport

logger = logging.getLogger(__name__)


class FindMyAccessoryMapping(TypedDict):
    """JSON mapping representing state of a FindMyAccessory instance."""

    type: Literal["accessory"]
    master_key: str
    skn: str
    sks: str
    paired_at: str
    name: str | None
    model: str | None
    identifier: str | None
    alignment_date: str | None
    alignment_index: int | None


class RollingKeyPairSource(ABC):
    """A class that generates rolling :meth:`KeyPair`s."""

    @property
    @abstractmethod
    def interval(self) -> timedelta:
        """KeyPair rollover interval."""
        raise NotImplementedError

    @abstractmethod
    def get_min_index(self, dt: datetime) -> int:
        """Get the minimum key index that the accessory could be broadcasting at a specific time."""
        raise NotImplementedError

    @abstractmethod
    def get_max_index(self, dt: datetime) -> int:
        """Get the maximum key index that the accessory could be broadcasting at a specific time."""
        raise NotImplementedError

    @abstractmethod
    def update_alignment(self, report: LocationReport, index: int) -> None:
        """
        Update alignment of the accessory.

        Alignment can be updated based on a LocationReport that was observed at a specific index.
        """
        raise NotImplementedError

    @abstractmethod
    def keys_at(self, ind: int) -> set[KeyPair]:
        """Generate potential key(s) occurring at a certain index."""
        raise NotImplementedError

    def keys_between(self, start: int, end: int) -> set[KeyPair]:
        """Generate potential key(s) occurring between two indices."""
        keys: set[KeyPair] = set()

        for ind in range(start, end + 1):
            keys.update(self.keys_at(ind))

        return keys


class FindMyAccessory(RollingKeyPairSource, Serializable[FindMyAccessoryMapping]):
    """A findable Find My-accessory using official key rollover."""

    def __init__(  # noqa: PLR0913
        self,
        *,
        master_key: bytes,
        skn: bytes,
        sks: bytes,
        paired_at: datetime,
        name: str | None = None,
        model: str | None = None,
        identifier: str | None = None,
        alignment_date: datetime | None = None,
        alignment_index: int | None = None,
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
            logger.warning(
                "Pairing datetime is timezone-naive. Assuming system tz: %s.",
                self._paired_at.tzname(),
            )

        self._name = name
        self._model = model
        self._identifier = identifier
        self._alignment_date = alignment_date if alignment_date is not None else paired_at
        self._alignment_index = alignment_index if alignment_index is not None else 0
        if self._alignment_date.tzinfo is None:
            self._alignment_date = self._alignment_date.astimezone()
            logger.warning(
                "Alignment datetime is timezone-naive. Assuming system tz: %s.",
                self._alignment_date.tzname(),
            )

    @property
    def master_key(self) -> bytes:
        """The private master key."""
        return self._primary_gen.master_key

    @property
    def skn(self) -> bytes:
        """The SKN for the primary key."""
        return self._primary_gen.initial_sk

    @property
    def sks(self) -> bytes:
        """The SKS for the secondary key."""
        return self._secondary_gen.initial_sk

    @property
    def paired_at(self) -> datetime:
        """Date and time at which this accessory was paired with an Apple account."""
        return self._paired_at

    @property
    def name(self) -> str | None:
        """Name of this accessory."""
        return self._name

    @name.setter
    def name(self, name: str | None) -> None:
        self._name = name

    @property
    def model(self) -> str | None:
        """Model string of this accessory, as provided by the manufacturer."""
        return self._model

    @property
    def identifier(self) -> str | None:
        """Internal identifier of this accessory."""
        return self._identifier

    @property
    @override
    def interval(self) -> timedelta:
        """Official FindMy accessory rollover interval (15 minutes)."""
        return timedelta(minutes=15)

    @override
    def get_min_index(self, dt: datetime) -> int:
        if dt.tzinfo is None:
            end = dt.astimezone()
            logger.warning(
                "Datetime is timezone-naive. Assuming system tz: %s.",
                end.tzname(),
            )

        if dt >= self._alignment_date:
            # in the worst case, the accessory has not rolled over at all since alignment
            return self._alignment_index

        # the accessory key will rollover AT MOST once every 15 minutes, so
        # this is the minimum index for which we will need to generate keys.
        # it's possible that rollover has progressed slower or not at all.
        ind_before_alignment = (self._alignment_date - dt) // self.interval
        return self._alignment_index - ind_before_alignment

    @override
    def get_max_index(self, dt: datetime) -> int:
        if dt.tzinfo is None:
            end = dt.astimezone()
            logger.warning(
                "Datetime is timezone-naive. Assuming system tz: %s.",
                end.tzname(),
            )

        if dt <= self._alignment_date:
            # in the worst case, the accessory has not rolled over at all since `dt`,
            # in which case it was at the alignment index. We can't go lower than that.
            return self._alignment_index

        # the accessory key will rollover AT MOST once every 15 minutes, so
        # this is the maximum index for which we will need to generate keys.
        # it's possible that rollover has progressed slower or not at all.
        ind_since_alignment = (dt - self._alignment_date) // self.interval
        return self._alignment_index + ind_since_alignment

    @override
    def update_alignment(self, report: LocationReport, index: int) -> None:
        if report.timestamp < self._alignment_date:
            # we only care about the most recent report
            return

        logger.info("Updating alignment based on report observed at index %i", index)

        self._alignment_date = report.timestamp
        self._alignment_index = index

    def _primary_key_at(self, ind: int) -> KeyPair:
        """Get the primary key at a certain index."""
        return self._primary_gen[ind]

    def _secondary_keys_at(self, ind: int) -> tuple[KeyPair, KeyPair]:
        """Get possible secondary keys at a certain primary index."""
        # when the accessory has been rebooted, it will use the following secondary key
        key_1 = self._secondary_gen[ind // 96 + 1]

        # in some cases, the secondary index may not be at primary_ind // 96 + 1, but at +2 instead.
        # example: if we paired at 3:00 am, the first secondary key will be used until 4:00 am,
        # at which point the second secondary key will be used. The primary index at 4:00 am is 4,
        # but the 'second' secondary key is used.
        # however, since we don't know the exact index rollover pattern, we just take a guess here
        # and return both keys. for alignment, it's better to underestimate progression of the index
        # than to overestimate it.
        key_2 = self._secondary_gen[ind // 96 + 2]

        return key_1, key_2

    @override
    def keys_at(self, ind: int) -> set[KeyPair]:
        """Get the primary and secondary keys that might be active at a certain index."""
        if ind < 0:
            return set()

        return {self._primary_key_at(ind), *self._secondary_keys_at(ind)}

    @classmethod
    def from_plist(
        cls,
        plist: str | Path | dict | bytes,
        key_alignment_plist: str | Path | dict | bytes | None = None,
        *,
        name: str | None = None,
    ) -> FindMyAccessory:
        """Create a FindMyAccessory from a .plist file dumped from the FindMy app."""
        device_data = read_data_plist(plist)

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

        model = device_data["model"]
        identifier = device_data["identifier"]

        alignment_date = None
        index = None
        if key_alignment_plist:
            alignment_data = read_data_plist(key_alignment_plist)

            # last observed date
            alignment_date = alignment_data["lastIndexObservationDate"].replace(
                tzinfo=timezone.utc,
            )
            # primary index value at last observed date
            index = alignment_data["lastIndexObserved"]

        return cls(
            master_key=master_key,
            skn=skn,
            sks=sks,
            paired_at=paired_at,
            name=name,
            model=model,
            identifier=identifier,
            alignment_date=alignment_date,
            alignment_index=index,
        )

    @override
    def to_json(self, path: str | Path | None = None, /) -> FindMyAccessoryMapping:
        alignment_date = None
        if self._alignment_date is not None:
            alignment_date = self._alignment_date.isoformat()

        res: FindMyAccessoryMapping = {
            "type": "accessory",
            "master_key": self._primary_gen.master_key.hex(),
            "skn": self.skn.hex(),
            "sks": self.sks.hex(),
            "paired_at": self._paired_at.isoformat(),
            "name": self.name,
            "model": self.model,
            "identifier": self.identifier,
            "alignment_date": alignment_date,
            "alignment_index": self._alignment_index,
        }

        return save_and_return_json(res, path)

    @classmethod
    @override
    def from_json(
        cls,
        val: str | Path | FindMyAccessoryMapping,
        /,
    ) -> FindMyAccessory:
        val = read_data_json(val)
        assert val["type"] == "accessory"

        try:
            alignment_date = val["alignment_date"]
            if alignment_date is not None:
                alignment_date = datetime.fromisoformat(alignment_date)

            return cls(
                master_key=bytes.fromhex(val["master_key"]),
                skn=bytes.fromhex(val["skn"]),
                sks=bytes.fromhex(val["sks"]),
                paired_at=datetime.fromisoformat(val["paired_at"]),
                name=val["name"],
                model=val["model"],
                identifier=val["identifier"],
                alignment_date=alignment_date,
                alignment_index=val["alignment_index"],
            )
        except KeyError as e:
            msg = f"Failed to restore account data: {e}"
            raise ValueError(msg) from None


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

    @property
    def master_key(self) -> bytes:
        """The private master key."""
        return self._master_key

    @property
    def initial_sk(self) -> bytes:
        """The initial secret key."""
        return self._initial_sk

    @property
    def key_type(self) -> KeyType:
        """The type of key this generator produces."""
        return self._key_type

    def _get_sk(self, ind: int) -> bytes:
        if ind < 0:
            msg = "The key index must be non-negative"
            raise ValueError(msg)

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
    def __getitem__(self, val: int) -> KeyPair: ...

    @overload
    def __getitem__(self, val: slice) -> Generator[KeyPair, None, None]: ...

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
