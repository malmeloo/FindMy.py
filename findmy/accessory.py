"""
Module to interact with accessories that implement Find My.

Accessories could be anything ranging from AirTags to iPhones.
"""

from __future__ import annotations

import bisect
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Literal, TypedDict, overload

from typing_extensions import override

from . import util
from .keys import KeyGenerator, KeyPair, KeyPairType
from .util import crypto

if TYPE_CHECKING:
    import io
    from collections.abc import Generator
    from pathlib import Path

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
    def update_alignment(self, dt: datetime, index: int) -> None:
        """
        Update alignment of the accessory based on a key index that was observed at a specific time.

        Implementations of this method should consider that this method may be called
        multiple times, sometimes with seemingly conflicting data: the same index may be
        observed at different times, or multiple indices may be observed at the same time.
        """
        raise NotImplementedError

    @abstractmethod
    def keys_at(self, ind: int) -> set[KeyPair]:
        """Generate potential key(s) occurring at a certain index."""
        raise NotImplementedError

    def keys_between(
        self, start: int | datetime, end: int | datetime
    ) -> Generator[tuple[int, KeyPair], None, None]:
        """Generate potential key(s) that could be occurring between two indices or datetimes."""
        if isinstance(start, datetime):
            start = self.get_min_index(start)
        if isinstance(end, datetime):
            end = self.get_max_index(end)

        yielded: set[KeyPair] = set()
        for ind in range(start, end + 1):
            for key in self.keys_at(ind):
                if key in yielded:
                    continue

                yielded.add(key)
                yield ind, key


class FindMyAccessory(RollingKeyPairSource, util.abc.Serializable[FindMyAccessoryMapping]):
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
        self._primary_gen = _AccessoryKeyGenerator(master_key, skn, KeyPairType.PRIMARY)
        self._secondary_gen = _AccessoryKeyGenerator(master_key, sks, KeyPairType.SECONDARY)
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
    def update_alignment(self, dt: datetime, index: int) -> None:
        if dt < self._alignment_date or index < self._alignment_index:
            # We only care about the most recent report and index.
            # Multiple calls to this method may be made with
            # possibly conflicting data, so we just ignore
            # anything that seems to go backwards in time or index.
            # Saving the newest data is at least likely to be stable
            # over multiple fetches.
            return

        logger.info("Updating alignment based on report observed at index %i", index)

        self._alignment_date = dt
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
        plist: str | Path | dict | bytes | io.BufferedIOBase,
        key_alignment_plist: str | Path | dict | bytes | None = None,
        *,
        name: str | None = None,
    ) -> FindMyAccessory:
        """Create a FindMyAccessory from a .plist file dumped from the FindMy app."""
        device_data = util.files.read_data_plist(plist)

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
            alignment_data = util.files.read_data_plist(key_alignment_plist)

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
    def to_json(self, path: str | Path | io.TextIOBase | None = None, /) -> FindMyAccessoryMapping:
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

        return util.files.save_and_return_json(res, path)

    @classmethod
    @override
    def from_json(
        cls,
        val: str | Path | io.TextIOBase | io.BufferedIOBase | FindMyAccessoryMapping,
        /,
    ) -> FindMyAccessory:
        val = util.files.read_data_json(val)
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

    @override
    def __hash__(self) -> int:
        master = crypto.bytes_to_int(self.master_key)
        skn = crypto.bytes_to_int(self.skn)
        sks = crypto.bytes_to_int(self.sks)
        return hash((master, skn, sks))

    @override
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FindMyAccessory):
            return False

        return (
            self.master_key == other.master_key and self.skn == other.skn and self.sks == other.sks
        )


@dataclass(frozen=True)
class _CacheTier:
    """Configuration for a cache tier."""

    interval: int  # Cache every n'th key
    max_size: int | None  # Maximum number of keys to cache in this tier (None = unlimited)


class _AccessoryKeyGenerator(KeyGenerator[KeyPair]):
    """KeyPair generator. Uses the same algorithm internally as FindMy accessories do."""

    # Define cache tiers: (interval, max_size)
    # Tier 1: Cache every 4th key (1 hour), keep up to 672 keys (2 weeks at 15min intervals)
    # Tier 2: Cache every 672nd key (1 week), unlimited
    _CACHE_TIERS = (
        _CacheTier(interval=4, max_size=672),
        _CacheTier(interval=672, max_size=None),
    )

    def __init__(
        self,
        master_key: bytes,
        initial_sk: bytes,
        key_type: KeyPairType = KeyPairType.UNKNOWN,
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

        # Multi-tier cache: dict + sorted indices per tier
        self._sk_caches: list[dict[int, bytes]] = [{} for _ in self._CACHE_TIERS]
        self._cache_indices: list[list[int]] = [[] for _ in self._CACHE_TIERS]

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
    def key_type(self) -> KeyPairType:
        """The type of key this generator produces."""
        return self._key_type

    def _find_best_cached_sk(self, ind: int) -> tuple[int, bytes]:
        """Find the largest cached index smaller than ind across all tiers."""
        best_ind = 0
        best_sk = self._initial_sk

        for indices, cache in zip(self._cache_indices, self._sk_caches, strict=True):
            if not indices:
                continue

            # Use bisect to find the largest index < ind in O(log n)
            pos = bisect.bisect_left(indices, ind)
            if pos == 0:  # No cached index less than ind
                continue

            cached_ind = indices[pos - 1]
            if cached_ind > best_ind:
                best_ind = cached_ind
                best_sk = cache[cached_ind]

        return best_ind, best_sk

    def _update_caches(self, ind: int, sk: bytes) -> None:
        """Update all applicable cache tiers with the computed key."""
        for tier_idx, tier in enumerate(self._CACHE_TIERS):
            if ind % tier.interval != 0:
                continue

            cache = self._sk_caches[tier_idx]
            indices = self._cache_indices[tier_idx]

            # Add to cache if not already present
            if ind in cache:
                continue
            cache[ind] = sk
            bisect.insort(indices, ind)

            # Evict if cache exceeds size limit
            if tier.max_size is not None and len(cache) > tier.max_size:
                # If adding a historical key, evict smallest index
                # If adding a future key, evict largest
                evict_ind = indices.pop(0 if indices and ind > indices[0] else -1)

                del cache[evict_ind]

    def _get_sk(self, ind: int) -> bytes:
        if ind < 0:
            msg = "The key index must be non-negative"
            raise ValueError(msg)

        # Check all caches for exact match
        for cache in self._sk_caches:
            cached_sk = cache.get(ind)
            if cached_sk is not None:
                return cached_sk

        # Find best starting point across all tiers
        start_ind, cur_sk = self._find_best_cached_sk(ind)

        # Compute from best cached position to target
        for cur_ind in range(start_ind + 1, ind + 1):
            cur_sk = crypto.x963_kdf(cur_sk, b"update", 32)
            self._update_caches(cur_ind, cur_sk)

        return cur_sk

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
        return self

    @override
    def __next__(self) -> KeyPair:
        key = self._get_keypair(self._iter_ind)
        self._iter_ind += 1

        return key

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
