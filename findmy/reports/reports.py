"""Module providing functionality to look up location reports."""

from __future__ import annotations

import base64
import bisect
import hashlib
import logging
import struct
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Literal, TypedDict, overload

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing_extensions import override

from findmy import util
from findmy.accessory import RollingKeyPairSource
from findmy.errors import EmptyResponseError
from findmy.keys import HasHashedPublicKey, KeyPair, KeyPairMapping, KeyPairType

if TYPE_CHECKING:
    import io
    from collections.abc import Sequence
    from pathlib import Path

    from .account import AsyncAppleAccount

logger = logging.getLogger(__name__)


class LocationReportEncryptedMapping(TypedDict):
    """JSON mapping representing an encrypted location report."""

    type: Literal["locReportEncrypted"]

    payload: str
    hashed_adv_key: str


class LocationReportDecryptedMapping(TypedDict):
    """JSON mapping representing a decrypted location report."""

    type: Literal["locReportDecrypted"]

    payload: str
    hashed_adv_key: str
    key: KeyPairMapping


LocationReportMapping = LocationReportEncryptedMapping | LocationReportDecryptedMapping


class LocationReport(HasHashedPublicKey, util.abc.Serializable[LocationReportMapping]):
    """Location report corresponding to a certain :meth:`HasHashedPublicKey`."""

    def __init__(
        self,
        payload: bytes,
        hashed_adv_key: bytes,
    ) -> None:
        """
        Initialize a :class:`LocationReport`.

        You should probably use :meth:`LocationReport.from_payload` instead.
        """
        self._payload: bytes = payload
        self._hashed_adv_key: bytes = hashed_adv_key

        self._decrypted_data: tuple[KeyPair, bytes] | None = None

    @property
    @override
    def hashed_adv_key_bytes(self) -> bytes:
        """See :meth:`HasHashedPublicKey.hashed_adv_key_bytes`."""
        return self._hashed_adv_key

    @property
    def key(self) -> KeyPair:
        """`KeyPair` using which this report was decrypted."""
        if not self.is_decrypted:
            msg = "Full key is unavailable while the report is encrypted."
            raise RuntimeError(msg)
        assert self._decrypted_data is not None

        return self._decrypted_data[0]

    @property
    def payload(self) -> bytes:
        """Full (partially encrypted) payload of the report, as retrieved from Apple."""
        return self._payload

    @property
    def is_decrypted(self) -> bool:
        """Whether the report is currently decrypted."""
        return self._decrypted_data is not None

    def can_decrypt(self, key: KeyPair, /) -> bool:
        """Whether the report can be decrypted using the given key."""
        return key.hashed_adv_key_bytes == self._hashed_adv_key

    def decrypt(self, key: KeyPair) -> None:
        """Decrypt the report using its corresponding :meth:`KeyPair`."""
        if not self.can_decrypt(key):
            msg = "Cannot decrypt with this key!"
            raise ValueError(msg)

        if self.is_decrypted:
            return

        encrypted_data = self._payload[4:]

        # Fix decryption for new report format via MacOS 14+
        # See: https://github.com/MatthewKuKanich/FindMyFlipper/issues/61#issuecomment-2065003410
        if len(encrypted_data) == 85:
            encrypted_data = encrypted_data[1:]

        eph_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP224R1(),
            encrypted_data[1:58],
        )
        shared_key = key.dh_exchange(eph_key)
        symmetric_key = hashlib.sha256(
            shared_key + b"\x00\x00\x00\x01" + encrypted_data[1:58],
        ).digest()

        decryption_key = symmetric_key[:16]
        iv = symmetric_key[16:]
        enc_data = encrypted_data[58:68]
        tag = encrypted_data[68:]

        decryptor = Cipher(
            algorithms.AES(decryption_key),
            modes.GCM(iv, tag),
            default_backend(),
        ).decryptor()
        decrypted_payload = decryptor.update(enc_data) + decryptor.finalize()

        self._decrypted_data = (key, decrypted_payload)

    @property
    def timestamp(self) -> datetime:
        """The :meth:`datetime` when this report was recorded by a device."""
        timestamp_int = int.from_bytes(self._payload[0:4], "big") + (60 * 60 * 24 * 11323)
        return datetime.fromtimestamp(timestamp_int, tz=timezone.utc).astimezone()

    @property
    def confidence(self) -> int:
        """Confidence of the location of this report. Int between 1 and 3."""
        # If the payload length is 88, the confidence is the 5th byte, otherwise it's the 6th byte
        if len(self._payload) == 88:
            return self._payload[4]
        return self._payload[5]

    @property
    def latitude(self) -> float:
        """Latitude of the location of this report."""
        if not self.is_decrypted:
            msg = "Latitude is unavailable while the report is encrypted."
            raise RuntimeError(msg)
        assert self._decrypted_data is not None

        lat_bytes = self._decrypted_data[1][:4]
        return struct.unpack(">i", lat_bytes)[0] / 10000000

    @property
    def longitude(self) -> float:
        """Longitude of the location of this report."""
        if not self.is_decrypted:
            msg = "Longitude is unavailable while the report is encrypted."
            raise RuntimeError(msg)
        assert self._decrypted_data is not None

        lon_bytes = self._decrypted_data[1][4:8]
        return struct.unpack(">i", lon_bytes)[0] / 10000000

    @property
    def horizontal_accuracy(self) -> int:
        """Horizontal accuracy of the location of this report."""
        if not self.is_decrypted:
            msg = "Horizontal accuracy is unavailable while the report is encrypted."
            raise RuntimeError(msg)
        assert self._decrypted_data is not None

        conf_bytes = self._decrypted_data[1][8:9]
        return int.from_bytes(conf_bytes, "big")

    @property
    def status(self) -> int:
        """Status byte of the accessory as recorded by a device, as an integer."""
        if not self.is_decrypted:
            msg = "Status byte is unavailable while the report is encrypted."
            raise RuntimeError(msg)
        assert self._decrypted_data is not None

        status_bytes = self._decrypted_data[1][9:10]
        return int.from_bytes(status_bytes, "big")

    @overload
    def to_json(
        self,
        dst: str | Path | io.TextIOBase | None = None,
        /,
        *,
        include_key: Literal[True],
    ) -> LocationReportEncryptedMapping:
        pass

    @overload
    def to_json(
        self,
        dst: str | Path | io.TextIOBase | None = None,
        /,
        *,
        include_key: Literal[False],
    ) -> LocationReportDecryptedMapping:
        pass

    @overload
    def to_json(
        self,
        dst: str | Path | io.TextIOBase | None = None,
        /,
        *,
        include_key: None = None,
    ) -> LocationReportMapping:
        pass

    @override
    def to_json(
        self,
        dst: str | Path | io.TextIOBase | None = None,
        /,
        *,
        include_key: bool | None = None,
    ) -> LocationReportMapping:
        if include_key is None:
            include_key = self.is_decrypted

        if include_key:
            return util.files.save_and_return_json(
                {
                    "type": "locReportDecrypted",
                    "payload": base64.b64encode(self._payload).decode("utf-8"),
                    "hashed_adv_key": base64.b64encode(self._hashed_adv_key).decode("utf-8"),
                    "key": self.key.to_json(),
                },
                dst,
            )
        return util.files.save_and_return_json(
            {
                "type": "locReportEncrypted",
                "payload": base64.b64encode(self._payload).decode("utf-8"),
                "hashed_adv_key": base64.b64encode(self._hashed_adv_key).decode("utf-8"),
            },
            dst,
        )

    @classmethod
    @override
    def from_json(
        cls, val: str | Path | io.TextIOBase | io.BufferedIOBase | LocationReportMapping, /
    ) -> LocationReport:
        val = util.files.read_data_json(val)
        assert val["type"] == "locReportEncrypted" or val["type"] == "locReportDecrypted"

        try:
            report = cls(
                payload=base64.b64decode(val["payload"]),
                hashed_adv_key=base64.b64decode(val["hashed_adv_key"]),
            )
            if val["type"] == "locReportDecrypted":
                key = KeyPair.from_json(val["key"])
                report.decrypt(key)
        except KeyError as e:
            msg = f"Failed to restore account data: {e}"
            raise ValueError(msg) from None
        else:
            return report

    @override
    def __eq__(self, other: object) -> bool:
        """
        Compare two report instances.

        Two reports are considered equal iff they correspond to the same key,
        were reported at the same timestamp and represent the same physical location.
        """
        if not isinstance(other, LocationReport):
            return NotImplemented

        return (
            super().__eq__(other)
            and self.timestamp == other.timestamp
            and self.latitude == other.latitude
            and self.longitude == other.longitude
        )

    @override
    def __hash__(self) -> int:
        """
        Get the hash of this instance.

        Two instances will have the same hash iff they correspond to the same key,
        were reported at the same timestamp and represent the same physical location.
        """
        return hash((self.hashed_adv_key_bytes, self.timestamp, self.latitude, self.longitude))

    def __lt__(self, other: LocationReport) -> bool:
        """
        Compare against another :meth:`LocationReport`.

        A :meth:`LocationReport` is said to be "less than" another :meth:`LocationReport` iff
        its recorded timestamp is strictly less than the other report.
        """
        if isinstance(other, LocationReport):
            return self.timestamp < other.timestamp
        return NotImplemented

    @override
    def __repr__(self) -> str:
        """Human-readable string representation of the location report."""
        msg = f"LocationReport(hashed_adv_key={self.hashed_adv_key_b64}, timestamp={self.timestamp}"
        if self.is_decrypted:
            msg += f", lat={self.latitude}, lon={self.longitude}"
        msg += ")"
        return msg


class LocationReportsFetcher:
    """Fetcher class to retrieve location reports."""

    def __init__(self, account: AsyncAppleAccount) -> None:
        """
        Initialize the fetcher.

        :param account: Apple account.
        """
        self._account: AsyncAppleAccount = account

    @overload
    async def fetch_location_history(
        self,
        device: HasHashedPublicKey,
    ) -> list[LocationReport]: ...

    @overload
    async def fetch_location_history(
        self,
        device: RollingKeyPairSource,
    ) -> list[LocationReport]: ...

    @overload
    async def fetch_location_history(
        self,
        device: Sequence[HasHashedPublicKey | RollingKeyPairSource],
    ) -> dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]: ...

    async def fetch_location_history(
        self,
        device: HasHashedPublicKey
        | RollingKeyPairSource
        | Sequence[HasHashedPublicKey | RollingKeyPairSource],
    ) -> (
        list[LocationReport] | dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]
    ):
        """
        Fetch location history for a certain device or multiple devices.

        When `device` is a single :class:`HasHashedPublicKey`, this method will return
        a list of location reports corresponding to that key.
        When `device` is a :class:`RollingKeyPairSource`, it will return a list of location
        reports corresponding to that source.
        When `device` is a sequence of :class:`HasHashedPublicKey`s or RollingKeyPairSource's,
        it will return a dictionary with the provided objects
        as keys, and a list of location reports as value.

        Note that the location history of :class:`RollingKeyPairSource` devices is not guaranteed
        to be complete, and may be missing certain historical reports. The most recent report is
        however guaranteed to be in line with what Apple reports.
        """
        if isinstance(device, HasHashedPublicKey):
            # single key
            key_reports = await self._fetch_key_reports([device])
            return key_reports.get(device, [])

        if isinstance(device, RollingKeyPairSource):
            # key generator
            return await self._fetch_accessory_reports(device, only_latest=True)

        if not isinstance(device, list) or not all(
            isinstance(x, HasHashedPublicKey | RollingKeyPairSource) for x in device
        ):
            # unsupported type
            msg = "Device must be a HasHashedPublicKey, RollingKeyPairSource, or list thereof."
            raise ValueError(msg)

        # multiple key generators
        #   we can batch static keys in a single request,
        #   but key generators need to be queried separately
        static_keys: list[HasHashedPublicKey] = []
        reports: dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]] = {
            dev: [] for dev in device
        }
        for dev in device:
            if isinstance(dev, HasHashedPublicKey):
                # save for later batch request
                static_keys.append(dev)
            elif isinstance(dev, RollingKeyPairSource):
                # query immediately
                reports[dev] = await self._fetch_accessory_reports(dev, only_latest=True)

        if static_keys:  # batch request for static keys
            key_reports = await self._fetch_key_reports(static_keys)
            reports.update(dict(key_reports.items()))

        return reports

    async def _fetch_accessory_reports(  # noqa: C901
        self,
        accessory: RollingKeyPairSource,
        only_latest: bool = False,
    ) -> list[LocationReport]:
        logger.debug("Fetching location report for accessory")

        now = datetime.now().astimezone()
        start_date = now - timedelta(days=7)
        end_date = now

        # mappings
        key_to_ind: dict[KeyPair, set[int]] = defaultdict(set)
        id_to_key: dict[bytes, KeyPair] = {}

        # state variables
        cur_keys_primary: set[str] = set()
        cur_keys_secondary: set[str] = set()
        cur_index = accessory.get_max_index(end_date)
        ret: set[LocationReport] = set()

        async def _fetch() -> set[LocationReport]:
            """Fetch current keys and add them to final reports."""
            new_reports: list[LocationReport] = await self._account.fetch_raw_reports(
                [(list(cur_keys_primary), (list(cur_keys_secondary)))]
            )
            logger.info("Fetched %d new reports (index %i)", len(new_reports), cur_index)

            for report in new_reports:
                key = id_to_key[report.hashed_adv_key_bytes]
                report.decrypt(key)

                # update alignment data on every report
                # iterate in reverse sorted order to prevent potentially
                # excessive internal updates and logging in the accessory,
                # because most accessories probably only really care about
                # the latest index anyway.
                for i in sorted(key_to_ind[key], reverse=True):
                    accessory.update_alignment(report.timestamp, i)

            cur_keys_primary.clear()
            cur_keys_secondary.clear()

            return set(new_reports)

        while cur_index >= accessory.get_min_index(start_date):
            key_batch = accessory.keys_at(cur_index)

            # split into primary and secondary keys
            # (UNKNOWN keys are filed as primary)
            new_keys_primary: set[str] = {
                key.hashed_adv_key_b64 for key in key_batch if key.key_type == KeyPairType.PRIMARY
            }
            new_keys_secondary: set[str] = {
                key.hashed_adv_key_b64 for key in key_batch if key.key_type != KeyPairType.PRIMARY
            }

            # 290 seems to be the maximum number of keys that Apple accepts in a single request,
            # so if adding the new keys would exceed that, fire a request first
            if (
                len(cur_keys_primary | new_keys_primary) > 290
                or len(cur_keys_secondary | new_keys_secondary) > 290
            ):
                try:
                    ret |= await _fetch()
                except EmptyResponseError:
                    return []

                # if we only want the latest report, we can stop here
                # since we are iterating backwards in time
                if only_latest and ret:
                    return sorted(ret)

            # build mappings before adding to current keys
            for key in key_batch:
                key_to_ind[key].add(cur_index)
                id_to_key[key.hashed_adv_key_bytes] = key
            cur_keys_primary |= new_keys_primary
            cur_keys_secondary |= new_keys_secondary

            cur_index -= 1

        if cur_keys_primary or cur_keys_secondary:
            # fetch remaining keys
            try:
                ret |= await _fetch()
            except EmptyResponseError:
                return []

        return sorted(ret)

    async def _fetch_key_reports(
        self,
        keys: Sequence[HasHashedPublicKey],
    ) -> dict[HasHashedPublicKey, list[LocationReport]]:
        logger.debug("Fetching reports for %s key(s)", len(keys))

        # fetch all as primary keys
        ids = [([key.hashed_adv_key_b64], []) for key in keys]
        try:
            encrypted_reports: list[LocationReport] = await self._account.fetch_raw_reports(ids)
        except EmptyResponseError:
            encrypted_reports = []

        id_to_key: dict[bytes, HasHashedPublicKey] = {key.hashed_adv_key_bytes: key for key in keys}
        reports: dict[HasHashedPublicKey, list[LocationReport]] = {key: [] for key in keys}
        for report in encrypted_reports:
            key = id_to_key[report.hashed_adv_key_bytes]
            bisect.insort(reports[key], report)

            # pre-decrypt report if possible
            if isinstance(key, KeyPair):
                report.decrypt(key)

        return reports
