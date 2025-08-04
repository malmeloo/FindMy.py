"""Module providing functionality to look up location reports."""

from __future__ import annotations

import base64
import hashlib
import logging
import struct
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Literal, TypedDict, Union, cast, overload

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing_extensions import override

from findmy.accessory import RollingKeyPairSource
from findmy.keys import HasHashedPublicKey, KeyPair, KeyPairMapping
from findmy.util.abc import Serializable
from findmy.util.files import read_data_json, save_and_return_json

if TYPE_CHECKING:
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


LocationReportMapping = Union[LocationReportEncryptedMapping, LocationReportDecryptedMapping]


class LocationReport(HasHashedPublicKey, Serializable[LocationReportMapping]):
    """Location report corresponding to a certain `HasHashedPublicKey`."""

    def __init__(
        self,
        payload: bytes,
        hashed_adv_key: bytes,
    ) -> None:
        """Initialize a `KeyReport`. You should probably use `KeyReport.from_payload` instead."""
        self._payload: bytes = payload
        self._hashed_adv_key: bytes = hashed_adv_key

        self._decrypted_data: tuple[KeyPair, bytes] | None = None

    @property
    @override
    def hashed_adv_key_bytes(self) -> bytes:
        """See `HasHashedPublicKey.hashed_adv_key_bytes`."""
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
        """Decrypt the report using its corresponding `KeyPair`."""
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
        """The `datetime` when this report was recorded by a device."""
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
        dst: str | Path | None = None,
        /,
        *,
        include_key: Literal[True],
    ) -> LocationReportEncryptedMapping:
        pass

    @overload
    def to_json(
        self,
        dst: str | Path | None = None,
        /,
        *,
        include_key: Literal[False],
    ) -> LocationReportDecryptedMapping:
        pass

    @overload
    def to_json(
        self,
        dst: str | Path | None = None,
        /,
        *,
        include_key: None = None,
    ) -> LocationReportMapping:
        pass

    @override
    def to_json(
        self,
        dst: str | Path | None = None,
        /,
        *,
        include_key: bool | None = None,
    ) -> LocationReportMapping:
        if include_key is None:
            include_key = self.is_decrypted

        if include_key:
            return save_and_return_json(
                {
                    "type": "locReportDecrypted",
                    "payload": base64.b64encode(self._payload).decode("utf-8"),
                    "hashed_adv_key": base64.b64encode(self._hashed_adv_key).decode("utf-8"),
                    "key": self.key.to_json(),
                },
                dst,
            )
        return save_and_return_json(
            {
                "type": "locReportEncrypted",
                "payload": base64.b64encode(self._payload).decode("utf-8"),
                "hashed_adv_key": base64.b64encode(self._hashed_adv_key).decode("utf-8"),
            },
            dst,
        )

    @classmethod
    @override
    def from_json(cls, val: str | Path | LocationReportMapping, /) -> LocationReport:
        val = read_data_json(val)
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
        Compare against another `KeyReport`.

        A `KeyReport` is said to be "less than" another `KeyReport` iff its recorded
        timestamp is strictly less than the other report.
        """
        if isinstance(other, LocationReport):
            return self.timestamp < other.timestamp
        return NotImplemented

    @override
    def __repr__(self) -> str:
        """Human-readable string representation of the location report."""
        msg = f"KeyReport(hashed_adv_key={self.hashed_adv_key_b64}, timestamp={self.timestamp}"
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
    async def fetch_reports(
        self,
        date_from: datetime,
        date_to: datetime,
        device: HasHashedPublicKey,
    ) -> list[LocationReport]: ...

    @overload
    async def fetch_reports(
        self,
        date_from: datetime,
        date_to: datetime,
        device: RollingKeyPairSource,
    ) -> list[LocationReport]: ...

    @overload
    async def fetch_reports(
        self,
        date_from: datetime,
        date_to: datetime,
        device: Sequence[HasHashedPublicKey | RollingKeyPairSource],
    ) -> dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]: ...

    async def fetch_reports(  # noqa: C901
        self,
        date_from: datetime,
        date_to: datetime,
        device: HasHashedPublicKey
        | RollingKeyPairSource
        | Sequence[HasHashedPublicKey | RollingKeyPairSource],
    ) -> (
        list[LocationReport] | dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]
    ):
        """
        Fetch location reports for a certain device.

        When ``device`` is a single :class:`.HasHashedPublicKey`, this method will return
        a list of location reports corresponding to that key.
        When ``device`` is a :class:`.RollingKeyPairSource`, it will return a list of
        location reports corresponding to that source.
        When ``device`` is a sequence of :class:`.HasHashedPublicKey`s or RollingKeyPairSource's,
        it will return a dictionary with the :class:`.HasHashedPublicKey` or `.RollingKeyPairSource`
        as key, and a list of location reports as value.
        """
        key_devs: dict[HasHashedPublicKey, HasHashedPublicKey | RollingKeyPairSource] = {}
        key_batches: list[list[HasHashedPublicKey]] = []
        if isinstance(device, HasHashedPublicKey):
            # single key
            key_devs = {device: device}
            key_batches.append([device])
        elif isinstance(device, RollingKeyPairSource):
            # key generator
            #   add 12h margin to the generator
            keys = device.keys_between(
                date_from - timedelta(hours=12),
                date_to + timedelta(hours=12),
            )
            key_devs = dict.fromkeys(keys, device)
            key_batches.append(list(keys))
        elif isinstance(device, list) and all(
            isinstance(x, HasHashedPublicKey | RollingKeyPairSource) for x in device
        ):
            # multiple key generators
            #   add 12h margin to each generator
            device = cast("list[HasHashedPublicKey | RollingKeyPairSource]", device)
            for dev in device:
                if isinstance(dev, HasHashedPublicKey):
                    key_devs[dev] = dev
                    key_batches.append([dev])
                elif isinstance(dev, RollingKeyPairSource):
                    keys = dev.keys_between(
                        date_from - timedelta(hours=12),
                        date_to + timedelta(hours=12),
                    )
                    for key in keys:
                        key_devs[key] = dev
                    key_batches.append(list(keys))
        else:
            msg = "Unknown device type: %s"
            raise ValueError(msg, type(device))

        # sequence of keys (fetch 256 max at a time)
        key_reports: dict[HasHashedPublicKey, list[LocationReport]] = await self._fetch_reports(
            date_from,
            date_to,
            key_batches,
        )

        # combine (key -> list[report]) and (key -> device) into (device -> list[report])
        device_reports = defaultdict(list)
        for key, reports in key_reports.items():
            device_reports[key_devs[key]].extend(reports)
        for dev in device_reports:
            device_reports[dev] = sorted(device_reports[dev])

        # result
        if isinstance(device, (HasHashedPublicKey, RollingKeyPairSource)):
            # single key or generator
            return device_reports[device]
        # multiple static keys or key generators
        return device_reports

    async def _fetch_reports(
        self,
        date_from: datetime,
        date_to: datetime,
        device_keys: Sequence[Sequence[HasHashedPublicKey]],
    ) -> dict[HasHashedPublicKey, list[LocationReport]]:
        logger.debug("Fetching reports for %s device(s)", len(device_keys))

        # lock requested time range to the past 7 days, +- 12 hours, then filter the response.
        # this is due to an Apple backend bug where the time range is not respected.
        # More info: https://github.com/biemster/FindMy/issues/7
        now = datetime.now().astimezone()
        start_date = now - timedelta(days=7, hours=12)
        end_date = now + timedelta(hours=12)
        ids = [[key.hashed_adv_key_b64 for key in keys] for keys in device_keys]
        data = await self._account.fetch_raw_reports(start_date, end_date, ids)

        id_to_key: dict[bytes, HasHashedPublicKey] = {
            key.hashed_adv_key_bytes: key for keys in device_keys for key in keys
        }
        reports: dict[HasHashedPublicKey, list[LocationReport]] = defaultdict(list)
        for key_reports in data.get("locationPayload", []):
            hashed_adv_key_bytes = base64.b64decode(key_reports["id"])
            key = id_to_key[hashed_adv_key_bytes]

            for report in key_reports.get("locationInfo", []):
                payload = base64.b64decode(report)
                loc_report = LocationReport(payload, hashed_adv_key_bytes)

                if loc_report.timestamp < date_from or loc_report.timestamp > date_to:
                    continue

                # pre-decrypt if possible
                if isinstance(key, KeyPair):
                    loc_report.decrypt(key)

                reports[key].append(loc_report)

        return reports
