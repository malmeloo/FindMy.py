"""Module providing functionality to look up location reports."""
from __future__ import annotations

import base64
import hashlib
import struct
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Sequence

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from findmy.util import HttpSession

if TYPE_CHECKING:
    from findmy.keys import KeyPair

_session = HttpSession()


class ReportsError(RuntimeError):
    """Raised when an error occurs while looking up reports."""


def _decrypt_payload(payload: bytes, key: KeyPair) -> bytes:
    eph_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP224R1(),
        payload[5:62],
    )
    shared_key = key.dh_exchange(eph_key)
    symmetric_key = hashlib.sha256(
        shared_key + b"\x00\x00\x00\x01" + payload[5:62],
    ).digest()

    decryption_key = symmetric_key[:16]
    iv = symmetric_key[16:]
    enc_data = payload[62:72]
    tag = payload[72:]

    decryptor = Cipher(
        algorithms.AES(decryption_key),
        modes.GCM(iv, tag),
        default_backend(),
    ).decryptor()
    return decryptor.update(enc_data) + decryptor.finalize()


class KeyReport:
    """Location report corresponding to a certain `KeyPair`."""

    def __init__(  # noqa: PLR0913
        self,
        key: KeyPair,
        publish_date: datetime,
        timestamp: datetime,
        description: str,
        lat: float,
        lng: float,
        confidence: int,
        status: int,
    ) -> None:
        """Initialize a `KeyReport`. You should probably use `KeyReport.from_payload` instead."""
        self._key = key
        self._publish_date = publish_date
        self._timestamp = timestamp
        self._description = description

        self._lat = lat
        self._lng = lng
        self._confidence = confidence

        self._status = status

    @property
    def key(self) -> KeyPair:
        """The `KeyPair` corresponding to this location report."""
        return self._key

    @property
    def published_at(self) -> datetime:
        """The `datetime` when this report was published by a device."""
        return self._publish_date

    @property
    def timestamp(self) -> datetime:
        """The `datetime` when this report was recorded by a device."""
        return self._timestamp

    @property
    def description(self) -> str:
        """Description of the location report as published by Apple."""
        return self._description

    @property
    def latitude(self) -> float:
        """Latitude of the location of this report."""
        return self._lat

    @property
    def longitude(self) -> float:
        """Longitude of the location of this report."""
        return self._lng

    @property
    def confidence(self) -> int:
        """Confidence of the location of this report."""
        return self._confidence

    @property
    def status(self) -> int:
        """Status byte of the accessory as recorded by a device, as an integer."""
        return self._status

    @classmethod
    def from_payload(
        cls,
        key: KeyPair,
        publish_date: datetime,
        description: str,
        payload: bytes,
    ) -> KeyReport:
        """
        Create a `KeyReport` from fields and a payload as reported by Apple.

        Requires a `KeyPair` to decrypt the report's payload.
        """
        timestamp_int = int.from_bytes(payload[0:4], "big") + (60 * 60 * 24 * 11323)
        timestamp = datetime.fromtimestamp(timestamp_int, tz=timezone.utc)

        data = _decrypt_payload(payload, key)
        latitude = struct.unpack(">i", data[0:4])[0] / 10000000
        longitude = struct.unpack(">i", data[4:8])[0] / 10000000
        confidence = int.from_bytes(data[8:9], "big")
        status = int.from_bytes(data[9:10], "big")

        return KeyReport(
            key,
            publish_date,
            timestamp,
            description,
            latitude,
            longitude,
            confidence,
            status,
        )

    def __lt__(self, other: KeyReport) -> bool:
        """
        Compare against another `KeyReport`.

        A `KeyReport` is said to be "less than" another `KeyReport` iff its recorded
        timestamp is strictly less than the other report.
        """
        if isinstance(other, KeyReport):
            return self.timestamp < other.timestamp
        return NotImplemented

    def __repr__(self) -> str:
        """Human-readable string representation of the location report."""
        return (
            f"<KeyReport(key={self._key.hashed_adv_key_b64}, timestamp={self._timestamp},"
            f" lat={self._lat}, lng={self._lng})>"
        )


async def fetch_reports(  # noqa: PLR0913
    dsid: str,
    search_party_token: str,
    anisette_headers: dict[str, str],
    date_from: datetime,
    date_to: datetime,
    keys: Sequence[KeyPair],
) -> dict[KeyPair, list[KeyReport]]:
    """Look up reports for given `KeyPair`s."""
    start_date = date_from.timestamp() * 1000
    end_date = date_to.timestamp() * 1000
    ids = [key.hashed_adv_key_b64 for key in keys]
    data = {"search": [{"startDate": start_date, "endDate": end_date, "ids": ids}]}

    # TODO(malmeloo): do not create a new session every time
    # https://github.com/malmeloo/FindMy.py/issues/3
    r = await _session.post(
        "https://gateway.icloud.com/acsnservice/fetch",
        auth=(dsid, search_party_token),
        headers=anisette_headers,
        json=data,
    )
    resp = r.json()
    if not r.ok or resp["statusCode"] != "200":
        msg = f"Failed to fetch reports: {resp['statusCode']}"
        raise ReportsError(msg)
    await _session.close()

    reports: dict[KeyPair, list[KeyReport]] = {key: [] for key in keys}
    id_to_key: dict[str, KeyPair] = {key.hashed_adv_key_b64: key for key in keys}

    for report in resp.get("results", []):
        key = id_to_key[report["id"]]
        date_published = datetime.fromtimestamp(
            report.get("datePublished", 0) / 1000,
            tz=timezone.utc,
        )
        description = report.get("description", "")
        payload = base64.b64decode(report["payload"])

        r = KeyReport.from_payload(key, date_published, description, payload)
        reports[key].append(r)

    return {key: sorted(reps) for key, reps in reports.items()}
