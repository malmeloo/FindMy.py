import base64
import hashlib
import struct
from datetime import datetime
from typing import Sequence

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .keys import KeyPair
from .http import HttpSession

_session = HttpSession()


class ReportsError(RuntimeError):
    pass


def _decrypt_payload(payload: bytes, key: KeyPair) -> bytes:
    eph_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP224R1(), payload[5:62]
    )
    shared_key = key.dh_exchange(eph_key)
    symmetric_key = hashlib.sha256(
        shared_key + b"\x00\x00\x00\x01" + payload[5:62]
    ).digest()

    decryption_key = symmetric_key[:16]
    iv = symmetric_key[16:]
    enc_data = payload[62:72]
    tag = payload[72:]

    decryptor = Cipher(
        algorithms.AES(decryption_key), modes.GCM(iv, tag), default_backend()
    ).decryptor()
    return decryptor.update(enc_data) + decryptor.finalize()


class KeyReport:
    def __init__(
        self,
        key: KeyPair,
        publish_date: datetime,
        timestamp: datetime,
        description: str,
        lat: float,
        lng: float,
        confidence: int,
        status: int,
    ):
        self._key = key
        self._publish_date = publish_date
        self._timestamp = timestamp
        self._description = description

        self._lat = lat
        self._lng = lng
        self._confidence = confidence

        self._status = status

    @property
    def key(self):
        return self._key

    @property
    def published_at(self):
        return self._publish_date

    @property
    def timestamp(self):
        return self._timestamp

    @property
    def description(self):
        return self._description

    @property
    def latitude(self):
        return self._lat

    @property
    def longitude(self):
        return self._lng

    @property
    def confidence(self):
        return self._confidence

    @property
    def status(self):
        return self._status

    @classmethod
    def from_payload(
        cls, key: KeyPair, publish_date: datetime, description: str, payload: bytes
    ) -> "KeyReport":
        timestamp_int = int.from_bytes(payload[0:4], "big") + (60 * 60 * 24 * 11323)
        timestamp = datetime.utcfromtimestamp(timestamp_int)

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

    def __lt__(self, other):
        if isinstance(other, KeyReport):
            return self.timestamp < other.timestamp
        return NotImplemented

    def __repr__(self):
        return (
            f"<KeyReport(key={self._key.hashed_adv_key_b64}, timestamp={self._timestamp},"
            f" lat={self._lat}, lng={self._lng})>"
        )


async def fetch_reports(
    dsid: str,
    search_party_token: str,
    anisette_headers: dict[str, str],
    date_from: datetime,
    date_to: datetime,
    keys: Sequence[KeyPair],
):
    start_date = date_from.timestamp() * 1000
    end_date = date_to.timestamp() * 1000
    ids = [key.hashed_adv_key_b64 for key in keys]
    data = {"search": [{"startDate": start_date, "endDate": end_date, "ids": ids}]}

    # TODO: do not create a new session every time
    # probably needs a wrapper class to allow closing the connections
    async with await _session.post(
        "https://gateway.icloud.com/acsnservice/fetch",
        auth=(dsid, search_party_token),
        headers=anisette_headers,
        json=data,
    ) as r:
        resp = await r.json()
        if not r.ok or resp["statusCode"] != "200":
            raise ReportsError(f"Failed to fetch reports: {resp['statusCode']}")
    await _session.close()

    reports: dict[KeyPair, list[KeyReport]] = {key: [] for key in keys}
    id_to_key: dict[str, KeyPair] = {key.hashed_adv_key_b64: key for key in keys}

    for report in resp.get("results", []):
        key = id_to_key[report["id"]]
        date_published = datetime.utcfromtimestamp(
            report.get("datePublished", 0) / 1000
        )
        description = report.get("description", "")
        payload = base64.b64decode(report["payload"])

        report = KeyReport.from_payload(key, date_published, description, payload)
        reports[key].append(report)

    return {key: sorted(reps) for key, reps in reports.items()}
