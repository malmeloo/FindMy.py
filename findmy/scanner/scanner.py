"""Airtag scanner."""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from bleak import BleakScanner
from typing_extensions import override

from findmy.accessory import RollingKeyPairSource
from findmy.keys import HasPublicKey

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from _typeshed import SupportsWrite
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData

logger = logging.getLogger(__name__)

APPLE_DEVICE_TYPE = {
    0b00: "Apple Device",
    0b01: "AirTag",
    0b10: "Licensed 3rd Party Find My Device",
    0b11: "AirPods",
}

BATTERY_LEVEL = {0b00: "Full", 0b01: "Medium", 0b10: "Low", 0b11: "Very Low"}


def _print_scanning_results(seen_devices: dict[str, list[OfflineFindingDevice]]) -> None:
    """Print summary of each device seen."""
    # ruff: noqa: T201
    print("================  RESULTS  =========================")
    for mac, devices in seen_devices.items():
        avg_rssi = sum(d.rssi for d in devices if d.rssi is not None) / len(
            [d for d in devices if d.rssi is not None]
        )
        print(f"Device {mac} seen {len(devices)} times, average RSSI: {avg_rssi:.1f}")
        of_type = "nearby" if isinstance(devices[0], NearbyOfflineFindingDevice) else "separated"
        print(
            f"    {devices[0].device_type} with {devices[0].battery_level} battery"
            f" ({of_type} state)"
        )

        if isinstance(devices[0], SeparatedOfflineFindingDevice):
            print(f"    Public key: {devices[0].adv_key_b64}")
            print(f"    Lookup key: {devices[0].hashed_adv_key_b64}")
    print("===============================================")

    device_type_counts: dict[str, int] = {}
    for devs in seen_devices.values():
        dev_type = devs[0].device_type
        device_type_counts[dev_type] = device_type_counts.get(dev_type, 0) + 1

    for dev_type, count in device_type_counts.items():
        print(f"Total {dev_type}: {count}")


class OfflineFindingDevice(ABC):
    """Device discoverable through Apple's bluetooth-based Offline Finding protocol."""

    OF_HEADER_SIZE = 2
    OF_TYPE = 0x12

    def __init__(
        self,
        mac_bytes: bytes,
        status_byte: int,
        detected_at: datetime,
        rssi: int | None = None,
        additional_data: dict[Any, Any] | None = None,
    ) -> None:
        """Instantiate an OfflineFindingDevice."""
        self._mac_bytes: bytes = mac_bytes
        self._status: int = status_byte
        self._detected_at: datetime = detected_at
        self._rssi: int | None = rssi
        self._additional_data: dict[Any, Any] = additional_data or {}

    @property
    def mac_address(self) -> str:
        """MAC address of the device in AA:BB:CC:DD:EE:FF format."""
        mac = self._mac_bytes.hex().upper()
        return ":".join(mac[i : i + 2] for i in range(0, len(mac), 2))

    @property
    def status(self) -> int:
        """Status value as reported by the device."""
        return self._status % 255

    @property
    def detected_at(self) -> datetime:
        """Timezone-aware datetime of when the device was detected."""
        return self._detected_at

    @property
    def rssi(self) -> int | None:
        """Received Signal Strength Indicator (RSSI) value."""
        return self._rssi

    @property
    def additional_data(self) -> dict[Any, Any]:
        """Any additional data. No guarantees about the contents of this dictionary."""
        return self._additional_data

    @property
    def device_type(self) -> str:
        """Get the device type from status byte."""
        type_id = (self.status >> 4) & 0b00000011
        return APPLE_DEVICE_TYPE.get(type_id, "Unknown")

    @property
    def battery_level(self) -> str:
        """Get the battery level from status byte."""
        battery_id = (self.status >> 6) & 0b00000011
        return BATTERY_LEVEL.get(battery_id, "Unknown")

    @abstractmethod
    def is_from(self, other_device: HasPublicKey | RollingKeyPairSource) -> bool:
        """Check whether the OF device's identity originates from a specific key source."""
        raise NotImplementedError

    @abstractmethod
    def print(self, file: SupportsWrite[str] | None = None) -> None:
        """Print human-readable information about the device to stdout or file."""
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def from_payload(
        cls,
        mac_address: str,
        payload: bytes,
        detected_at: datetime,
        rssi: int | None = None,
        additional_data: dict[Any, Any] | None = None,
    ) -> OfflineFindingDevice | None:
        """Get a NearbyOfflineFindingDevice object from an OF message payload."""
        raise NotImplementedError

    @classmethod
    def from_ble_payload(
        cls,
        mac_address: str,
        ble_payload: bytes,
        detected_at: datetime | None = None,
        rssi: int | None = None,
        additional_data: dict[Any, Any] | None = None,
    ) -> OfflineFindingDevice | None:
        """Get a NearbyOfflineFindingDevice object from a BLE packet payload."""
        if len(ble_payload) < cls.OF_HEADER_SIZE:
            logger.error("Not enough bytes to decode: %s", len(ble_payload))
            return None
        if ble_payload[0] != cls.OF_TYPE:
            logger.debug("Unsupported OF type: %s", ble_payload[0])
            return None

        # Differentiate between Nearby and Separated advertisements by payload length
        device_type = next(
            (
                dev
                for dev in _DEVICE_TYPES
                if getattr(dev, "OF_PAYLOAD_LEN", None) == ble_payload[1]
            ),
            None,
        )
        if device_type is None:
            logger.error("Invalid OF payload length: %s", ble_payload[1])
            return None

        return device_type.from_payload(
            mac_address,
            ble_payload[cls.OF_HEADER_SIZE :],
            detected_at or datetime.now().astimezone(),
            rssi,
            additional_data,
        )

    @override
    def __eq__(self, other: object) -> bool:
        if isinstance(other, OfflineFindingDevice):
            return self.mac_address == other.mac_address

        return NotImplemented

    @override
    def __hash__(self) -> int:
        return int.from_bytes(self._mac_bytes, "big")


class NearbyOfflineFindingDevice(OfflineFindingDevice):
    """Offline-Finding device in nearby state."""

    OF_PAYLOAD_LEN = 0x02  # 2 bytes (status, 2 bits of public key/mac address)

    def __init__(  # noqa: PLR0913
        self,
        mac_bytes: bytes,
        status_byte: int,
        first_adv_key_bytes: bytes,
        detected_at: datetime,
        rssi: int | None = None,
        additional_data: dict[Any, Any] | None = None,
    ) -> None:
        """Instantiate a NearbyOfflineFindingDevice."""
        super().__init__(mac_bytes, status_byte, detected_at, rssi, additional_data)
        # When nearby, only the first 6 bytes of the public key are transmitted
        self._first_adv_key_bytes: bytes = first_adv_key_bytes

    @property
    def partial_adv_key(self) -> bytes:
        """Although not a full public key, still identifies device like one."""
        return self._first_adv_key_bytes

    @override
    def is_from(self, other_device: HasPublicKey | RollingKeyPairSource) -> bool:
        """Check whether the OF device's identity originates from a specific key source."""
        if isinstance(other_device, HasPublicKey):
            return other_device.adv_key_bytes.startswith(self._first_adv_key_bytes)
        if isinstance(other_device, RollingKeyPairSource):
            # 12 hour margin around the detected time
            potential_keys = other_device.keys_between(
                self.detected_at - timedelta(hours=12),
                self.detected_at + timedelta(hours=12),
            )
            for ind, key in potential_keys:
                if not self.is_from(key):
                    continue

                # update alignment of found key
                now = datetime.now(tz=timezone.utc)
                other_device.update_alignment(now, ind)

                return True

            return False

        msg = f"Cannot compare against {type(other_device)}"
        raise ValueError(msg)

    @classmethod
    @override
    def from_payload(
        cls,
        mac_address: str,
        payload: bytes,
        detected_at: datetime,
        rssi: int | None = None,
        additional_data: dict[Any, Any] | None = None,
    ) -> NearbyOfflineFindingDevice | None:
        """Get a NearbyOfflineFindingDevice object from an OF message payload."""
        if len(payload) != cls.OF_PAYLOAD_LEN:
            logger.error(
                "Invalid OF data length for NearbyOfflineFindingDevice: %s instead of %s",
                len(payload),
                cls.OF_PAYLOAD_LEN,
            )

        mac_bytes = bytes.fromhex(mac_address.replace(":", "").replace("-", ""))
        status_byte = payload[0]

        pubkey_middle = mac_bytes[1:]
        pubkey_start_ms = payload[1] << 6
        pubkey_start_ls = mac_bytes[0] & 0b00111111
        pubkey_start = (pubkey_start_ms | pubkey_start_ls).to_bytes(1, "big")
        partial_pubkey = pubkey_start + pubkey_middle

        return NearbyOfflineFindingDevice(
            mac_bytes,
            status_byte,
            partial_pubkey,
            detected_at,
            rssi,
            additional_data,
        )

    @override
    def print(self, file: SupportsWrite[str] | None = None) -> None:
        """Print human-readable information about the device to stdout or file."""
        # ruff: noqa: T201
        print(f"Nearby {self.device_type} - {self.mac_address}", file=file)
        print(f"  Status byte:  0x{self.status:x}", file=file)
        print(f"  Battery lvl:  {self.battery_level}", file=file)
        print(f"  RSSI:         {self.rssi}", file=file)
        print("  Extra data:", file=file)
        for k, v in sorted(self.additional_data.items()):
            print(f"    {k:20}: {v}", file=file)
        print("\n", file=file)


class SeparatedOfflineFindingDevice(OfflineFindingDevice, HasPublicKey):
    """Offline-Finding device in separated state."""

    OF_PAYLOAD_LEN = 0x19  # 25 bytes (status, pubkey(22), first 2 bits of MAC/pubkey, hint)

    def __init__(  # noqa: PLR0913
        self,
        mac_bytes: bytes,
        status: int,
        public_key: bytes,
        hint: int,
        detected_at: datetime,
        rssi: int | None = None,
        additional_data: dict[Any, Any] | None = None,
    ) -> None:
        """Initialize a :meth:`SeparatedOfflineFindingDevice`."""
        super().__init__(mac_bytes, status, detected_at, rssi, additional_data)
        self._public_key: bytes = public_key
        self._hint: int = hint

    @property
    def hint(self) -> int:
        """Hint value as reported by the device."""
        return self._hint % 255

    @property
    @override
    def adv_key_bytes(self) -> bytes:
        """See :meth:`HasPublicKey.adv_key_bytes`."""
        return self._public_key

    @override
    def is_from(self, other_device: HasPublicKey | RollingKeyPairSource) -> bool:
        """Check whether the OF device's identity originates from a specific key source."""
        if isinstance(other_device, HasPublicKey):
            return other_device.adv_key_bytes == self.adv_key_bytes
        if isinstance(other_device, RollingKeyPairSource):
            # 12 hour margin around the detected time
            potential_keys = other_device.keys_between(
                self.detected_at - timedelta(hours=12),
                self.detected_at + timedelta(hours=12),
            )
            for ind, key in potential_keys:
                if not self.is_from(key):
                    continue

                # update alignment of found key
                now = datetime.now(tz=timezone.utc)
                other_device.update_alignment(now, ind)

                return True

            return False

        msg = f"Cannot compare against {type(other_device)}"
        raise ValueError(msg)

    @classmethod
    @override
    def from_payload(
        cls,
        mac_address: str,
        payload: bytes,
        detected_at: datetime,
        rssi: int | None = None,
        additional_data: dict[Any, Any] | None = None,
    ) -> SeparatedOfflineFindingDevice | None:
        """Get a SeparatedOfflineFindingDevice object from an OF message payload."""
        if len(payload) != cls.OF_PAYLOAD_LEN:
            logger.error(
                "Invalid OF data length for SeparatedOfflineFindingDevice: %s instead of %s",
                len(payload),
                cls.OF_PAYLOAD_LEN,
            )
            return None

        mac_bytes = bytes.fromhex(mac_address.replace(":", "").replace("-", ""))

        status = payload[0]

        pubkey_end = payload[1:23]
        pubkey_middle = mac_bytes[1:]
        pubkey_start_ms = payload[23] << 6
        pubkey_start_ls = mac_bytes[0] & 0b00111111
        pubkey_start = (pubkey_start_ms | pubkey_start_ls).to_bytes(1, "big")
        pubkey = pubkey_start + pubkey_middle + pubkey_end

        hint = payload[24]

        return SeparatedOfflineFindingDevice(
            mac_bytes,
            status,
            pubkey,
            hint,
            detected_at,
            rssi,
            additional_data,
        )

    @override
    def print(self, file: SupportsWrite[str] | None = None) -> None:
        """Print human-readable information about the device to stdout or file."""
        # ruff: noqa: T201
        print(f"Separated {self.device_type} - {self.mac_address}", file=file)
        print(f"  Public key:   {self.adv_key_b64}", file=file)
        print(f"  Lookup key:   {self.hashed_adv_key_b64}", file=file)
        print(f"  Status byte:  0x{self.status:x}", file=file)
        print(f"  Battery lvl:  {self.battery_level}", file=file)
        print(f"  Hint byte:    0x{self.hint:x}", file=file)
        print(f"  RSSI:         {self.rssi}", file=file)
        print("  Extra data:", file=file)
        for k, v in sorted(self.additional_data.items()):
            print(f"    {k:20}: {v}", file=file)
        print("\n", file=file)

    @override
    def __repr__(self) -> str:
        """Human-readable string representation of an OfflineFindingDevice."""
        return (
            f"OfflineFindingDevice({self.mac_address}, pubkey={self.adv_key_b64},"
            f" status={self.status}, hint={self.hint})"
        )


_DEVICE_TYPES = {
    NearbyOfflineFindingDevice,
    SeparatedOfflineFindingDevice,
}


class OfflineFindingScanner:
    """BLE scanner that searches for :meth:`OfflineFindingDevice`s."""

    _scan_ctrl_lock = asyncio.Lock()

    BLE_COMPANY_APPLE = 0x004C

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        """
        Initialize an instance of the Scanner using an event loop.

        You most likely do not want to use this yourself;
        check out :meth:`OfflineFindingScanner.create` instead.
        """
        self._scanner: BleakScanner = BleakScanner(self._scan_callback, cb={"use_bdaddr": True})

        self._loop = loop
        self._device_fut: asyncio.Future[tuple[BLEDevice, AdvertisementData]] = loop.create_future()

        self._scanner_count: int = 0

    @classmethod
    async def create(cls) -> OfflineFindingScanner:
        """Create an instance of the scanner."""
        loop = asyncio.get_running_loop()
        return cls(loop)

    async def _start_scan(self) -> None:
        async with self._scan_ctrl_lock:
            if self._scanner_count == 0:
                logger.info("Starting BLE scanner")
                await self._scanner.start()
            self._scanner_count += 1

    async def _stop_scan(self) -> None:
        async with self._scan_ctrl_lock:
            self._scanner_count -= 1
            if self._scanner_count == 0:
                logger.info("Stopping BLE scanner")
                await self._scanner.stop()

    async def _scan_callback(
        self,
        device: BLEDevice,
        data: AdvertisementData,
    ) -> None:
        # Ensure that only one waiting coroutine is notified
        if not self._device_fut.done():
            self._device_fut.set_result((device, data))
            self._device_fut = self._loop.create_future()

    async def _wait_for_device(self, timeout: float) -> OfflineFindingDevice | None:
        device, data = await asyncio.wait_for(self._device_fut, timeout=timeout)

        apple_data = data.manufacturer_data.get(self.BLE_COMPANY_APPLE, b"")
        if not apple_data:
            return None

        detected_at = datetime.now().astimezone()

        # Extract RSSI (which may be None)
        rssi = data.rssi

        try:
            additional_data = device.details.get("props", {})
        except AttributeError:
            # Likely Windows host, where details is a '_RawAdvData' object.
            # See: https://github.com/malmeloo/FindMy.py/issues/24
            additional_data = {}
        return OfflineFindingDevice.from_ble_payload(
            device.address,
            apple_data,
            detected_at,
            rssi,
            additional_data,
        )

    async def scan_for(
        self,
        timeout: float = 10,
        *,
        extend_timeout: bool = False,
        print_summary: bool = False,
    ) -> AsyncGenerator[OfflineFindingDevice, None]:
        """
        Scan for :meth:`OfflineFindingDevice`s for up to :meth:`timeout` seconds.

        If :meth:`extend_timeout` is set, the timer will be extended
        by :meth:`timeout` seconds every time a new device is discovered.
        """
        await self._start_scan()

        stop_at = time.time() + timeout
        # Map MAC address to device objects (nearby doesn't send entire pubkey)
        # This avoids double counting when device has different status/hint byte (but same pubkey)
        devices_seen: dict[str, list[OfflineFindingDevice]] = {}

        try:
            time_left = stop_at - time.time()
            while time_left > 0:
                device = await self._wait_for_device(time_left)

                if device is not None:
                    # Check if we have already seen this device
                    new_device = device.mac_address not in devices_seen

                    devices_seen[device.mac_address] = [
                        *devices_seen.get(device.mac_address, []),
                        device,
                    ]

                    if new_device:
                        if extend_timeout:
                            stop_at = time.time() + timeout
                        yield device

                time_left = stop_at - time.time()

        except asyncio.TimeoutError:  # timeout reached
            self._device_fut = self._loop.create_future()
            if print_summary:
                _print_scanning_results(devices_seen)
            return
        finally:
            await self._stop_scan()
