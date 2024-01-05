"""Airtag scanner."""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, AsyncGenerator

import bleak

from findmy.keys import HasPublicKey

logging.getLogger(__name__)


class OfflineFindingDevice(HasPublicKey):
    """Device discoverable through Apple's bluetooth-based Offline Finding protocol."""

    OF_HEADER_SIZE = 2
    OF_TYPE = 0x12
    OF_DATA_LEN = 25

    def __init__(  # noqa: PLR0913
        self,
        mac_bytes: bytes,
        status: int,
        public_key: bytes,
        hint: int,
        additional_data: dict[Any, Any] | None = None,
    ) -> None:
        """Initialize an `OfflineFindingDevice`."""
        self._mac_bytes: bytes = mac_bytes
        self._status: int = status
        self._public_key: bytes = public_key
        self._hint: int = hint

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
    def hint(self) -> int:
        """Hint value as reported by the device."""
        return self._hint % 255

    @property
    def additional_data(self) -> dict[Any, Any]:
        """Any additional data. No guarantees about the contents of this dictionary."""
        return self._additional_data

    @property
    def adv_key_bytes(self) -> bytes:
        """See `HasPublicKey.adv_key_bytes`."""
        return self._public_key

    @classmethod
    def from_payload(
        cls,
        mac_address: str,
        payload: bytes,
        additional_data: dict[Any, Any],
    ) -> OfflineFindingDevice | None:
        """Get an OfflineFindingDevice object from a BLE payload."""
        if len(payload) < cls.OF_HEADER_SIZE:
            logging.error("Not enough bytes to decode: %s", len(payload))
            return None
        if payload[0] != cls.OF_TYPE:
            logging.debug("Unsupported OF type: %s", payload[0])
            return None
        if payload[1] != cls.OF_DATA_LEN:
            logging.debug("Unknown OF data length: %s", payload[1])
            return None
        if len(payload) != cls.OF_HEADER_SIZE + cls.OF_DATA_LEN:
            logging.debug(
                "Invalid OF data length: %s instead of %s",
                len(payload) - cls.OF_HEADER_SIZE,
                payload[1],
            )
            return None

        mac_bytes = bytes.fromhex(mac_address.replace(":", "").replace("-", ""))

        status = payload[cls.OF_HEADER_SIZE + 0]

        pubkey_end = payload[cls.OF_HEADER_SIZE + 1 : cls.OF_HEADER_SIZE + 23]
        pubkey_middle = mac_bytes[1:]
        pubkey_start_ms = payload[cls.OF_HEADER_SIZE + 23] << 6
        pubkey_start_ls = mac_bytes[0] & 0b00111111
        pubkey_start = (pubkey_start_ms | pubkey_start_ls).to_bytes(1, "big")
        pubkey = pubkey_start + pubkey_middle + pubkey_end

        hint = payload[cls.OF_HEADER_SIZE + 24]

        return OfflineFindingDevice(mac_bytes, status, pubkey, hint, additional_data)

    def __repr__(self) -> str:
        """Human-readable string representation of an OfflineFindingDevice."""
        return (
            f"OfflineFindingDevice({self.mac_address}, pubkey={self.adv_key_b64},"
            f" status={self.status}, hint={self.hint})"
        )

    def __eq__(self, other: OfflineFindingDevice) -> bool:
        """Check if two OfflineFindingDevices are equal by comparing their MAC addresses."""
        if not isinstance(other, OfflineFindingDevice):
            return False
        return other.mac_address == self.mac_address

    def __hash__(self) -> int:
        """Hash an OfflineFindingDevice. This is simply the MAC address as an integer."""
        return int.from_bytes(self._mac_bytes, "big")


class OfflineFindingScanner:
    """BLE scanner that searches for `OfflineFindingDevice`s."""

    _scan_ctrl_lock = asyncio.Lock()

    BLE_COMPANY_APPLE = 0x004C

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        """
        Initialize an instance of the Scanner using an event loop.

        You most likely do not want to use this yourself;
        check out `OfflineFindingScanner.create` instead.
        """
        self._scanner: bleak.BleakScanner = bleak.BleakScanner(self._scan_callback)

        self._loop = loop
        self._device_fut: asyncio.Future[
            (bleak.BLEDevice, bleak.AdvertisementData)
        ] = loop.create_future()

        self._scanner_count: int = 0

    @classmethod
    async def create(cls) -> OfflineFindingScanner:
        """Create an instance of the scanner."""
        loop = asyncio.get_running_loop()
        return cls(loop)

    async def _start_scan(self) -> None:
        async with self._scan_ctrl_lock:
            if self._scanner_count == 0:
                logging.info("Starting BLE scanner")
                await self._scanner.start()
            self._scanner_count += 1

    async def _stop_scan(self) -> None:
        async with self._scan_ctrl_lock:
            self._scanner_count -= 1
            if self._scanner_count == 0:
                logging.info("Stopping BLE scanner")
                await self._scanner.stop()

    async def _scan_callback(
        self,
        device: bleak.BLEDevice,
        data: bleak.AdvertisementData,
    ) -> None:
        self._device_fut.set_result((device, data))
        self._device_fut = self._loop.create_future()

    async def _wait_for_device(self, timeout: float) -> OfflineFindingDevice | None:
        device, data = await asyncio.wait_for(self._device_fut, timeout=timeout)

        apple_data = data.manufacturer_data.get(self.BLE_COMPANY_APPLE, b"")
        if not apple_data:
            return None

        additional_data = device.details.get("props", {})
        return OfflineFindingDevice.from_payload(device.address, apple_data, additional_data)

    async def scan_for(
        self,
        timeout: float = 10,
        *,
        extend_timeout: bool = False,
    ) -> AsyncGenerator[OfflineFindingDevice]:
        """
        Scan for `OfflineFindingDevice`s for up to `timeout` seconds.

        If `extend_timeout` is set, the timer will be extended
        by `timeout` seconds every time a new device is discovered.
        """
        await self._start_scan()

        stop_at = time.time() + timeout
        devices_seen: set[OfflineFindingDevice] = set()

        try:
            time_left = stop_at - time.time()
            while time_left > 0:
                device = await self._wait_for_device(time_left)
                if device is not None and device not in devices_seen:
                    devices_seen.add(device)
                    if extend_timeout:
                        stop_at = time.time() + timeout
                    yield device

                time_left = stop_at - time.time()
        except (asyncio.CancelledError, asyncio.TimeoutError):  # timeout reached
            return
        finally:
            await self._stop_scan()
