"""Tests for decoding of Offline Finding advertisements."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from findmy import KeyPair
from findmy.scanner import (
    NearbyOfflineFindingDevice,
    OfflineFindingDevice,
    SeparatedOfflineFindingDevice,
)

NOW = datetime(2026, 11, 25, 19, 0, tzinfo=timezone.utc)

# DULT service data as broadcast by an AirTag (2nd generation) near its owner.
# This is the only data in its advertisement: there is no Apple manufacturer data.
AIRTAG2_NEAR_OWNER_MAC = "E4:FE:6F:86:32:47"
AIRTAG2_NEAR_OWNER_DULT = bytes.fromhex("01011403")


def _mac_of(key: KeyPair) -> str:
    """BLE address an accessory uses while broadcasting a key."""
    adv = key.adv_key_bytes
    return bytes([adv[0] | 0b11000000, *adv[1:6]]).hex(":").upper()


def _separated_of_data(key: KeyPair, status: int, hint: int) -> bytes:
    """OF data of a separated advertisement: status, key (22 bytes), key bits, hint."""
    adv = key.adv_key_bytes
    return bytes([status, *adv[6:], adv[0] >> 6, hint])


def test_dult_near_owner() -> None:
    """Decode the DULT advertisement of an AirTag (2nd generation) near its owner."""
    device = OfflineFindingDevice.from_dult_payload(
        AIRTAG2_NEAR_OWNER_MAC,
        AIRTAG2_NEAR_OWNER_DULT,
        NOW,
        -59,
    )

    assert isinstance(device, NearbyOfflineFindingDevice)
    assert device.near_owner is True
    assert device.mac_address == AIRTAG2_NEAR_OWNER_MAC
    assert device.rssi == -59
    # key bits (0b11) + lower 6 bits of the first address byte, then the rest of the address
    assert device.partial_adv_key == bytes.fromhex("E4FE6F863247")


def test_dult_near_owner_is_from_key() -> None:
    """Match a DULT near-owner advertisement against the key that it broadcasts."""
    key = KeyPair.new()
    other_key = KeyPair.new()
    dult = bytes([0x01, 0x01, 0x14, key.adv_key_bytes[0] >> 6])

    device = OfflineFindingDevice.from_dult_payload(_mac_of(key), dult, NOW)

    assert isinstance(device, NearbyOfflineFindingDevice)
    assert device.near_owner is True
    assert device.is_from(key)
    assert not device.is_from(other_key)


def test_dult_separated() -> None:
    """Decode the DULT advertisement of a separated accessory."""
    key = KeyPair.new()
    dult = bytes([0x01, 0x00]) + _separated_of_data(key, status=0x10, hint=0x47)

    device = OfflineFindingDevice.from_dult_payload(_mac_of(key), dult, NOW)

    assert isinstance(device, SeparatedOfflineFindingDevice)
    assert device.near_owner is False
    assert device.adv_key_bytes == key.adv_key_bytes
    assert device.hint == 0x47
    assert device.is_from(key)


@pytest.mark.parametrize(
    "dult",
    [
        b"",
        bytes.fromhex("01"),
        bytes.fromhex("0101"),  # no OF data
        bytes.fromhex("0101140300"),  # OF data of unknown length
        bytes.fromhex("02011403"),  # not the Apple network
    ],
)
def test_dult_invalid(dult: bytes) -> None:
    """Ignore DULT service data that does not carry Apple OF data."""
    assert OfflineFindingDevice.from_dult_payload(AIRTAG2_NEAR_OWNER_MAC, dult, NOW) is None


def test_advertisement_dult_only() -> None:
    """An advertisement with only DULT data is decoded from that data."""
    device = OfflineFindingDevice.from_advertisement(
        AIRTAG2_NEAR_OWNER_MAC,
        dult_data=AIRTAG2_NEAR_OWNER_DULT,
        detected_at=NOW,
    )

    assert isinstance(device, NearbyOfflineFindingDevice)
    assert device.near_owner is True


def test_advertisement_apple_and_dult() -> None:
    """A separated AirTag (2nd generation) broadcasts both Apple and DULT data."""
    key = KeyPair.new()
    apple = bytes([0x12, 0x19]) + _separated_of_data(key, status=0x20, hint=0x47)
    dult = bytes([0x01, 0x00]) + _separated_of_data(key, status=0x10, hint=0x47)

    device = OfflineFindingDevice.from_advertisement(_mac_of(key), apple, dult, NOW)

    assert isinstance(device, SeparatedOfflineFindingDevice)
    # the status byte is taken from the Apple data
    assert device.status == 0x20
    assert device.near_owner is False
    assert device.is_from(key)


def test_advertisement_apple_only() -> None:
    """Accessories without a DULT advertisement do not report whether they are near the owner."""
    key = KeyPair.new()
    apple = bytes([0x12, 0x02, 0x00, key.adv_key_bytes[0] >> 6])

    device = OfflineFindingDevice.from_advertisement(_mac_of(key), apple, None, NOW)

    assert isinstance(device, NearbyOfflineFindingDevice)
    assert device.near_owner is None
    assert device.is_from(key)


def test_advertisement_unrelated() -> None:
    """Advertisements without OF data are ignored."""
    # Apple "Nearby Info" (0x10) message, as broadcast by iPhones
    apple = bytes.fromhex("1007771ff6c91f1d08")

    assert OfflineFindingDevice.from_advertisement("58:10:E3:73:09:16", apple, None, NOW) is None
    assert OfflineFindingDevice.from_advertisement("58:10:E3:73:09:16", None, None, NOW) is None
