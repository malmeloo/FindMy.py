# AirTags

```{note}
This page is a work in progress. It currently only documents the Bluetooth advertisements
of official accessories; key rotation is not covered yet.
```

## Bluetooth Advertisements

Official accessories broadcast one of their rotating public keys over Bluetooth Low Energy.
The first 6 bytes of that key are used as the (random) BLE address of the accessory, with the
two most significant bits of the first byte forced to `0b11`. The two bits that are lost this way
are sent separately in the advertisement, as the 'key bits'.

Which advertisement is sent depends on whether the accessory is near its owner ('nearby' state)
or not ('separated' state), and on the generation of the accessory.

### Offline Finding data

Most accessories send their data as Apple manufacturer data (company ID `0x004C`), in a message of
type `0x12`. Two variants exist, which are distinguished by their length:

| State     | Length | Contents                                                             |
|-----------|--------|----------------------------------------------------------------------|
| Nearby    | `0x02` | status (1 byte), key bits (1 byte)                                   |
| Separated | `0x19` | status (1 byte), key bytes 6-27 (22 bytes), key bits (1 byte), hint (1 byte) |

In the nearby state, only the first 6 bytes of the public key can be reconstructed (from the
address and the key bits). This is not enough to query location reports, but it is enough to
recognize an accessory if you have its keys. In the separated state, the entire public key is
available.

In FindMy.py, these are represented by {class}`~findmy.scanner.NearbyOfflineFindingDevice`
and {class}`~findmy.scanner.SeparatedOfflineFindingDevice`.

### DULT advertisements (AirTag 2nd generation)

The AirTag (2nd generation) additionally implements
[DULT](https://datatracker.ietf.org/doc/draft-ietf-dult-accessory-protocol/) ("Detecting Unwanted
Location Trackers"), a cross-vendor protocol for detecting unknown trackers. Such accessories
broadcast service data for the 16-bit service UUID `0xFCB2`:

| Byte(s) | Contents                                                        |
|---------|-----------------------------------------------------------------|
| 0       | Network ID. `0x01` for Apple.                                   |
| 1       | Flags. Bit 0 is the near-owner bit: set if the accessory is near its owner. |
| 2+      | Offline Finding data, in the same layout as in the table above. |

What the accessory broadcasts depends on its state:

| State                  | Apple manufacturer data | DULT service data      |
|------------------------|-------------------------|------------------------|
| Separated              | Yes (length `0x19`)     | Yes (25 bytes OF data) |
| Nearby (near-owner)    | **No**                  | Yes (2 bytes OF data)  |

This means that a 2nd generation AirTag near its owner can *only* be discovered through its DULT
service data: a scanner that only looks at Apple manufacturer data will see the AirTag while it is
separated, and lose it as soon as its owner comes home.

As an example, this is the service data of an AirTag (2nd generation) near its owner:
`01 01 14 03` (Apple network, near-owner, status `0x14`, key bits `0b11`).

FindMy.py decodes this data using {meth}`~findmy.scanner.OfflineFindingDevice.from_dult_payload`,
and the scanner does so automatically. The near-owner bit is available as
{attr}`~findmy.scanner.OfflineFindingDevice.near_owner`.

```{note}
The first byte of the OF data in the DULT service data is not identical to the status byte in the
Apple manufacturer data that is sent in the same advertisement (`0x10` versus `0x20` has been
observed for a separated AirTag). Its exact meaning is currently unknown, so the device type and
battery level that FindMy.py derives from it may be inaccurate for near-owner AirTags.

In the Apple manufacturer data, the 2nd generation AirTag has also been observed to use the device
type bits `0b10` rather than the `0b01` used by the 1st generation.

These observations are based on a single accessory. If you can confirm or correct them,
please open an issue.
```
