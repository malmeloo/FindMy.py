from __future__ import annotations

TWO_MOST_SIGNIFICANT_BITS_MASK = 0b11000000


def pubkey_to_ble(pubkey: bytes) -> tuple[bytes, bytes]:
    assert len(pubkey) == 28

    addr = bytearray(pubkey[:6])
    addr[0] |= TWO_MOST_SIGNIFICANT_BITS_MASK

    ad = bytes(
        [
            # apple company id
            0x4C,
            0x00,
            # offline finding
            0x12,
            # offline finding data length
            25,
            # status
            0b11100000,  # critically low battery
            # remaining public key bytes
            *pubkey[6:],
            pubkey[0] >> 6,
            0,  # hint
        ],
    )

    return bytes(addr), ad


def ble_to_pubkey(addr: bytes, ad: bytes) -> bytes:
    assert len(addr) == 6
    assert len(ad) == 29

    assert ad[0:2] == bytes([0x4C, 0x00])
    assert ad[2] == 0x12
    assert ad[3] == 25

    return bytes(
        [
            (addr[0] & (0xFF ^ TWO_MOST_SIGNIFICANT_BITS_MASK)) | (ad[27] << 6),
            *addr[1:],
            *ad[5:27],
        ],
    )


if __name__ == "__main__":
    import base64
    import sys

    USAGE = f"""Usage: {sys.argv[0]} <subcommand> <args>

Subcommands:

{sys.argv[0]} gen-pubkey <hex bt address (BE)> <hex ble ad data (BE)>
{sys.argv[0]} gen-ble <base64 public key>"""

    if len(sys.argv) < 2:
        print(USAGE, file=sys.stderr)
        sys.exit(1)

    subcommand = sys.argv[1]

    if subcommand == "gen-pubkey":
        if len(sys.argv) != 4:
            print(USAGE, file=sys.stderr)
            sys.exit(1)

        addr = bytes.fromhex(sys.argv[2])
        ad = bytes.fromhex(sys.argv[3])

        pubkey = ble_to_pubkey(addr, ad)
        print(base64.b64encode(pubkey).decode())
    elif subcommand == "gen-ble":
        if len(sys.argv) != 3:
            print(USAGE, file=sys.stderr)
            sys.exit(1)

        pubkey = base64.b64decode(sys.argv[2])
        addr, ad = pubkey_to_ble(pubkey)

        print(addr.hex(), ad.hex())
    else:
        print(USAGE, file=sys.stderr)
        sys.exit(1)
