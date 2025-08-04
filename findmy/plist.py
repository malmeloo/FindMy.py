"""Utils for decrypting the encypted .record files into .plist files."""

from __future__ import annotations

import plistlib
import subprocess
from pathlib import Path
from typing import IO

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .accessory import FindMyAccessory

# Originally from:
# Author: Shane B. <shane@wander.dev>
# in https://github.com/parawanderer/OpenTagViewer/blob/08a59cab551721afb9dc9f829ad31dae8d5bd400/python/airtag_decryptor.py
# which was based on:
# Based on: https://gist.github.com/airy10/5205dc851fbd0715fcd7a5cdde25e7c8


# consider switching to this library https://github.com/microsoft/keyper
# once they publish a version of it that includes my MR with the changes to make it compatible
# with keys that are non-utf-8 encoded (like the BeaconStore one)
# if I contribute this, properly escape the label argument here...
def get_key() -> bytes:
    """Get the decryption key for BeaconStore using the system password prompt window."""
    # This thing will pop up 2 Password Input windows...
    key_in_hex = subprocess.getoutput("/usr/bin/security find-generic-password -l 'BeaconStore' -w")  # noqa: S605
    return bytes.fromhex(key_in_hex)


def decrypt_plist(encrypted: str | Path | bytes | IO[bytes], key: bytes) -> dict:
    """
    Decrypts the encrypted plist file at `encrypted` using the provided `key`.

    :param encrypted:       If bytes or IO, the encrypted plist data.
                            If str or Path, the path to the encrypted plist file, which is
                            generally something like `/Users/<username>/Library/com.apple.icloud.searchpartyd/OwnedBeacons/<UUID>.record`
    :param key:             Raw key to decrypt plist file with.
                            See: `get_key()`

    :returns:               The decoded plist dict
    """  # noqa: E501
    if isinstance(encrypted, (str, Path)):
        with Path(encrypted).open("rb") as f:
            encrypted_bytes = f.read()
    elif isinstance(encrypted, bytes):
        encrypted_bytes = encrypted
    elif isinstance(encrypted, IO):
        encrypted_bytes = encrypted.read()
    else:
        raise TypeError("encrypted must be a str, Path, bytes, or IO[bytes]")  # noqa: EM101, TRY003

    plist = plistlib.loads(encrypted_bytes)
    if not isinstance(plist, list) or len(plist) < 3:
        raise ValueError(plist, "encrypted plist should be a list of 3 elements")

    nonce, tag, ciphertext = plist[0], plist[1], plist[2]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    decrypted_plist_bytes = decryptor.update(ciphertext) + decryptor.finalize()

    decrypted_plist = plistlib.loads(decrypted_plist_bytes)
    if not isinstance(decrypted_plist, dict):
        raise ValueError(decrypted_plist, "decrypted plist should be a dictionary")  # noqa: TRY004
    return decrypted_plist


def list_accessories(
    *,
    key: bytes | None = None,
    search_path: str | Path | None = None,
) -> list[FindMyAccessory]:
    """Get all accesories from the encrypted .plist files dumped from the FindMy app."""
    if search_path is None:
        search_path = Path.home() / "Library" / "com.apple.icloud.searchpartyd"
    search_path = Path(search_path)
    if key is None:
        key = get_key()

    accesories = []
    encrypted_plist_paths = search_path.glob("OwnedBeacons/*.record")
    for path in encrypted_plist_paths:
        plist = decrypt_plist(path, key)
        naming_record_path = next((search_path / "BeaconNamingRecord" / path.stem).glob("*.record"))
        naming_record_plist = decrypt_plist(naming_record_path, key)
        name = naming_record_plist["name"]
        accessory = FindMyAccessory.from_plist(plist, name=name)
        accesories.append(accessory)
    return accesories
