"""
Utils for decrypting the encypted .record files into .plist files.

Originally from:
Author: Shane B. <shane@wander.dev>
in https://github.com/parawanderer/OpenTagViewer/blob/08a59cab551721afb9dc9f829ad31dae8d5bd400/python/airtag_decryptor.py
which was based on:
Based on: https://gist.github.com/airy10/5205dc851fbd0715fcd7a5cdde25e7c8
"""

from __future__ import annotations

import logging
import plistlib
import re
import subprocess
from pathlib import Path
from typing import IO

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .accessory import FindMyAccessory

logger = logging.getLogger(__name__)


_DEFAULT_SEARCH_PATH = Path.home() / "Library" / "com.apple.icloud.searchpartyd"


def _parse_beaconstore_key_from_string_output(output: str) -> bytes:
    if '"acct"<blob>="BeaconStoreKey"' not in output:
        raise ValueError
    m = re.search(r'"gena"<blob>=0x([0-9A-Fa-f]+)', output)
    if not m:
        raise ValueError
    return bytes.fromhex(m.group(1))


def _parse_beaconstore_key_from_hex_output(output: str) -> bytes:
    if not output:
        msg = "Empty output from security -w"
        raise ValueError(msg)
    return bytes.fromhex(output)


# consider switching to this library https://github.com/microsoft/keyper
# once they publish a version of it that includes my MR with the changes to make it compatible
# with keys that are non-utf-8 encoded (like the BeaconStore one)
# if I contribute this, properly escape the label argument here...
def _get_beaconstore_key() -> bytes:
    try:
        # This thing will pop up 2 Password Input windows...
        key_in_hex = subprocess.getoutput(  # noqa: S605
            "/usr/bin/security find-generic-password -l 'BeaconStore' -w"
        )
        return _parse_beaconstore_key_from_hex_output(key_in_hex)
    except (ValueError, subprocess.SubprocessError):
        output = subprocess.getoutput("/usr/bin/security find-generic-password -l 'BeaconStore'")  # noqa: S605
        return _parse_beaconstore_key_from_string_output(output)


def _get_accessory_name(
    accessory_id: str,
    key: bytes,
    *,
    search_path: Path | None = None,
) -> str | None:
    search_path = search_path or _DEFAULT_SEARCH_PATH
    path = next((search_path / "BeaconNamingRecord" / accessory_id).glob(pattern="*.record"), None)
    if path is None:
        logger.warning(
            "Accessory %s does not have a BeaconNamingRecord, defaulting to None", accessory_id
        )
        return None

    naming_record_plist = decrypt_plist(path, key)
    return naming_record_plist.get("name", None)


def _get_alignment_plist(
    accessory_id: str,
    key: bytes,
    *,
    search_path: Path | None = None,
) -> dict | None:
    search_path = search_path or _DEFAULT_SEARCH_PATH
    path = next((search_path / "KeyAlignmentRecords" / accessory_id).glob(pattern="*.record"), None)
    if path is None:
        logger.warning("Accessory %s does not have a KeyAlignmentRecord", accessory_id)
        return None

    return decrypt_plist(path, key)


def decrypt_plist(encrypted: str | Path | bytes | IO[bytes], key: bytes) -> dict:
    """
    Decrypts the encrypted plist file at :meth:`encrypted` using the provided :meth:`key`.

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
        key = _get_beaconstore_key()

    accesories = []
    encrypted_plist_paths = search_path.glob("OwnedBeacons/*.record")
    for path in encrypted_plist_paths:
        plist = decrypt_plist(path, key)
        name = _get_accessory_name(path.stem, key)
        alignment_plist = _get_alignment_plist(path.stem, key)

        accessory = FindMyAccessory.from_plist(plist, alignment_plist, name=name)
        accesories.append(accessory)
    return accesories
