"""Offline synthetic CTAP2 authenticator exercises real python-fido2 and ECDSA.
NOT a hardware-key test; NOT an Apple authentication response.
"""

import base64
import hashlib
from typing import Any, cast

from apple_fido import Challenge, apple_payload, sign_usb
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.client import UserInteraction
from fido2.ctap import CtapDevice
from fido2.hid import CAPABILITY, CTAPHID
from fido2.webauthn import AuthenticatorData
from typing_extensions import override


class SyntheticAuthenticator(CtapDevice):
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = b"\xff\xfbsynthetic-credential"
        self.requests = []

    @property
    @override
    def capabilities(self):
        return CAPABILITY.CBOR

    @classmethod
    @override
    def list_devices(cls):
        return iter(())

    @override
    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        assert cmd == CTAPHID.CBOR
        self.requests.append(data[0])
        if data[0] == 4:  # CTAP2 authenticatorGetInfo
            return b"\0" + cbor.encode(
                {1: ["FIDO_2_0"], 3: b"\0" * 16, 4: {"rk": False, "up": True}, 5: 1200}
            )
        assert data[0] == 2  # CTAP2 authenticatorGetAssertion
        request = cast("dict[int, Any]", cbor.decode(data[1:]))
        assert request[1] == "apple.com"
        assert len(request[3]) == 1
        assert request[3][0]["id"] == self.credential_id
        assert request[3][0]["type"] == "public-key"
        assert request[3][0].get("transports", ["usb"]) == ["usb"]
        auth = AuthenticatorData.create(
            hashlib.sha256(request[1].encode()).digest(), AuthenticatorData.FLAG.UP, 1
        )
        signature = self.private_key.sign(bytes(auth) + request[2], ec.ECDSA(hashes.SHA256()))
        return b"\0" + cbor.encode(
            {1: {"type": "public-key", "id": self.credential_id}, 2: bytes(auth), 3: signature}
        )


def test_real_fido2_client_ctap2_codec_and_ecdsa_verification():
    device = SyntheticAuthenticator()
    c = Challenge(b"\xfb\xff" * 16, "apple.com", (device.credential_id,))
    result = sign_usb(c, device, UserInteraction())
    payload = apple_payload(c, result)
    client_data = base64.b64decode(payload["clientData"])
    auth_data = base64.b64decode(payload["authenticatorData"])
    signature = base64.b64decode(payload["signatureData"])
    device.private_key.public_key().verify(
        signature, auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
    )
    assert 2 in device.requests
    assert result.raw_id == device.credential_id
