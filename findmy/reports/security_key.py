"""Apple HSA2 hardware-security-key challenge and assertion codecs."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from findmy.errors import SecurityKeyError

SECURITY_KEY_ORIGIN = "https://gsa.apple.com"
SECURITY_KEY_RESPONSE_LIMIT = 2_000_000
_SUPPORTED_RP_IDS = frozenset({"apple.com", "gsa.apple.com"})
_SUPPORTED_FACTOR = "fsa2_hsa2"


@dataclass(frozen=True, repr=False)
class SecurityKeyChallenge:
    """
    A validated Apple HSA2 WebAuthn challenge.

    The representation deliberately omits challenge and credential bytes.
    """

    challenge: bytes
    rp_id: str
    credential_ids: tuple[bytes, ...]
    origin: str = SECURITY_KEY_ORIGIN
    created_at: float = field(default_factory=time.monotonic)

    def validate(self) -> None:
        """Validate the RP, origin, sizes and challenge lifetime."""
        origin = urlsplit(self.origin)
        if (
            self.origin != SECURITY_KEY_ORIGIN
            or origin.scheme != "https"
            or origin.hostname != "gsa.apple.com"
            or origin.username is not None
            or origin.password is not None
            or origin.port is not None
            or origin.path
            or origin.query
            or origin.fragment
        ):
            msg = "Unsupported security-key origin."
            raise SecurityKeyError(msg)
        if self.rp_id not in _SUPPORTED_RP_IDS or not (
            origin.hostname == self.rp_id or origin.hostname.endswith("." + self.rp_id)
        ):
            msg = "Security-key RP ID does not match the origin."
            raise SecurityKeyError(msg)
        if not 16 <= len(self.challenge) <= 1024:
            msg = "Invalid security-key challenge size."
            raise SecurityKeyError(msg)
        if not 1 <= len(self.credential_ids) <= 64 or any(
            not 1 <= len(value) <= 4096 for value in self.credential_ids
        ):
            msg = "Invalid security-key credential allowlist."
            raise SecurityKeyError(msg)
        age = time.monotonic() - self.created_at
        if not 0 <= age <= 120:
            msg = "Security-key challenge expired."
            raise SecurityKeyError(msg)


@dataclass(frozen=True, repr=False)
class SecurityKeyAssertion:
    """Authenticator output required by Apple's HSA2 verification endpoint."""

    credential_id: bytes
    client_data_json: bytes
    authenticator_data: bytes
    signature: bytes
    user_handle: bytes | None = None
    client_extension_results: dict[str, Any] = field(default_factory=dict)


def _decode_base64(value: str, *, minimum: int = 1, maximum: int = 4096) -> bytes:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum * 2:
        msg = "Invalid security-key binary field."
        raise SecurityKeyError(msg)
    if not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", value):
        msg = "Invalid security-key base64 encoding."
        raise SecurityKeyError(msg)
    if ("+" in value or "/" in value) and ("-" in value or "_" in value):
        msg = "Mixed security-key base64 alphabets."
        raise SecurityKeyError(msg)
    try:
        normalized = value.translate(str.maketrans("-_", "+/"))
        decoded = base64.b64decode(normalized + "=" * (-len(normalized) % 4), validate=True)
    except ValueError:
        msg = "Invalid security-key base64 encoding."
        raise SecurityKeyError(msg) from None
    if not minimum <= len(decoded) <= maximum:
        msg = "Invalid security-key binary field size."
        raise SecurityKeyError(msg)
    if base64.b64encode(decoded).decode().rstrip("=") != normalized.rstrip("="):
        msg = "Ambiguous security-key base64 encoding."
        raise SecurityKeyError(msg)
    return decoded


def _encode_base64(value: bytes, *, padding: bool = True) -> str:
    result = base64.b64encode(value).decode("ascii")
    return result if padding else result.rstrip("=")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            msg = "Duplicate security-key JSON field."
            raise SecurityKeyError(msg)
        result[key] = value
    return result


def _missing_challenge(required: bool, message: str) -> None:
    if required:
        raise SecurityKeyError(message)


def _boot_args(html: str) -> dict[str, Any] | None:
    if not isinstance(html, str) or len(html) > SECURITY_KEY_RESPONSE_LIMIT:
        return None
    tags = BeautifulSoup(html, "html.parser").select("script.boot_args")
    if len(tags) != 1:
        return None
    try:
        value = json.loads(tags[0].get_text(), object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, SecurityKeyError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def parse_security_key_challenge(
    html: str,
    *,
    required: bool = False,
) -> SecurityKeyChallenge | None:
    """
    Extract an HSA2 security-key challenge from Apple's ``/auth`` page.

    ``None`` means that the page does not advertise a supported security-key factor.
    A malformed advertised factor raises :class:`SecurityKeyError`.
    """
    boot = _boot_args(html)
    if boot is None:
        _missing_challenge(required, "Invalid Apple authentication page.")
        return None
    direct = boot.get("direct")
    if not isinstance(direct, dict):
        _missing_challenge(required, "Apple did not provide a supported 2FA document.")
        return None
    nested = "twoSV" in direct
    two_sv = direct.get("twoSV") if nested else direct
    if not isinstance(two_sv, dict):
        _missing_challenge(required, "Apple did not provide a supported 2FA document.")
        return None
    factors = two_sv.get("authFactors")
    verification = two_sv.get("fsaVerification")
    challenge_data = verification.get("fsaChallenge") if isinstance(verification, dict) else None
    advertised = isinstance(factors, list) and _SUPPORTED_FACTOR in factors
    observed_direct = factors is None and not nested and challenge_data is not None
    if not advertised and not observed_direct:
        _missing_challenge(required, "Apple did not provide a supported fsa2_hsa2 challenge.")
        return None
    if factors is not None and (
        not isinstance(factors, list) or not factors or factors[0] != _SUPPORTED_FACTOR
    ):
        msg = "Apple provided an unsupported security-key factor order."
        raise SecurityKeyError(msg)
    if direct.get("referrerQuery") or two_sv.get("referrerQuery"):
        msg = "Security-key referrerQuery is not supported."
        raise SecurityKeyError(msg)
    if not isinstance(challenge_data, dict):
        msg = "Unsupported Apple security-key challenge structure."
        raise SecurityKeyError(msg)
    if (
        challenge_data.get("extensions")
        or challenge_data.get("legacyExtensionAppId")
        or challenge_data.get("requirePrf")
    ):
        msg = "Security-key challenge extensions are not supported."
        raise SecurityKeyError(msg)
    handles = challenge_data.get("keyHandles")
    encoded_challenge = challenge_data.get("challenge")
    rp_id = challenge_data.get("rpId")
    if (
        not isinstance(handles, list)
        or not 1 <= len(handles) <= 64
        or not all(isinstance(value, str) for value in handles)
        or not isinstance(encoded_challenge, str)
        or not isinstance(rp_id, str)
    ):
        msg = "Unsupported Apple security-key challenge structure."
        raise SecurityKeyError(msg)
    challenge = SecurityKeyChallenge(
        challenge=_decode_base64(encoded_challenge, minimum=16, maximum=1024),
        rp_id=rp_id,
        credential_ids=tuple(_decode_base64(value) for value in handles),
    )
    challenge.validate()
    return challenge


def _client_data(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, SecurityKeyError, UnicodeDecodeError, RecursionError):
        msg = "Invalid security-key client data."
        raise SecurityKeyError(msg) from None
    if not isinstance(value, dict):
        msg = "Invalid security-key client data."
        raise SecurityKeyError(msg)
    return value


def security_key_payload(
    challenge: SecurityKeyChallenge,
    assertion: SecurityKeyAssertion,
) -> dict[str, str]:
    """Validate an assertion and encode Apple's HSA2 verification payload."""
    challenge.validate()
    if (
        not isinstance(assertion.credential_id, bytes)
        or not isinstance(assertion.client_data_json, bytes)
        or not 1 <= len(assertion.client_data_json) <= 65536
        or not isinstance(assertion.authenticator_data, bytes)
        or not isinstance(assertion.signature, bytes)
        or (assertion.user_handle is not None and not isinstance(assertion.user_handle, bytes))
        or not isinstance(assertion.client_extension_results, dict)
    ):
        msg = "Invalid security-key assertion field type or size."
        raise SecurityKeyError(msg)
    client_data = _client_data(assertion.client_data_json)
    encoded_challenge = client_data.get("challenge")
    if (
        client_data.get("type") != "webauthn.get"
        or client_data.get("origin") != challenge.origin
        or client_data.get("crossOrigin", False) is not False
        or not isinstance(encoded_challenge, str)
        or _decode_base64(encoded_challenge) != challenge.challenge
    ):
        msg = "Security-key assertion does not match the challenge."
        raise SecurityKeyError(msg)
    authenticator_data = assertion.authenticator_data
    if len(authenticator_data) != 37:
        msg = "Invalid security-key authenticator data size."
        raise SecurityKeyError(msg)
    flags = authenticator_data[32]
    if (
        assertion.credential_id not in challenge.credential_ids
        or authenticator_data[:32] != hashlib.sha256(challenge.rp_id.encode()).digest()
        or not flags & 0x01
        or flags & 0xC0
    ):
        msg = "Security-key authenticator data does not match the challenge."
        raise SecurityKeyError(msg)
    if not 1 <= len(assertion.signature) <= 4096:
        msg = "Invalid security-key signature size."
        raise SecurityKeyError(msg)
    if assertion.user_handle is not None and len(assertion.user_handle) > 4096:
        msg = "Invalid security-key user handle size."
        raise SecurityKeyError(msg)
    if assertion.client_extension_results:
        msg = "Security-key assertion extensions are not supported."
        raise SecurityKeyError(msg)
    return {
        "challenge": _encode_base64(challenge.challenge, padding=False),
        "clientData": _encode_base64(assertion.client_data_json),
        "signatureData": _encode_base64(assertion.signature),
        "authenticatorData": _encode_base64(assertion.authenticator_data),
        "userHandle": _encode_base64(assertion.user_handle or b"", padding=False),
        "credentialID": _encode_base64(assertion.credential_id, padding=False),
        "rpId": challenge.rp_id,
    }
