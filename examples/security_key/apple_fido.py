"""Optional python-fido2 USB adapter for FindMy's native security-key factor."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.webauthn import PublicKeyCredentialRequestOptions

from findmy import SecurityKeyAssertion, SecurityKeyChallenge, SecurityKeyError

if TYPE_CHECKING:
    from fido2.ctap import CtapDevice


class FidoError(SecurityKeyError):
    """A secret-free error raised at the optional USB adapter boundary."""


def request_options(challenge: SecurityKeyChallenge) -> PublicKeyCredentialRequestOptions:
    """Convert a native FindMy challenge to python-fido2 request options."""
    challenge.validate()
    return PublicKeyCredentialRequestOptions.from_dict(
        {
            "challenge": challenge.challenge,
            "rpId": challenge.rp_id,
            "timeout": 90_000,
            "userVerification": "preferred",
            "allowCredentials": [
                {"type": "public-key", "id": value, "transports": ["usb"]}
                for value in challenge.credential_ids
            ],
        }
    )


def sign_usb(
    challenge: SecurityKeyChallenge,
    device: CtapDevice,
    interaction: UserInteraction,
) -> SecurityKeyAssertion:
    """Request one USB assertion and return the dependency-free FindMy value object."""
    client = Fido2Client(
        device,
        DefaultClientDataCollector(challenge.origin),
        user_interaction=interaction,
    )
    selection = client.get_assertion(request_options(challenge))
    if len(selection.get_assertions()) != 1:
        msg = "Ambiguous authenticator response; refusing automatic account selection."
        raise FidoError(msg)
    result = selection.get_response(0)
    response = result.response
    assertion = SecurityKeyAssertion(
        credential_id=result.raw_id,
        client_data_json=bytes(response.client_data),
        authenticator_data=bytes(response.authenticator_data),
        signature=response.signature,
        user_handle=response.user_handle,
        client_extension_results=dict(result.client_extension_results),
    )
    # Validate before returning. This helper performs no HTTP request.
    from findmy.reports.security_key import security_key_payload

    security_key_payload(challenge, assertion)
    return assertion
