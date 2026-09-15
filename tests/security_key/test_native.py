"""Synthetic tests for native Apple HSA2 hardware-security-key support."""

import asyncio
import base64
import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest

from findmy import (
    AppleAccount,
    AsyncAppleAccount,
    AsyncSecurityKeySecondFactor,
    BaseAppleAccount,
    BaseSecondFactorMethod,
    LoginState,
    SecurityKeyAssertion,
    SecurityKeyChallenge,
    SecurityKeyError,
    SecurityKeySecondFactorMethod,
    SyncSecurityKeySecondFactor,
    UnhandledProtocolError,
)
from findmy.reports.security_key import (
    SECURITY_KEY_ORIGIN,
    parse_security_key_challenge,
    security_key_payload,
)
from findmy.util.http import HttpResponse


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode()


def document() -> dict[str, Any]:
    return {
        "direct": {
            "authFactors": ["fsa2_hsa2"],
            "fsaVerification": {
                "fsaChallenge": {
                    "challenge": b64(b"\xfb\xff" * 16),
                    "rpId": "apple.com",
                    "keyHandles": [b64(b"\xfbcredential\xff").rstrip("=")],
                }
            },
            "phoneNumberVerification": {"trustedPhoneNumbers": []},
        }
    }


def page(value: dict[str, Any]) -> str:
    body = json.dumps(value)
    return f'<script class="boot_args" type="application/json">{body}</script>'


def assertion(challenge: SecurityKeyChallenge, **overrides: Any) -> SecurityKeyAssertion:
    client_data = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": base64.urlsafe_b64encode(challenge.challenge).decode().rstrip("="),
            "origin": challenge.origin,
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode()
    values: dict[str, Any] = {
        "credential_id": challenge.credential_ids[0],
        "client_data_json": client_data,
        "authenticator_data": hashlib.sha256(challenge.rp_id.encode()).digest()
        + b"\x01\x00\x00\x00\x01",
        "signature": b"SYNTHETIC-SIGNATURE",
        "user_handle": None,
    }
    values.update(overrides)
    return SecurityKeyAssertion(**values)


def challenge() -> SecurityKeyChallenge:
    result = parse_security_key_challenge(page(document()), required=True)
    assert result is not None
    return result


def test_parse_actual_and_nested_apple_layouts() -> None:
    current = challenge()
    assert current.rp_id == "apple.com"
    assert current.challenge == b"\xfb\xff" * 16
    assert current.credential_ids == (b"\xfbcredential\xff",)

    nested = document()
    nested["direct"] = {"twoSV": nested["direct"]}
    parsed = parse_security_key_challenge(page(nested), required=True)
    assert parsed is not None
    assert parsed.rp_id == "apple.com"


def test_parse_observed_direct_layout_without_auth_factors() -> None:
    value = document()
    del value["direct"]["authFactors"]
    parsed = parse_security_key_challenge(page(value), required=True)
    assert parsed is not None
    assert parsed.credential_ids == (b"\xfbcredential\xff",)


def test_absent_factor_is_none_but_required_mode_errors() -> None:
    value = document()
    value["direct"]["authFactors"] = ["sms"]
    del value["direct"]["fsaVerification"]
    assert parse_security_key_challenge(page(value)) is None
    with pytest.raises(SecurityKeyError):
        parse_security_key_challenge(page(value), required=True)


@pytest.mark.parametrize(
    "change",
    [
        lambda value: value["direct"].update(authFactors=["fsa1"]),
        lambda value: value["direct"].update(authFactors=[]),
        lambda value: value["direct"]["fsaVerification"]["fsaChallenge"].update(
            rpId="evil.example"
        ),
        lambda value: value["direct"]["fsaVerification"]["fsaChallenge"].update(
            challenge="!!bad!!"
        ),
        lambda value: value["direct"]["fsaVerification"]["fsaChallenge"].update(challenge="YQ=="),
        lambda value: value["direct"]["fsaVerification"]["fsaChallenge"].update(keyHandles=[]),
        lambda value: value["direct"]["fsaVerification"]["fsaChallenge"].update(
            extensions={"prf": {}}
        ),
        lambda value: value["direct"].update(referrerQuery="?redirect=evil"),
    ],
)
def test_challenge_parser_fails_closed(change: Any) -> None:
    value = document()
    change(value)
    with pytest.raises(SecurityKeyError):
        parse_security_key_challenge(page(value), required=True)


def test_duplicate_or_oversized_boot_document_is_rejected() -> None:
    duplicate = page(document()).replace('"direct":', '"direct":{},"direct":', 1)
    for html in ("<html/>", page(document()) * 2, duplicate, "x" * 2_000_001):
        with pytest.raises(SecurityKeyError):
            parse_security_key_challenge(html, required=True)


def test_challenge_repr_and_expiry_do_not_leak() -> None:
    current = challenge()
    assert b64(current.challenge) not in repr(current)
    assert "credential" not in repr(current)
    with pytest.raises(SecurityKeyError):
        replace(current, created_at=current.created_at - 121).validate()


def test_hsa2_payload_uses_apple_base64_conventions() -> None:
    current = challenge()
    signed = assertion(current)
    payload = security_key_payload(current, signed)
    assert payload == {
        "challenge": b64(current.challenge).rstrip("="),
        "clientData": b64(signed.client_data_json),
        "signatureData": b64(signed.signature),
        "authenticatorData": b64(signed.authenticator_data),
        "credentialID": b64(current.credential_ids[0]).rstrip("="),
        "userHandle": "",
        "rpId": "apple.com",
    }
    assert "requestId" not in payload


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("credential_id", b"other"),
        ("authenticator_data", b"x" * 37),
        ("authenticator_data", hashlib.sha256(b"apple.com").digest() + b"\0\0\0\0\1"),
        ("signature", b""),
        ("user_handle", b"x" * 4097),
        ("client_extension_results", {"prf": True}),
    ],
)
def test_assertion_validation_fails_closed(field: str, value: Any) -> None:
    current = challenge()
    with pytest.raises(SecurityKeyError):
        security_key_payload(current, assertion(current, **{field: value}))


def test_client_data_must_match_challenge_and_origin() -> None:
    current = challenge()
    signed = assertion(current)
    client_data = json.loads(signed.client_data_json)
    for key, value in (
        ("challenge", "ZGlmZmVyZW50"),
        ("origin", "https://evil.example"),
        ("type", "webauthn.create"),
        ("crossOrigin", True),
    ):
        changed = {**client_data, key: value}
        with pytest.raises(SecurityKeyError):
            security_key_payload(
                current,
                replace(signed, client_data_json=json.dumps(changed).encode()),
            )


def test_async_factor_uses_authenticate_not_submit_and_is_one_shot() -> None:
    async def run() -> None:
        current = challenge()
        signed = assertion(current)
        account = SimpleNamespace(
            security_key_2fa_request=AsyncMock(return_value=current),
            security_key_2fa_submit=AsyncMock(return_value=LoginState.LOGGED_IN),
        )
        factor = AsyncSecurityKeySecondFactor(cast("Any", account), current)
        assert isinstance(factor, BaseSecondFactorMethod)
        assert isinstance(factor, SecurityKeySecondFactorMethod)
        await factor.request()

        async def signer(received: SecurityKeyChallenge) -> SecurityKeyAssertion:
            assert received is current
            return signed

        assert await factor.authenticate(signer) == LoginState.LOGGED_IN
        account.security_key_2fa_submit.assert_awaited_once_with(current, signed)
        with pytest.raises(RuntimeError):
            await factor.authenticate(signer)
        with pytest.raises(TypeError):
            await factor.submit("000000")

    asyncio.run(run())


def test_sync_factor_uses_authenticate_not_submit_and_is_one_shot() -> None:
    current = challenge()
    signed = assertion(current)
    calls: list[tuple[SecurityKeyChallenge, SecurityKeyAssertion]] = []
    account = SimpleNamespace(
        security_key_2fa_request=lambda: current,
        security_key_2fa_submit=lambda first, second: calls.append((first, second))
        or LoginState.LOGGED_IN,
    )
    factor = SyncSecurityKeySecondFactor(cast("Any", account), current)
    factor.request()
    assert factor.authenticate(lambda received: signed) == LoginState.LOGGED_IN
    assert calls == [(current, signed)]
    with pytest.raises(RuntimeError):
        factor.authenticate(lambda received: signed)
    with pytest.raises(TypeError):
        factor.submit("000000")


def test_sync_account_casts_native_async_factor() -> None:
    current = challenge()
    account = AppleAccount(cast("Any", DummyAnisette()))
    async_factor = AsyncSecurityKeySecondFactor(account._asyncacc, current)
    account._asyncacc.get_2fa_methods = AsyncMock(return_value=[async_factor])
    try:
        methods = account.get_2fa_methods()
        assert len(methods) == 1
        assert isinstance(methods[0], SyncSecurityKeySecondFactor)
        assert methods[0].challenge is current
    finally:
        account._evt_loop.run_until_complete(account.close())
        account._loop = None
        account._evt_loop.close()


def test_security_key_addition_does_not_add_abstract_requirements() -> None:
    assert "security_key_2fa_request" not in BaseAppleAccount.__abstractmethods__
    assert "security_key_2fa_submit" not in BaseAppleAccount.__abstractmethods__


class DummyAnisette:
    async def close(self) -> None:
        pass

    def to_json(self) -> dict[str, Any]:
        return {"type": "aniLocal", "prov_data": None}


async def _native_account() -> AsyncAppleAccount:
    account = AsyncAppleAccount(cast("Any", DummyAnisette()))
    account._set_login_state(
        LoginState.REQUIRE_2FA,
        {"adsid": "SYNTHETIC-ID", "idms_token": "SYNTHETIC-TOKEN"},
    )
    account._account_info = {
        "account_name": "synthetic@example.invalid",
        "first_name": "Synthetic",
        "last_name": "Account",
        "trusted_device_2fa": False,
    }
    account.get_anisette_headers = AsyncMock(return_value={})
    return account


def test_get_methods_returns_native_security_key_factor() -> None:
    async def run() -> None:
        account = await _native_account()
        account._sms_2fa_request = AsyncMock(return_value=page(document()))
        try:
            methods = await account.get_2fa_methods()
            keys = [
                method for method in methods if isinstance(method, AsyncSecurityKeySecondFactor)
            ]
            assert len(keys) == 1
            assert keys[0].challenge.rp_id == "apple.com"
        finally:
            await account.close()

    asyncio.run(run())


def test_get_methods_does_not_silently_hide_malformed_security_key_factor() -> None:
    async def run() -> None:
        account = await _native_account()
        invalid = document()
        invalid["direct"]["fsaVerification"]["fsaChallenge"]["rpId"] = "evil.example"
        account._sms_2fa_request = AsyncMock(return_value=page(invalid))
        try:
            with pytest.raises(SecurityKeyError):
                await account.get_2fa_methods()
        finally:
            await account.close()

    asyncio.run(run())


def test_native_factor_preserves_continuation_and_requires_final_states() -> None:
    async def run() -> None:
        account = await _native_account()
        account._http.request = AsyncMock(
            side_effect=[
                HttpResponse(
                    200,
                    page(document()).encode(),
                    {
                        "Scnt": "SYNTHETIC-CONTINUATION",
                        "X-Apple-ID-Session-Id": "SYNTHETIC-SESSION",
                    },
                ),
                HttpResponse(250, b""),
            ]
        )
        account._gsa_authenticate = AsyncMock(return_value=LoginState.AUTHENTICATED)
        account._login_mobileme = AsyncMock(return_value=LoginState.LOGGED_IN)
        try:
            methods = await account.get_2fa_methods()
            factor = next(
                method for method in methods if isinstance(method, AsyncSecurityKeySecondFactor)
            )

            async def signer(received: SecurityKeyChallenge) -> SecurityKeyAssertion:
                return assertion(received)

            assert await factor.authenticate(signer) == LoginState.LOGGED_IN
            calls = account._http.request.call_args_list
            assert calls[0].args == ("GET", account._ENDPOINT_2FA_METHODS)
            assert calls[0].kwargs["allow_redirects"] is False
            assert calls[0].kwargs["max_response_size"] == 2_000_000
            assert calls[1].args == (
                "POST",
                account._ENDPOINT_2FA_SECURITY_KEY_SUBMIT,
            )
            assert calls[1].kwargs["headers"]["scnt"] == "SYNTHETIC-CONTINUATION"
            assert calls[1].kwargs["headers"]["x-apple-id-session-id"] == "SYNTHETIC-SESSION"
            assert calls[1].kwargs["headers"]["Origin"] == SECURITY_KEY_ORIGIN
            account._gsa_authenticate.assert_awaited_once_with()
            account._login_mobileme.assert_awaited_once_with()
        finally:
            await account.close()

    asyncio.run(run())


@pytest.mark.parametrize("status", [201, 202, 302, 400, 401, 409, 412, 423, 429, 500])
def test_security_key_endpoint_rejects_nonterminal_status(status: int) -> None:
    async def run() -> None:
        account = await _native_account()
        account._http.request = AsyncMock(return_value=HttpResponse(status, b"SENSITIVE"))
        account._gsa_authenticate = AsyncMock()
        current = challenge()
        account._security_key_challenge = current
        try:
            with pytest.raises(UnhandledProtocolError) as error:
                await account.security_key_2fa_submit(current, assertion(current))
            assert "SENSITIVE" not in str(error.value)
            account._gsa_authenticate.assert_not_awaited()
        finally:
            await account.close()

    asyncio.run(run())


def test_account_rejects_assertion_for_unissued_challenge() -> None:
    async def run() -> None:
        account = await _native_account()
        current = challenge()
        account._security_key_challenge = current
        account._http.request = AsyncMock()
        try:
            with pytest.raises(SecurityKeyError, match="active account challenge"):
                await account.security_key_2fa_submit(replace(current), assertion(current))
            account._http.request.assert_not_awaited()
        finally:
            await account.close()

    asyncio.run(run())
