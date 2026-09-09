"""Offline tests. Every challenge, account and key here is SYNTHETIC."""

import asyncio
import base64
import hashlib
import json
from typing import Any, cast

import pytest
from apple_fido import (
    CheckedHttpSession,
    FidoError,
    apple_payload,
    apple_ssl_context,
    complete_second_factor,
    parse_auth_page,
)
from fido2.webauthn import (
    AuthenticationResponse,
    AuthenticatorAssertionResponse,
    AuthenticatorData,
    CollectedClientData,
)

from findmy import LoginState


def b64(value):
    return base64.b64encode(value).decode()


def document():
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
        }
    }


def page(doc):
    return '<script class="boot_args" type="application/json">' + json.dumps(doc) + "</script>"


def response(challenge, **overrides):
    client = CollectedClientData.create("webauthn.get", challenge.challenge, challenge.origin)
    auth = AuthenticatorData.create(
        hashlib.sha256(challenge.rp_id.encode()).digest(), AuthenticatorData.FLAG.UP, 1
    )
    fields = {
        "raw_id": challenge.credential_ids[0],
        "response": AuthenticatorAssertionResponse(
            client_data=client,
            authenticator_data=auth,
            signature=b"FAKE-SIGNATURE",
            user_handle=None,
        ),
    }
    fields.update(overrides)
    return AuthenticationResponse(**fields)


def test_parse_actual_apple_field_layout():
    c = parse_auth_page(page(document()))
    assert c.rp_id == "apple.com"
    assert c.challenge == b"\xfb\xff" * 16
    assert c.credential_ids == (b"\xfbcredential\xff",)
    assert c.options().user_verification == "preferred"
    credentials = c.options().allow_credentials
    assert credentials is not None
    assert credentials[0].id == c.credential_ids[0]


def test_accept_explicit_two_sv_layout():
    d = document()
    d["direct"] = {"twoSV": d["direct"]}
    assert parse_auth_page(page(d)).rp_id == "apple.com"


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d["direct"].update(authFactors=["fsa1"]),
        lambda d: d["direct"].update(authFactors=[]),
        lambda d: d["direct"]["fsaVerification"]["fsaChallenge"].update(rpId="evil.example"),
        lambda d: d["direct"]["fsaVerification"]["fsaChallenge"].update(rpId="idmsa.apple.com"),
        lambda d: d["direct"]["fsaVerification"]["fsaChallenge"].update(challenge="!!bad!!"),
        lambda d: d["direct"]["fsaVerification"]["fsaChallenge"].update(challenge="YQ=="),
        lambda d: d["direct"]["fsaVerification"]["fsaChallenge"].update(keyHandles=[]),
        lambda d: d["direct"]["fsaVerification"]["fsaChallenge"].update(keyHandles=["!"]),
        lambda d: d["direct"]["fsaVerification"]["fsaChallenge"].update(keyHandles="abc"),
        lambda d: d["direct"]["fsaVerification"]["fsaChallenge"].update(extensions={"prf": {}}),
        lambda d: d["direct"].update(referrerQuery="?redirect=https://evil.example"),
    ],
)
def test_fail_closed(change):
    d = document()
    change(d)
    with pytest.raises(FidoError):
        parse_auth_page(page(d))


def test_duplicate_boot_args_and_missing_rejected():
    for html in ("<html/>", page(document()) * 2, '<script class="boot_args">{</script>'):
        with pytest.raises(FidoError):
            parse_auth_page(html)


def test_no_secret_repr():
    c = parse_auth_page(page(document()))
    assert b64(c.challenge) not in repr(c)
    assert "credential" not in repr(c)


def test_hsa2_base64_not_primary_securitykey_base64url():
    c = parse_auth_page(page(document()))
    r = response(c)
    p = apple_payload(c, r)
    assert p == {
        "challenge": b64(c.challenge).rstrip("="),
        "clientData": b64(bytes(r.response.client_data)),
        "signatureData": b64(b"FAKE-SIGNATURE"),
        "authenticatorData": b64(bytes(r.response.authenticator_data)),
        "credentialID": b64(c.credential_ids[0]).rstrip("="),
        "userHandle": "",
        "rpId": "apple.com",
    }
    assert "requestId" not in p


@pytest.mark.parametrize(
    "what", ["challenge", "origin", "type", "rp_hash", "up", "credential", "cross_origin"]
)
def test_assertion_must_match_challenge(what):
    c = parse_auth_page(page(document()))
    r = response(c)
    cd = json.loads(bytes(r.response.client_data))
    ad = bytes(r.response.authenticator_data)
    cred = r.raw_id
    if what == "challenge":
        cd["challenge"] = "ZGlmZmVyZW50"
    if what == "origin":
        cd["origin"] = "https://evil.example"
    if what == "type":
        cd["type"] = "webauthn.create"
    if what == "cross_origin":
        cd["crossOrigin"] = True
    if what == "rp_hash":
        ad = b"x" * 32 + ad[32:]
    if what == "up":
        ad = ad[:32] + b"\0" + ad[33:]
    if what == "credential":
        cred = b"other"
    bad = AuthenticationResponse(
        raw_id=cred,
        response=AuthenticatorAssertionResponse(
            client_data=CollectedClientData(json.dumps(cd).encode()),
            authenticator_data=AuthenticatorData(ad),
            signature=b"FAKE-SIGNATURE",
        ),
    )
    with pytest.raises(FidoError):
        apple_payload(c, bad)


class FakeAccount:
    """Explicit SDK fixture; never communicates with Apple."""

    login_state = LoginState.REQUIRE_2FA

    def __init__(self, final=LoginState.AUTHENTICATED):
        self.calls = []
        self.final = final

    async def _fido_request(self, method, path, data=None):
        self.calls.append((method, path))
        return page(document()) if method == "GET" else ""

    async def _gsa_authenticate(self):
        self.calls.append("gsa")
        self.login_state = self.final
        return self.final

    async def _login_mobileme(self):
        self.calls.append("mobileme")
        self.login_state = LoginState.LOGGED_IN
        return self.login_state


def test_full_adapter_order_fixture():
    a = FakeAccount()
    assert asyncio.run(complete_second_factor(cast("Any", a), response)) == LoginState.LOGGED_IN
    assert a.calls == [("GET", "/auth"), ("POST", "/auth/verify/security/key"), "gsa", "mobileme"]


def test_post_success_is_not_login_success():
    a = FakeAccount(LoginState.REQUIRE_2FA)
    with pytest.raises(FidoError):
        asyncio.run(complete_second_factor(cast("Any", a), response))
    assert "mobileme" not in a.calls


def test_no_retry_after_rejected_assertion():
    a = FakeAccount()

    async def reject(method, path, data=None):
        a.calls.append(method)
        if method == "POST":
            raise FidoError("HTTP 401")
        return page(document())

    a._fido_request = reject
    with pytest.raises(FidoError):
        asyncio.run(complete_second_factor(cast("Any", a), response))
    assert a.calls == ["GET", "POST"]


def test_no_submit_after_cancel():
    a = FakeAccount()

    def cancel(c):
        raise FidoError("cancelled")

    with pytest.raises(FidoError):
        asyncio.run(complete_second_factor(cast("Any", a), cancel))
    assert a.calls == [("GET", "/auth")]


def test_wrong_state_no_requests():
    a = FakeAccount()
    a.login_state = LoginState.LOGGED_OUT
    with pytest.raises(FidoError):
        asyncio.run(complete_second_factor(cast("Any", a), response))
    assert not a.calls


def test_tls_enabled():
    import ssl

    c = apple_ssl_context()
    assert c.verify_mode == ssl.CERT_REQUIRED
    assert c.check_hostname


@pytest.mark.parametrize(
    "url",
    [
        "http://gsa.apple.com/auth",
        "https://gsa.apple.com.evil.example/auth",
        "https://u:p@gsa.apple.com/auth",
        "https://gsa.apple.com/auth#secret",
        "https://gsa.apple.com/auth?redirect=evil",
        "https://gateway.icloud.com/findmyservice/v2/fetch",
    ],
)
def test_auth_transport_blocks_unapproved_destinations(url):
    async def run():
        h = CheckedHttpSession()
        try:
            with pytest.raises(FidoError):
                await h.request("GET", url)
        finally:
            await h.close()

    asyncio.run(run())
