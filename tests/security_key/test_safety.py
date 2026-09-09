"""Offline safety tests; all identifiers/tokens below are fabricated fixtures."""

import asyncio
import json
import stat
import subprocess
import sys
from typing import Any, cast
from unittest.mock import AsyncMock

import apple_fido
import login
import pytest
from apple_fido import CheckedHttpSession, FidoAppleAccount, FidoError
from fido2.ctap2.pin import ClientPin
from test_protocol import document, page, response

from findmy import LoginState
from findmy.util.http import HttpResponse


class DummyAnisette:
    async def close(self):
        pass

    def to_json(self):
        return {"type": "aniLocal", "prov_data": None}


def test_real_sdk_adapter_get_post_headers_and_one_shot():
    async def run():
        a = FidoAppleAccount(cast("Any", DummyAnisette()))
        a._set_login_state(LoginState.REQUIRE_2FA, {"adsid": "TEST-ID", "idms_token": "TEST-TOKEN"})
        a.get_anisette_headers = AsyncMock(return_value={})
        a._http.request = AsyncMock(
            side_effect=[HttpResponse(200, page(document()).encode()), HttpResponse(250, b"")]
        )
        a._gsa_authenticate = AsyncMock(return_value=LoginState.AUTHENTICATED)
        a._login_mobileme = AsyncMock(return_value=LoginState.LOGGED_IN)
        try:
            result = await a.authenticate_security_key(response)
            assert result == LoginState.LOGGED_IN
            calls = a._http.request.call_args_list
            assert calls[0].args == ("GET", apple_fido.ORIGIN + "/auth")
            assert calls[1].args == ("POST", apple_fido.ORIGIN + "/auth/verify/security/key")
            assert calls[1].kwargs["headers"]["Origin"] == apple_fido.ORIGIN
            assert (
                calls[1].kwargs["headers"]["X-Apple-Identity-Token"] == "VEVTVC1JRDpURVNULVRPS0VO"
            )
            assert calls[1].kwargs["json"]["rpId"] == "apple.com"
            with pytest.raises(FidoError):
                await a.authenticate_security_key(response)
            assert a._http.request.call_count == 2
        finally:
            await a.close()

    asyncio.run(run())


@pytest.mark.parametrize("status", [201, 202, 302, 400, 401, 409, 412, 423, 429, 500])
def test_nonterminal_or_error_http_must_not_reauthenticate(status):
    async def run():
        a = FidoAppleAccount(cast("Any", DummyAnisette()))
        a._set_login_state(LoginState.REQUIRE_2FA, {"adsid": "TEST-ID", "idms_token": "TEST-TOKEN"})
        a.get_anisette_headers = AsyncMock(return_value={})
        a._http.request = AsyncMock(
            side_effect=[
                HttpResponse(200, page(document()).encode()),
                HttpResponse(status, b"SENSITIVE BODY"),
            ]
        )
        a._gsa_authenticate = AsyncMock()
        try:
            with pytest.raises(FidoError) as err:
                await a.authenticate_security_key(response)
            assert "SENSITIVE" not in str(err.value)
            a._gsa_authenticate.assert_not_called()
        finally:
            await a.close()

    asyncio.run(run())


class FakeStream:
    def __init__(self, chunks):
        self.chunks = chunks

    async def iter_chunked(self, size):
        for chunk in self.chunks:
            yield chunk


class FakeResponse:
    def __init__(self, status=200, chunks=(b"{}",)):
        self.status = status
        self.content = FakeStream(chunks)
        self.headers = {"scnt": "SYNTHETIC-CONTINUATION"}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.response

    async def close(self):
        pass


def test_transport_tls_no_redirect_and_continuation():
    async def run():
        h = CheckedHttpSession()
        s = FakeSession(FakeResponse())
        h._session = cast("Any", s)
        try:
            await h.get(apple_fido.ORIGIN + "/auth")
            await h.post(apple_fido.ORIGIN + "/auth/verify/security/key", json={})
            await h.post("https://setup.icloud.com/setup/iosbuddy/loginDelegates", data=b"fixture")
            assert s.calls[0][1]["allow_redirects"] is False
            assert s.calls[0][1]["ssl"].check_hostname
            assert s.calls[1][1]["headers"]["scnt"] == "SYNTHETIC-CONTINUATION"
            assert "scnt" not in s.calls[2][1]["headers"]
            assert s.calls[2][1]["ssl"] is h.standard_context
        finally:
            await h.close()

    asyncio.run(run())


@pytest.mark.parametrize("reply", [FakeResponse(302), FakeResponse(200, (b"x" * 2_000_001,))])
def test_transport_rejects_redirect_and_large_response_without_retry(reply):
    async def run():
        h = CheckedHttpSession()
        s = FakeSession(reply)
        h._session = cast("Any", s)
        try:
            with pytest.raises(FidoError):
                await h.get(apple_fido.ORIGIN + "/auth")
            assert len(s.calls) == 1
        finally:
            await h.close()

    asyncio.run(run())


@pytest.mark.parametrize("opts", [{"ssl": False}, {"auto_retry": True}, {"allow_redirects": True}])
def test_no_caller_can_disable_transport_guards(opts):
    async def run():
        h = CheckedHttpSession()
        s = FakeSession(FakeResponse())
        h._session = cast("Any", s)
        try:
            with pytest.raises(FidoError):
                await h.get(apple_fido.ORIGIN + "/auth", **opts)
            assert not s.calls
        finally:
            await h.close()

    asyncio.run(run())


def test_expired_challenge():
    from dataclasses import replace

    c = apple_fido.parse_auth_page(page(document()))
    with pytest.raises(FidoError):
        replace(c, created=c.created - 121).options()


def test_private_save_uses_actual_sdk_serialization_and_removes_password(tmp_path, monkeypatch):
    monkeypatch.setattr(login, "DATA", tmp_path)
    a = FidoAppleAccount(cast("Any", DummyAnisette()))
    a._username = "SYNTHETIC"
    a._password = "SYNTHETIC-PASSWORD"
    a._set_login_state(
        LoginState.LOGGED_IN, {"mobileme_data": {"tokens": {"searchPartyToken": "SYNTHETIC-TOKEN"}}}
    )
    try:
        login.save_session(a)
        raw = (tmp_path / "session.json").read_bytes()
        assert b"SYNTHETIC-PASSWORD" not in raw
        assert json.loads(raw)["account"]["password"] is None
        assert stat.S_IMODE((tmp_path / "session.json").stat().st_mode) == 0o600
        with pytest.raises(FileExistsError):
            login.save_session(a)
        assert (tmp_path / "session.json").read_bytes() == raw
    finally:
        asyncio.run(a.close())


def test_no_save_without_findmy_token(tmp_path, monkeypatch):
    monkeypatch.setattr(login, "DATA", tmp_path)
    a = FidoAppleAccount(cast("Any", DummyAnisette()))
    a._set_login_state(LoginState.LOGGED_IN, {"mobileme_data": {}})
    try:
        with pytest.raises(FidoError):
            login.save_session(a)
        assert not (tmp_path / "session.json").exists()
    finally:
        asyncio.run(a.close())


def test_private_directory_refuses_symlink_or_existing(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(target)
    monkeypatch.setattr(login, "DATA", link)
    with pytest.raises(FidoError):
        login.prepare_private_directory()
    monkeypatch.setattr(login, "DATA", target)
    (target / "session.json").write_text("SYNTHETIC")
    with pytest.raises(FidoError):
        login.prepare_private_directory()
    assert (target / "session.json").read_text() == "SYNTHETIC"


def test_pin_not_retried(monkeypatch):
    called = []
    monkeypatch.setattr(login.getpass, "getpass", lambda prompt: called.append(True) or "TEST-PIN")
    ui = login.TerminalInteraction()
    assert ui.request_pin(ClientPin.PERMISSION.GET_ASSERTION, "apple.com") == "TEST-PIN"
    with pytest.raises(FidoError):
        ui.request_pin(ClientPin.PERMISSION.GET_ASSERTION, "apple.com")
    assert len(called) == 1


def test_cli_blocks_noninteractive_login_and_does_not_leak():
    p = subprocess.run(
        [sys.executable, str(login.ROOT / "login.py"), "--login"],
        check=False,
        input="SYNTHETIC-PASSWORD\n",
        text=True,
        capture_output=True,
    )
    assert p.returncode == 2
    assert json.loads(p.stdout)["status"] == "blocked"
    assert "SYNTHETIC-PASSWORD" not in p.stdout + p.stderr
    assert not p.stderr
