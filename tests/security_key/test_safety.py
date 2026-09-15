"""Offline safety tests; all identifiers and tokens are synthetic fixtures."""

import asyncio
import json
import stat
import subprocess
import sys
from typing import Any, cast

import login
import pytest
from apple_fido import FidoError
from fido2.ctap2.pin import ClientPin

from findmy import AsyncAppleAccount, LoginState
from findmy.util.http import HttpSession


class DummyAnisette:
    async def close(self):
        pass

    def to_json(self):
        return {"type": "aniLocal", "prov_data": None}


class FakeStream:
    def __init__(self, chunks):
        self.chunks = chunks

    async def read(self):
        return b"".join(self.chunks)

    async def iter_chunked(self, size):
        del size
        for chunk in self.chunks:
            yield chunk


class FakeResponse:
    def __init__(self, status=200, chunks=(b"{}",)):
        self.status = status
        self.content = FakeStream(chunks)
        self.headers = {
            "Scnt": "SYNTHETIC-CONTINUATION",
            "X-Apple-ID-Session-Id": "SYNTHETIC-SESSION",
        }

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    async def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.response

    async def close(self):
        pass


def test_http_session_bounds_response_preserves_headers_and_disables_redirects():
    async def run():
        http = HttpSession()
        session = FakeSession(FakeResponse(chunks=(b"one", b"two")))
        http._session = cast("Any", session)
        try:
            response = await http.get(
                "https://gsa.apple.com/auth",
                allow_redirects=False,
                max_response_size=6,
            )
            assert response.text() == "onetwo"
            assert response.headers["scnt"] == "SYNTHETIC-CONTINUATION"
            assert response.headers["x-apple-id-session-id"] == "SYNTHETIC-SESSION"
            assert session.calls[0][1]["allow_redirects"] is False
            assert session.calls[0][1]["ssl"].check_hostname
        finally:
            await http.close()

    asyncio.run(run())


def test_http_session_rejects_oversized_response():
    async def run():
        http = HttpSession()
        session = FakeSession(FakeResponse(chunks=(b"123", b"4567")))
        http._session = cast("Any", session)
        try:
            with pytest.raises(ValueError, match="size limit"):
                await http.get("https://gsa.apple.com/auth", max_response_size=6)
            assert len(session.calls) == 1
        finally:
            await http.close()

    asyncio.run(run())


def test_private_save_uses_sdk_serialization_and_removes_password(tmp_path, monkeypatch):
    monkeypatch.setattr(login, "DATA", tmp_path)
    account = AsyncAppleAccount(cast("Any", DummyAnisette()))
    account._username = "synthetic@example.invalid"
    account._password = "SYNTHETIC-PASSWORD"
    account._set_login_state(
        LoginState.LOGGED_IN,
        {"mobileme_data": {"tokens": {"searchPartyToken": "SYNTHETIC-TOKEN"}}},
    )
    try:
        login.save_session(account)
        raw = (tmp_path / "session.json").read_bytes()
        assert b"SYNTHETIC-PASSWORD" not in raw
        assert json.loads(raw)["account"]["password"] is None
        assert stat.S_IMODE((tmp_path / "session.json").stat().st_mode) == 0o600
        with pytest.raises(FileExistsError):
            login.save_session(account)
        assert (tmp_path / "session.json").read_bytes() == raw
    finally:
        asyncio.run(account.close())


def test_no_save_without_findmy_token(tmp_path, monkeypatch):
    monkeypatch.setattr(login, "DATA", tmp_path)
    account = AsyncAppleAccount(cast("Any", DummyAnisette()))
    account._set_login_state(LoginState.LOGGED_IN, {"mobileme_data": {}})
    try:
        with pytest.raises(FidoError):
            login.save_session(account)
        assert not (tmp_path / "session.json").exists()
    finally:
        asyncio.run(account.close())


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
    monkeypatch.setattr(
        login.getpass,
        "getpass",
        lambda prompt: called.append(prompt) or "TEST-PIN",
    )
    interaction = login.TerminalInteraction()
    assert interaction.request_pin(ClientPin.PERMISSION.GET_ASSERTION, "apple.com") == "TEST-PIN"
    with pytest.raises(FidoError):
        interaction.request_pin(ClientPin.PERMISSION.GET_ASSERTION, "apple.com")
    assert len(called) == 1


def test_cli_blocks_noninteractive_login_and_does_not_leak():
    result = subprocess.run(
        [sys.executable, str(login.ROOT / "login.py"), "--login"],
        check=False,
        input="SYNTHETIC-PASSWORD\n",
        text=True,
        capture_output=True,
    )
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "blocked"
    assert "SYNTHETIC-PASSWORD" not in result.stdout + result.stderr
    assert not result.stderr
