"""Synthetic tests for isolated attempts in the optional native-security-key CLI."""

import asyncio
import stat
from types import SimpleNamespace
from unittest.mock import AsyncMock

import login
import pytest


def test_new_attempt_does_not_read_overwrite_or_remove_existing(tmp_path, monkeypatch):
    monkeypatch.setattr(login, "DATA", tmp_path)
    old = tmp_path / "anisette.bin"
    old.write_bytes(b"SYNTHETIC OLD")
    session = tmp_path / "session.json"
    session.write_bytes(b"SYNTHETIC SESSION")
    with pytest.raises(login.FidoError):
        login.prepare_private_directory()
    first = login.prepare_private_directory(fresh=True)
    second = login.prepare_private_directory(fresh=True)
    assert first != second
    assert first.parent == tmp_path
    assert first.name.startswith("login-")
    assert stat.S_IMODE(first.stat().st_mode) == 0o700
    assert not list(first.iterdir())
    assert old.read_bytes() == b"SYNTHETIC OLD"
    assert session.read_bytes() == b"SYNTHETIC SESSION"


def test_fresh_attempt_rejects_symlink_parent(tmp_path, monkeypatch):
    link = tmp_path / "link"
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    link.symlink_to(target)
    monkeypatch.setattr(login, "DATA", link)
    with pytest.raises(login.FidoError):
        login.prepare_private_directory(fresh=True)
    assert not list(target.iterdir())


def test_login_cli_uses_native_factor_and_separate_attempt(tmp_path, monkeypatch):
    monkeypatch.setattr(login, "DATA", tmp_path)
    old = tmp_path / "anisette.bin"
    old.write_bytes(b"SYNTHETIC OLD")
    for stream in (login.sys.stdin, login.sys.stdout, login.sys.stderr):
        monkeypatch.setattr(stream, "isatty", lambda: True)
    prompts = iter(["YES", "synthetic@example.invalid"])
    monkeypatch.setattr("builtins.input", lambda _: next(prompts))
    monkeypatch.setattr(login.getpass, "getpass", lambda _: "SYNTHETIC PASSWORD")
    key = SimpleNamespace(close=lambda: None)
    monkeypatch.setattr(login, "devices", lambda: [key])
    providers = []
    monkeypatch.setattr(login, "LocalAnisetteProvider", lambda **kw: providers.append(kw) or None)

    class SyntheticSecurityKeyFactor:
        def __init__(self):
            self.authenticate = AsyncMock(return_value=login.LoginState.LOGGED_IN)

    factor = SyntheticSecurityKeyFactor()
    account = SimpleNamespace(
        _password="SYNTHETIC PASSWORD",
        login=AsyncMock(return_value=login.LoginState.REQUIRE_2FA),
        get_2fa_methods=AsyncMock(return_value=[factor]),
        close=AsyncMock(),
    )
    monkeypatch.setattr(login, "AsyncSecurityKeySecondFactor", SyntheticSecurityKeyFactor)
    monkeypatch.setattr(login, "AsyncAppleAccount", lambda _: account)
    saves = []
    monkeypatch.setattr(
        login,
        "save_session",
        lambda instance, directory=None: saves.append(directory),
    )

    assert asyncio.run(login.login()) == 0
    assert saves[0].parent == tmp_path
    assert saves[0].name.startswith("login-")
    assert providers[0]["libs_path"] == saves[0] / "anisette.bin"
    assert old.read_bytes() == b"SYNTHETIC OLD"
    assert account._password is None
    account.get_2fa_methods.assert_awaited_once_with()
    factor.authenticate.assert_awaited_once()
