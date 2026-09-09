"""Observed GSA structural variant; all field VALUES below are synthetic."""

import asyncio
import base64
import stat
from types import SimpleNamespace
from unittest.mock import AsyncMock

import login
import pytest
from apple_fido import FidoError, parse_auth_page
from test_protocol import document, page


def observed_shape():
    d = document()
    del d["direct"]["authFactors"]
    d["direct"]["fsaVerification"]["fsaChallenge"]["keyHandles"].append(
        base64.b64encode(b"SYNTHETIC-SECOND-HANDLE").decode()
    )
    return d


def test_observed_direct_shape_without_authfactors():
    c = parse_auth_page(page(observed_shape()))
    assert c.rp_id == "apple.com"
    assert len(c.credential_ids) == 2
    assert c.options().user_verification == "preferred"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d["direct"]["fsaVerification"]["fsaChallenge"].pop("rpId"),
        lambda d: d["direct"]["fsaVerification"]["fsaChallenge"].pop("challenge"),
        lambda d: d["direct"]["fsaVerification"]["fsaChallenge"].pop("keyHandles"),
        lambda d: d["direct"]["fsaVerification"]["fsaChallenge"].update(rpId="evil.example"),
        lambda d: d["direct"]["fsaVerification"]["fsaChallenge"].update(keyHandles=[]),
        lambda d: d["direct"]["fsaVerification"]["fsaChallenge"].update(challenge="YQ=="),
        lambda d: d["direct"].update(authFactors=None),
        lambda d: d["direct"].update(authFactors=[]),
        lambda d: d["direct"].update(authFactors=["fsa1"]),
        lambda d: d["direct"].update(authFactors=["fsa2"]),
        lambda d: d["direct"].update(referrerQuery="?x=evil"),
        lambda d: d["direct"]["fsaVerification"]["fsaChallenge"].update(requirePrf=True),
    ],
)
def test_observed_variant_still_fails_closed(mutation):
    d = observed_shape()
    mutation(d)
    with pytest.raises(FidoError):
        parse_auth_page(page(d))


def test_nested_without_factor_not_observed_so_rejected():
    d = observed_shape()
    d["direct"] = {"twoSV": d["direct"]}
    with pytest.raises(FidoError):
        parse_auth_page(page(d))


def test_new_attempt_does_not_read_overwrite_or_remove_existing(tmp_path, monkeypatch):
    monkeypatch.setattr(login, "DATA", tmp_path)
    old = tmp_path / "anisette.bin"
    old.write_bytes(b"SYNTHETIC OLD")
    session = tmp_path / "session.json"
    session.write_bytes(b"SYNTHETIC SESSION")
    with pytest.raises(FidoError):
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
    with pytest.raises(FidoError):
        login.prepare_private_directory(fresh=True)
    assert not list(target.iterdir())


def test_login_cli_uses_separate_attempt_and_session_destination(tmp_path, monkeypatch):
    monkeypatch.setattr(login, "DATA", tmp_path)
    old = tmp_path / "anisette.bin"
    old.write_bytes(b"SYNTHETIC OLD")
    for stream in (login.sys.stdin, login.sys.stdout, login.sys.stderr):
        monkeypatch.setattr(stream, "isatty", lambda: True)
    prompts = iter(["YES", "SYNTHETIC ID"])
    monkeypatch.setattr("builtins.input", lambda _: next(prompts))
    monkeypatch.setattr(login.getpass, "getpass", lambda _: "SYNTHETIC PASSWORD")
    key = SimpleNamespace(close=lambda: None)
    monkeypatch.setattr(login, "devices", lambda: [key])
    providers = []
    monkeypatch.setattr(login, "LocalAnisetteProvider", lambda **kw: providers.append(kw) or None)
    account = SimpleNamespace(
        _password="SYNTHETIC PASSWORD",
        login=AsyncMock(return_value=login.LoginState.REQUIRE_2FA),
        authenticate_security_key=AsyncMock(return_value=login.LoginState.LOGGED_IN),
        close=AsyncMock(),
    )
    monkeypatch.setattr(login, "FidoAppleAccount", lambda _: account)
    saves = []
    monkeypatch.setattr(login, "save_session", lambda a, directory=None: saves.append(directory))
    assert asyncio.run(login.login()) == 0
    assert saves[0].parent == tmp_path
    assert saves[0].name.startswith("login-")
    assert providers[0]["libs_path"] == saves[0] / "anisette.bin"
    assert old.read_bytes() == b"SYNTHETIC OLD"
    assert account._password is None
