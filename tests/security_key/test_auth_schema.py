"""Diagnostics use synthetic secrets only; no Apple connection or USB access."""

import asyncio
import json
import stat
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock

import login
import pytest
from apple_fido import FidoError, LoginState, parse_auth_page
from auth_schema import summarize_auth_page


def html(data):
    return '<script class="boot_args">' + json.dumps(data) + "</script>"


def test_value_and_dynamic_key_redaction():
    data = {
        "direct": {
            "account": {"TEST-SECRET-KEY": "TEST-SECRET-VALUE"},
            "authFactors": ["fsa2_hsa2", "TEST-SECRET-FACTOR"],
            "fsaVerification": {
                "fsaChallenge": {
                    "challenge": "TEST-SECRET-CHALLENGE",
                    "rpId": "TEST-SECRET-RP",
                    "keyHandles": ["TEST-SECRET-HANDLE"],
                    "requestId": "TEST-SECRET-REQUEST",
                }
            },
            "TEST-SECRET-EMAIL": "anything",
        }
    }
    result = summarize_auth_page(html(data))
    encoded = json.dumps(result)
    assert "TEST-SECRET" not in encoded
    assert "fsa2_hsa2" in encoded
    assert any(
        r["path"] == "$.direct.fsaVerification.fsaChallenge.challenge" and r["type"] == "string"
        for r in result["fields"]
    )
    assert result["raw_values_saved"] is False


def test_reproduce_generic_missing_field_failure_and_expose_only_schema():
    doc = {"direct": {"fsaVerification": {"fsaChallenge": {"challenge": "TEST-SECRET"}}}}
    with pytest.raises(FidoError, match="Unsupported Apple challenge structure"):
        parse_auth_page(html(doc))
    result = summarize_auth_page(html(doc))
    assert not any(x["path"].endswith(".authFactors") for x in result["fields"])
    assert "TEST-SECRET" not in json.dumps(result)


@pytest.mark.parametrize(
    "document",
    [
        "<html/>",
        '<script class="boot_args">{invalid secret</script>',
        '<script class="boot_args">{"direct":1,"direct":2}</script>',
        '<script class="boot_args">{}</script>' * 2,
        "x" * 2_000_001,
    ],
)
def test_bad_input_contains_no_original_data(document):
    result = summarize_auth_page(document)
    assert result["parse_status"] != "ok"
    assert "invalid secret" not in json.dumps(result)


def test_nested_and_array_redaction_bounded():
    value = {"id": "TEST-SECRET"}
    for _ in range(30):
        value = {"data": [value]}
    out = summarize_auth_page(html(value))
    assert out["truncated"]
    assert len(out["fields"]) <= 240
    assert "TEST-SECRET" not in json.dumps(out)


def prepare(monkeypatch, tmp_path, state=LoginState.REQUIRE_2FA):
    data = tmp_path / "data"
    data.mkdir(mode=0o700)
    old = data / "anisette.bin"
    old.write_bytes(b"EXISTING-FIXTURE-DO-NOT-READ")
    monkeypatch.setattr(login, "DATA", data)
    for stream in (login.sys.stdin, login.sys.stdout, login.sys.stderr):
        monkeypatch.setattr(stream, "isatty", lambda: True)
    answers = iter(["YES", "SYNTHETIC-ID"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    monkeypatch.setattr(login.getpass, "getpass", lambda _: "SYNTHETIC-PASSWORD")
    monkeypatch.setattr(login, "LocalAnisetteProvider", lambda **kw: None)
    a = SimpleNamespace(
        _password="SYNTHETIC-PASSWORD",
        _gsa_authenticate=AsyncMock(return_value=state),
        _fido_request=AsyncMock(
            return_value=html({"direct": {"challenge": "SYNTHETIC-CHALLENGE"}})
        ),
        close=AsyncMock(),
    )
    monkeypatch.setattr(login, "FidoAppleAccount", lambda _: a)

    def forbid(*args, **kw):
        raise AssertionError("Must not sign, enumerate USB or save session")

    for name in ("save_session", "sign_usb", "devices"):
        monkeypatch.setattr(login, name, forbid)
    return data, old, a


def test_diagnostic_flow_single_get_no_sign_no_session_private_file(monkeypatch, tmp_path, capsys):
    data, old, a = prepare(monkeypatch, tmp_path)
    assert asyncio.run(login.diagnose_auth()) == 0
    a._gsa_authenticate.assert_awaited_once()
    a._fido_request.assert_awaited_once_with("GET", "/auth")
    a.close.assert_awaited_once()
    assert a._password is None
    files = list(data.glob("schema-*/diagnostic.json"))
    assert len(files) == 1
    assert stat.S_IMODE(files[0].stat().st_mode) == 0o600
    assert stat.S_IMODE(files[0].parent.stat().st_mode) == 0o700
    assert not list(data.rglob("session.json"))
    assert old.read_bytes() == b"EXISTING-FIXTURE-DO-NOT-READ"
    captured = capsys.readouterr()
    assert "SYNTHETIC" not in captured.out + captured.err + files[0].read_text()


def test_no_2fa_stops_before_get(monkeypatch, tmp_path):
    data, _old, a = prepare(monkeypatch, tmp_path, LoginState.AUTHENTICATED)
    with pytest.raises(FidoError):
        asyncio.run(login.diagnose_auth())
    a._fido_request.assert_not_awaited()
    assert not list(data.rglob("diagnostic.json"))
    assert a._password is None


def test_diagnostic_cli_requires_private_terminal():
    r = subprocess.run(
        [sys.executable, str(login.ROOT / "login.py"), "--diagnose-auth"],
        check=False,
        input="",
        text=True,
        capture_output=True,
    )
    assert r.returncode == 2
    assert json.loads(r.stdout)["status"] == "blocked"
    assert r.stderr == ""
