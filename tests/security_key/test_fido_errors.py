"""Synthetic exceptions/time only: no PIN attempts and no Apple connection."""

import json
from unittest.mock import patch

import pytest
from apple_fido import Challenge, sign_usb
from fido2.client import ClientError, UserInteraction
from fido2.ctap import CtapError
from fido_errors import safe_fido_error
from test_ctap import SyntheticAuthenticator


@pytest.mark.parametrize("code", list(ClientError.ERR))
def test_never_print_exception_cause(code):
    error = ClientError(code, ValueError("SYNTHETIC-SECRET-PIN"))
    out = safe_fido_error(error)
    assert out["client_code"] == code.name
    assert out["ctap_code"] == "UNAVAILABLE"
    assert "SYNTHETIC" not in json.dumps(out)
    assert out["retry"] is False


@pytest.mark.parametrize(
    "code",
    [
        CtapError.ERR.PIN_INVALID,
        CtapError.ERR.PIN_BLOCKED,
        CtapError.ERR.PIN_AUTH_BLOCKED,
        CtapError.ERR.NO_CREDENTIALS,
        CtapError.ERR.KEEPALIVE_CANCEL,
        CtapError.ERR.OTHER,
    ],
)
def test_ctap_enum_only(code):
    out = safe_fido_error(ClientError(ClientError.ERR.OTHER_ERROR, CtapError(code)))
    assert out["ctap_code"] == code.name
    assert out["client_code"] == "OTHER_ERROR"


def test_client_timer_allows_90_seconds_including_pin_entry():
    timers = []

    class TimerFixture:
        def __init__(self, seconds, callback):
            self.seconds = seconds
            self.cancelled = False
            timers.append(self)

        def start(self):
            pass

        def cancel(self):
            self.cancelled = True

    device = SyntheticAuthenticator()
    challenge = Challenge(b"TEST-CHALLENGE-16", "apple.com", (device.credential_id,))
    with patch("fido2.client.Timer", TimerFixture):
        result = sign_usb(challenge, device, UserInteraction())
    assert result.raw_id == device.credential_id
    assert timers
    assert timers[0].seconds == 90
    assert timers[0].cancelled


def test_cli_reports_only_error_codes(monkeypatch, capsys):
    import login

    monkeypatch.setattr(login.sys, "argv", ["login.py", "--preflight"])
    monkeypatch.setattr(login.resource, "setrlimit", lambda *a: None)
    monkeypatch.setattr(login.os, "umask", lambda *a: 0o077)
    monkeypatch.setattr(login.logging, "disable", lambda *a: None)

    async def fail():
        raise ClientError(ClientError.ERR.TIMEOUT, ValueError("SYNTHETIC-SECRET"))

    monkeypatch.setattr(login, "preflight", fail)
    assert login.main() == 1
    captured = capsys.readouterr()
    out = json.loads(captured.out)
    assert out["client_code"] == "TIMEOUT"
    assert out["ctap_code"] == "UNAVAILABLE"
    assert "SYNTHETIC-SECRET" not in captured.out + captured.err
