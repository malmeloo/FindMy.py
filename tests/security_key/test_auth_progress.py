"""Synthetic GSA responses only. Ensure observability doesn't leak any raw response."""

import asyncio
import contextlib
import json
from typing import Any, cast
from unittest.mock import AsyncMock, patch

from apple_fido import FidoAppleAccount, complete_second_factor
from test_protocol import FakeAccount, response
from test_safety import DummyAnisette

from findmy import AsyncAppleAccount, LoginState


def test_gsa_numeric_status_only_no_response_or_error_message():
    async def run():
        a = FidoAppleAccount(cast("Any", DummyAnisette()))
        events = []
        a.on_progress = events.append
        raw = {
            "Status": {"ec": -22406, "em": "SYNTHETIC SECRET", "au": "SYNTHETIC TOKEN"},
            "spd": b"SYNTHETIC ENCRYPTED PAYLOAD",
        }
        try:
            with patch.object(AsyncAppleAccount, "_gsa_request", AsyncMock(return_value=raw)):
                assert await a._gsa_request({"o": "init", "u": "SYNTHETIC ACCOUNT"}) is raw
                a._fido_attempted = True
                await a._gsa_request({"o": "complete", "M1": b"SYNTHETIC PROOF"})
            assert events == [
                {"stage": "initial_gsa_init_response", "apple_error_code": -22406},
                {"stage": "post_key_gsa_complete_response", "apple_error_code": -22406},
            ]
            assert "SYNTHETIC" not in json.dumps(events)
        finally:
            await a.close()

    asyncio.run(run())


def test_unsupported_error_code_types_not_echoed():
    async def run():
        a = FidoAppleAccount(cast("Any", DummyAnisette()))
        events = []
        a.on_progress = events.append
        try:
            for value in ("SYNTHETIC SECRET", True, None, {"token": "SYNTHETIC"}, 10**99):
                with patch.object(
                    AsyncAppleAccount,
                    "_gsa_request",
                    AsyncMock(return_value={"Status": {"ec": value}}),
                ):
                    await a._gsa_request({"o": "SYNTHETIC SECRET"})
            assert len(events) == 5
            assert all(
                e == {"stage": "initial_gsa_unknown_response", "apple_error_code": "UNAVAILABLE"}
                for e in events
            )
        finally:
            await a.close()

    asyncio.run(run())


def test_progress_distinguishes_signing_post_and_reauthentication():
    a = cast("Any", FakeAccount())
    events = []
    a.on_progress = events.append
    assert asyncio.run(complete_second_factor(a, response)) == LoginState.LOGGED_IN
    assert [e["stage"] for e in events] == [
        "key_assertion_created",
        "post_key_gsa_start",
        "mobileme_login_start",
    ]


def test_failed_post_must_not_claim_reauthentication_started():
    a = cast("Any", FakeAccount())
    events = []
    a.on_progress = events.append
    original = a._fido_request

    async def fail(method, path, data=None):
        if method == "POST":
            raise RuntimeError("SYNTHETIC FAILURE")
        return await original(method, path, data)

    a._fido_request = fail
    with contextlib.suppress(RuntimeError):
        asyncio.run(complete_second_factor(a, response))
    assert events == [{"stage": "key_assertion_created"}]
    assert "gsa" not in a.calls
