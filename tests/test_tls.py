"""Tests for the trust store, and for verification being on unless it is turned off."""

from __future__ import annotations

import hashlib
import ssl

import pytest

from findmy.reports.anisette import RemoteAnisetteProvider
from findmy.util.http import HttpSession
from findmy.util.tls import (
    APPLE_ROOT_CA_PEM,
    APPLE_ROOT_CA_SHA256,
    TlsError,
    apple_trust_context,
    tls_setting,
)

def _common_names(context: ssl.SSLContext) -> set[str]:
    """Every trust anchor the context holds, by common name."""
    return {
        value
        for certificate in context.get_ca_certs()
        for group in certificate.get("subject", ())
        for key, value in group
        if key == "commonName"
    }


def test_the_bundled_root_is_the_certificate_it_claims_to_be() -> None:
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(APPLE_ROOT_CA_PEM)).digest()

    assert digest == APPLE_ROOT_CA_SHA256
    assert digest.hex() == "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"


def test_a_root_that_does_not_match_its_fingerprint_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A trust anchor is only an anchor once it hashes to what it should. Catching a mangled
    # copy here means failing at import rather than at the first handshake, where it would
    # read as Apple's server being unreachable.
    monkeypatch.setattr("findmy.util.tls.APPLE_ROOT_CA_SHA256", b"\x00" * 32)
    apple_trust_context.cache_clear()

    with pytest.raises(TlsError, match="Refusing to trust it"):
        apple_trust_context()

    apple_trust_context.cache_clear()


def test_the_context_adds_apples_root_to_the_platforms_own() -> None:
    context = apple_trust_context()

    assert "Apple Root CA" in _common_names(context)
    # The check above is only worth making if it can fail: an empty context has no anchors,
    # and this is what distinguishes "the root was loaded" from "the helper always says
    # yes". The platform store cannot serve as the negative case -- macOS ships this root
    # and Mozilla-derived stores do not, which is the whole reason for bundling it.
    assert "Apple Root CA" not in _common_names(ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))

    # Added *on top of* the defaults, not instead of them: adding a trust anchor does not
    # weaken the ones already there, and a context holding only Apple's root would refuse
    # every other host this library talks to.
    assert len(context.get_ca_certs()) > 1

    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname


def test_verification_is_on_unless_it_is_turned_off() -> None:
    assert tls_setting(verify=True) is apple_trust_context()
    assert tls_setting(verify=False) is False


def test_disabling_verification_says_so(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING"):
        tls_setting(verify=False)

    assert "network path" in caplog.text


# These construct a session without ever making a request, so no aiohttp session is
# created and there is nothing to close -- which keeps them synchronous.


def test_an_http_session_verifies_by_default() -> None:
    assert HttpSession()._ssl is apple_trust_context()  # noqa: SLF001


def test_an_http_session_can_be_told_not_to() -> None:
    assert HttpSession(verify_tls=False)._ssl is False  # noqa: SLF001


def test_an_anisette_provider_verifies_by_default() -> None:
    provider = RemoteAnisetteProvider("https://ani.example/")

    assert provider._http._ssl is apple_trust_context()  # noqa: SLF001
    assert provider.to_json() == {"type": "aniRemote", "url": "https://ani.example/"}


def test_the_opt_in_reaches_the_session_and_survives_a_round_trip() -> None:
    # It has to be serialized, or saving and reloading an account would silently turn a
    # working self-signed setup into a failing one.
    provider = RemoteAnisetteProvider("https://ani.example/", allow_unverified_https=True)
    assert provider._http._ssl is False  # noqa: SLF001

    state = provider.to_json()
    assert state["allow_unverified_https"] is True

    assert RemoteAnisetteProvider.from_json(state)._http._ssl is False  # noqa: SLF001


def test_an_older_saved_provider_still_loads_and_verifies() -> None:
    # A file written before this option existed carries no flag, and must keep working --
    # verifying, which is the safe direction for a default to move in.
    restored = RemoteAnisetteProvider.from_json({"type": "aniRemote", "url": "https://a/"})

    assert restored._http._ssl is apple_trust_context()  # noqa: SLF001
