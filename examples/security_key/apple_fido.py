"""Experimental Apple HSA2 security-key adapter.

Verified on one real account; not a stable public API.

Wire format is based on Apple's public home/hsa2 JavaScript; see PROTOCOL.md.
Only authentication is in scope: no location, export, registration or recovery API.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlsplit

import aiohttp
from bs4 import BeautifulSoup
from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.rpid import verify_rp_id
from fido2.webauthn import AuthenticationResponse, PublicKeyCredentialRequestOptions
from typing_extensions import override

from findmy import AsyncAppleAccount, LoginState
from findmy.util.http import HttpResponse, HttpSession

if TYPE_CHECKING:
    from collections.abc import Callable

    from fido2.ctap import CtapDevice

    from findmy.reports.anisette import BaseAnisetteProvider

ORIGIN = "https://gsa.apple.com"
APPLE_ROOT_SHA256 = "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"
LIMIT = 2_000_000
AUTH_URLS = frozenset(
    {
        ORIGIN + "/auth",
        ORIGIN + "/auth/verify/security/key",
        ORIGIN + "/grandslam/GsService2",
        "https://setup.icloud.com/setup/iosbuddy/loginDelegates",
    }
)


class FidoError(Exception):
    """Only static, secret-free messages may cross the CLI boundary."""


def decode64(value: str, *, minimum: int = 1, maximum: int = 4096) -> bytes:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum * 2:
        message = "Invalid binary challenge field."
        raise FidoError(message)
    if not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", value):
        message = "Invalid challenge encoding."
        raise FidoError(message)
    if ("+" in value or "/" in value) and ("-" in value or "_" in value):
        message = "Mixed base64 alphabets in challenge."
        raise FidoError(message)
    try:
        normalized = value.translate(str.maketrans("-_", "+/"))
        decoded = base64.b64decode(normalized + "=" * (-len(normalized) % 4), validate=True)
    except ValueError:
        message = "Invalid challenge encoding."
        raise FidoError(message) from None
    if not minimum <= len(decoded) <= maximum:
        message = "Invalid challenge size."
        raise FidoError(message)
    if base64.b64encode(decoded).decode().rstrip("=") != normalized.rstrip("="):
        message = "Ambiguous challenge encoding."
        raise FidoError(message)
    return decoded


def encode64(value: bytes, *, padding: bool = True) -> str:
    result = base64.b64encode(value).decode("ascii")
    return result if padding else result.rstrip("=")


@dataclass(frozen=True, repr=False)
class Challenge:
    challenge: bytes
    rp_id: str
    credential_ids: tuple[bytes, ...]
    origin: str = ORIGIN
    created: float = field(default_factory=time.monotonic)

    def check(self) -> None:
        if self.origin != ORIGIN or self.rp_id not in ("apple.com", "gsa.apple.com"):
            message = "Unsupported RP/origin; refusing to sign."
            raise FidoError(message)
        if not verify_rp_id(self.rp_id, self.origin):
            message = "RP ID does not match origin."
            raise FidoError(message)
        if not 16 <= len(self.challenge) <= 1024 or not 1 <= len(self.credential_ids) <= 64:
            message = "Invalid challenge."
            raise FidoError(message)
        if any(not 1 <= len(x) <= 4096 for x in self.credential_ids):
            message = "Invalid credential identifier."
            raise FidoError(message)
        if not 0 <= time.monotonic() - self.created <= 120:
            message = "Challenge expired; no automatic retry."
            raise FidoError(message)

    def options(self) -> PublicKeyCredentialRequestOptions:
        self.check()
        return PublicKeyCredentialRequestOptions.from_dict(
            {
                "challenge": self.challenge,
                "rpId": self.rp_id,
                "timeout": 90_000,
                "userVerification": "preferred",
                "allowCredentials": [
                    {"type": "public-key", "id": x, "transports": ["usb"]}
                    for x in self.credential_ids
                ],
            }
        )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            message = "Duplicate JSON challenge field."
            raise FidoError(message)
        result[key] = value
    return result


def parse_auth_page(html: str) -> Challenge:
    if not isinstance(html, str) or len(html) > LIMIT:
        message = "Invalid authentication page response."
        raise FidoError(message)
    tags = BeautifulSoup(html, "html.parser").select("script.boot_args")
    if len(tags) != 1:
        message = "Unrecognized Apple boot_args layout; protocol review required."
        raise FidoError(message)
    try:
        boot = json.loads(tags[0].get_text(), object_pairs_hook=_unique_object)
        direct = boot["direct"]
        two_sv = direct.get("twoSV", direct)
        # No guessed URLs, callbacks, referrers, FSA1 or primary/passkey fallback.
        if direct.get("referrerQuery") or two_sv.get("referrerQuery"):
            message = "Unsupported referrerQuery; refusing to guess an endpoint."
            raise FidoError(message)
        if "authFactors" in two_sv:
            factors = two_sv["authFactors"]
            if not isinstance(factors, list) or not factors or factors[0] != "fsa2_hsa2":
                message = "Apple did not provide a supported fsa2_hsa2 challenge."
                raise FidoError(message)
        elif "twoSV" in direct:
            message = "Unsupported nested twoSV without authFactors."
            raise FidoError(message)
        # Real GSA schema diagnostic: direct.fsaVerification.fsaChallenge exists
        # without authFactors. Require every challenge/credential/RP check below.
        # Explicit incompatible factors still fail; no endpoint/origin fallback.
        fsa = two_sv["fsaVerification"]["fsaChallenge"]
        if fsa.get("extensions") or fsa.get("legacyExtensionAppId") or fsa.get("requirePrf"):
            message = "Unsupported authentication extension."
            raise FidoError(message)
        handles = fsa["keyHandles"]
        if not isinstance(handles, list) or not 1 <= len(handles) <= 64:
            message = "Missing or ambiguous credential allowlist."
            raise FidoError(message)
        c = Challenge(
            decode64(fsa["challenge"], minimum=16, maximum=1024),
            fsa["rpId"],
            tuple(decode64(x) for x in handles),
        )
        c.check()
        return c
    except (KeyError, TypeError, AttributeError, ValueError, RecursionError):
        message = "Unsupported Apple challenge structure; payload not retained."
        raise FidoError(message) from None


def apple_payload(c: Challenge, result: AuthenticationResponse) -> dict:
    """HSA2 codec: Apple EJ(assertion, rpId, undefined, false), NOT primary FSA2."""
    c.check()
    r = result.response
    try:
        data = json.loads(bytes(r.client_data), object_pairs_hook=_unique_object)
        if (
            data["type"] != "webauthn.get"
            or data["origin"] != c.origin
            or data.get("crossOrigin", False) is not False
            or decode64(data["challenge"]) != c.challenge
        ):
            message = "Assertion does not match challenge/origin."
            raise FidoError(message)
        if (
            result.type != "public-key"
            or result.raw_id not in c.credential_ids
            or r.authenticator_data.rp_id_hash != hashlib.sha256(c.rp_id.encode()).digest()
            or not r.authenticator_data.is_user_present()
        ):
            message = "Credential or authenticator data does not match challenge."
            raise FidoError(message)
        if not 1 <= len(r.signature) <= 4096:
            message = "Invalid signature."
            raise FidoError(message)
        if dict(result.client_extension_results):
            message = "Unsupported assertion extensions."
            raise FidoError(message)
    except (KeyError, ValueError, TypeError):
        message = "Invalid authenticator response."
        raise FidoError(message) from None
    return {
        "challenge": encode64(c.challenge, padding=False),
        "clientData": encode64(bytes(r.client_data)),
        "signatureData": encode64(r.signature),
        "authenticatorData": encode64(bytes(r.authenticator_data)),
        "userHandle": encode64(r.user_handle or b"", padding=False),
        "credentialID": encode64(result.raw_id, padding=False),
        "rpId": c.rp_id,
        # requestId is undefined in Apple's HSA2 caller; JSON.stringify omits it.
    }


def sign_usb(
    c: Challenge, device: CtapDevice, interaction: UserInteraction
) -> AuthenticationResponse:
    c.check()
    client = Fido2Client(device, DefaultClientDataCollector(c.origin), user_interaction=interaction)
    selection = client.get_assertion(c.options())
    if len(selection.get_assertions()) != 1:
        message = "Ambiguous authenticator response; refusing automatic account selection."
        raise FidoError(message)
    result = selection.get_response(0)
    apple_payload(c, result)  # validate before returning; no HTTP here
    return result


def apple_ssl_context() -> ssl.SSLContext:
    """Trust Apple's public root only inside this experiment, not OS-wide."""
    pem = (Path(__file__).parent / "certs/apple-root.pem").read_text()
    der = ssl.PEM_cert_to_DER_cert(pem)
    if hashlib.sha256(der).hexdigest() != APPLE_ROOT_SHA256:
        message = "Apple root certificate does not match pinned fingerprint."
        raise FidoError(message)
    context = ssl.create_default_context()
    context.load_verify_locations(cadata=pem)
    return context


class CheckedHttpSession:
    """Instance-local replacement for SDK ssl=False. No retries or redirects."""

    def __init__(self) -> None:
        self._session = None
        self._closed = False
        self.gsa_context = apple_ssl_context()
        self.standard_context = ssl.create_default_context()
        self.continuation = {}

    async def request(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
        if self._closed:
            message = "Transport session is closed."
            raise FidoError(message)
        if url not in AUTH_URLS or method not in ("GET", "POST"):
            message = "Endpoint outside authentication scope."
            raise FidoError(message)
        # Explicitly reject caller attempts to weaken the transport or retry.
        if set(kwargs) - {"headers", "auth", "json", "data", "auto_retry"} or kwargs.pop(
            "auto_retry", False
        ):
            message = "Unsupported transport options."
            raise FidoError(message)
        headers = dict(kwargs.pop("headers", {}) or {})
        if url.startswith(ORIGIN + "/auth"):
            headers.update(self.continuation)
        auth = kwargs.get("auth")
        if isinstance(auth, tuple):
            kwargs["auth"] = aiohttp.BasicAuth(*auth)
        if self._session is None:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30), trust_env=False
            )
        context = (
            self.gsa_context if urlsplit(url).hostname == "gsa.apple.com" else self.standard_context
        )
        async with self._session.request(
            method, url, headers=headers, ssl=context, allow_redirects=False, **kwargs
        ) as resp:
            if 300 <= resp.status <= 399:
                message = "Apple redirect rejected; no retry."
                raise FidoError(message)
            body = bytearray()
            async for chunk in resp.content.iter_chunked(65536):
                body.extend(chunk)
                if len(body) > LIMIT:
                    message = "Apple response exceeds size limit."
                    raise FidoError(message)
            if url.startswith(ORIGIN + "/auth"):
                for key in ("scnt", "X-Apple-ID-Session-Id"):
                    if resp.headers.get(key):
                        self.continuation[key] = resp.headers[key]
            return HttpResponse(resp.status, bytes(body))

    async def post(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self.request("POST", url, **kwargs)

    async def get(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self.request("GET", url, **kwargs)

    async def close(self) -> None:
        self._closed = True
        self.continuation.clear()
        if self._session:
            await self._session.close()


def report_progress(account: FidoAppleAccount, event: dict[str, object]) -> None:
    callback = getattr(account, "on_progress", None)
    if callback is not None:
        callback(event)


class FidoAppleAccount(AsyncAppleAccount):
    """Pinned FindMy 0.10.1 adapter, without editing or monkeypatching the SDK."""

    def __init__(self, anisette: BaseAnisetteProvider) -> None:
        super().__init__(anisette)
        # The SDK's previous lazy transport has not opened any connections yet.
        self._http = cast("HttpSession", CheckedHttpSession())
        self._fido_attempted = False
        self.on_progress: Callable[[dict], None] | None = None

    @override
    async def _gsa_request(self, parameters: dict) -> dict:
        response = await super()._gsa_request(parameters)
        status = response.get("Status")
        code = status.get("ec") if isinstance(status, dict) else None
        if type(code) is not int or not -1_000_000 <= code <= 1_000_000:
            code = "UNAVAILABLE"
        operation = parameters.get("o")
        if operation not in ("init", "complete"):
            operation = "unknown"
        phase = "post_key_gsa" if self._fido_attempted else "initial_gsa"
        report_progress(
            self, {"stage": phase + "_" + operation + "_response", "apple_error_code": code}
        )
        # Return original bytes/fields unchanged to the SDK. Never echo Status.em,
        # username, tokens, SRP proof or decrypted SPD, even when status is an error.
        return response

    async def _fido_request(self, method: str, path: str, data: dict | None = None) -> str:
        if path not in ("/auth", "/auth/verify/security/key"):
            message = "Unsupported security-key endpoint."
            raise FidoError(message)
        if self.login_state != LoginState.REQUIRE_2FA:
            message = "No active session requiring a second factor."
            raise FidoError(message)
        token = encode64(
            (self._login_state_data["adsid"] + ":" + self._login_state_data["idms_token"]).encode()
        )
        headers = {
            "User-Agent": "Xcode",
            "Accept-Language": "en-us",
            "X-Apple-Identity-Token": token,
            "Accept": "text/html" if method == "GET" else "application/json",
        }
        headers.update(await self.get_anisette_headers(with_client_info=True))
        if method == "POST":
            headers.update({"Origin": ORIGIN, "Referer": ORIGIN + "/auth"})
        resp = await self._http.request(method, ORIGIN + path, headers=headers, json=data)
        allowed = (200,) if method == "GET" else (200, 204, 250)
        if resp.status_code not in allowed:
            message = f"Apple rejected security-key step (HTTP {resp.status_code}); no retry."
            raise FidoError(message)
        if method == "POST":
            report_progress(
                self, {"stage": "key_endpoint_response", "http_status": resp.status_code}
            )
        return resp.text()

    async def authenticate_security_key(
        self, signer: Callable[[Challenge], AuthenticationResponse]
    ) -> LoginState:
        if self._fido_attempted:
            message = "Security-key attempt already consumed; new explicit login required."
            raise FidoError(message)
        self._fido_attempted = True
        return await complete_second_factor(self, signer)


async def complete_second_factor(
    account: FidoAppleAccount, signer: Callable[[Challenge], AuthenticationResponse]
) -> LoginState:
    if account.login_state != LoginState.REQUIRE_2FA:
        message = "Invalid state before security-key verification."
        raise FidoError(message)
    challenge = parse_auth_page(await account._fido_request("GET", "/auth"))
    result = await asyncio.to_thread(signer, challenge)
    payload = apple_payload(challenge, result)
    report_progress(account, {"stage": "key_assertion_created"})
    await account._fido_request("POST", "/auth/verify/security/key", payload)
    # A 200/204/250 from the key endpoint alone is NOT proof of a FindMy login.
    report_progress(account, {"stage": "post_key_gsa_start"})
    state = await account._gsa_authenticate()
    if state != LoginState.AUTHENTICATED:
        message = "Assertion submitted but GrandSlam did not confirm authentication."
        raise FidoError(message)
    report_progress(account, {"stage": "mobileme_login_start"})
    state = await account._login_mobileme()
    if state != LoginState.LOGGED_IN:
        message = "MobileMe did not confirm a FindMy session."
        raise FidoError(message)
    return state
