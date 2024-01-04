"""Module containing most of the code necessary to interact with an Apple account."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import plistlib
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import (
    TYPE_CHECKING,
    Any,
    Sequence,
    TypedDict,
)

import bs4
import srp._pysrp as srp
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from findmy.util import HttpSession, decode_plist
from findmy.util.errors import InvalidCredentialsError, UnhandledProtocolError

from .reports import KeyReport, fetch_reports
from .state import LoginState, require_login_state
from .twofactor import (
    AsyncSecondFactorMethod,
    AsyncSmsSecondFactor,
    BaseSecondFactorMethod,
    SyncSecondFactorMethod,
    SyncSmsSecondFactor,
)

if TYPE_CHECKING:
    from findmy.keys import KeyPair

    from .anisette import BaseAnisetteProvider

logging.getLogger(__name__)

srp.rfc5054_enable()
srp.no_username_in_x()


class _AccountInfo(TypedDict):
    account_name: str
    first_name: str
    last_name: str


def _encrypt_password(password: str, salt: bytes, iterations: int) -> bytes:
    p = hashlib.sha256(password.encode("utf-8")).digest()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(p)


def _decrypt_cbc(session_key: bytes, data: bytes) -> bytes:
    extra_data_key = hmac.new(session_key, b"extra data key:", hashlib.sha256).digest()
    extra_data_iv = hmac.new(session_key, b"extra data iv:", hashlib.sha256).digest()
    # Get only the first 16 bytes of the iv
    extra_data_iv = extra_data_iv[:16]

    # Decrypt with AES CBC
    cipher = Cipher(algorithms.AES(extra_data_key), modes.CBC(extra_data_iv))
    decryptor = cipher.decryptor()
    data = decryptor.update(data) + decryptor.finalize()
    # Remove PKCS#7 padding
    padder = padding.PKCS7(128).unpadder()
    return padder.update(data) + padder.finalize()


def _extract_phone_numbers(html: str) -> list[dict]:
    soup = bs4.BeautifulSoup(html, features="html.parser")
    data_elem = soup.find("script", **{"class": "boot_args"})
    if not data_elem:
        msg = "Could not find HTML element containing phone numbers"
        raise RuntimeError(msg)

    data = json.loads(data_elem.text)
    return data.get("direct", {}).get("phoneNumberVerification", {}).get("trustedPhoneNumbers", [])


class BaseAppleAccount(ABC):
    """Base class for an Apple account."""

    @property
    @abstractmethod
    def login_state(self) -> LoginState:
        """The current login state of the account."""
        raise NotImplementedError

    @property
    @abstractmethod
    def account_name(self) -> str:
        """
        The name of the account as reported by Apple.

        This is usually an e-mail address.
        May be None in some cases, such as when not logged in.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def first_name(self) -> str | None:
        """
        First name of the account holder as reported by Apple.

        May be None in some cases, such as when not logged in.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def last_name(self) -> str | None:
        """
        Last name of the account holder as reported by Apple.

        May be None in some cases, such as when not logged in.
        """
        raise NotImplementedError

    @abstractmethod
    def export(self) -> dict:
        """
        Export a representation of the current state of the account as a dictionary.

        The output of this method is guaranteed to be JSON-serializable, and passing
        the return value of this function as an argument to `BaseAppleAccount.restore`
        will always result in an exact copy of the internal state as it was when exported.

        This method is especially useful to avoid having to keep going through the login flow.
        """
        raise NotImplementedError

    @abstractmethod
    def restore(self, data: dict) -> None:
        """
        Restore a previous export of the internal state of the account.

        See `BaseAppleAccount.export` for more information.
        """
        raise NotImplementedError

    @abstractmethod
    def login(self, username: str, password: str) -> LoginState:
        """Log in to an Apple account using a username and password."""
        raise NotImplementedError

    @abstractmethod
    def get_2fa_methods(self) -> list[BaseSecondFactorMethod]:
        """
        Get a list of 2FA methods that can be used as a secondary challenge.

        Currently, only SMS-based 2FA methods are supported.
        """
        raise NotImplementedError

    @abstractmethod
    def sms_2fa_request(self, phone_number_id: int) -> None:
        """
        Request a 2FA code to be sent to a specific phone number ID.

        Consider using `BaseSecondFactorMethod.request` instead.
        """
        raise NotImplementedError

    @abstractmethod
    def sms_2fa_submit(self, phone_number_id: int, code: str) -> LoginState:
        """
        Submit a 2FA code that was sent to a specific phone number ID.

        Consider using `BaseSecondFactorMethod.submit` instead.
        """
        raise NotImplementedError

    @abstractmethod
    def fetch_reports(
        self,
        keys: Sequence[KeyPair],
        date_from: datetime,
        date_to: datetime,
    ) -> dict[KeyPair, list[KeyReport]]:
        """
        Fetch location reports for a sequence of `KeyPair`s between `date_from` and `date_end`.

        Returns a dictionary mapping `KeyPair`s to a list of their location reports.
        """
        raise NotImplementedError

    @abstractmethod
    def fetch_last_reports(
        self,
        keys: Sequence[KeyPair],
        hours: int = 7 * 24,
    ) -> dict[KeyPair, list[KeyReport]]:
        """
        Fetch location reports for a sequence of `KeyPair`s for the last `hours` hours.

        Utility method as an alternative to using `BaseAppleAccount.fetch_reports` directly.
        """
        raise NotImplementedError

    @abstractmethod
    def get_anisette_headers(self, serial: str = "0") -> dict[str, str]:
        """
        Retrieve a complete dictionary of Anisette headers.

        Utility method for `AnisetteProvider.get_headers` using this account's user and device ID.
        """
        raise NotImplementedError


class AsyncAppleAccount(BaseAppleAccount):
    """An async implementation of `BaseAppleAccount`."""

    def __init__(
        self,
        anisette: BaseAnisetteProvider,
        user_id: str | None = None,
        device_id: str | None = None,
    ) -> None:
        """
        Initialize the apple account.

        :param anisette: An instance of `AsyncAnisetteProvider`.
        :param user_id: An optional user ID to use. Will be auto-generated if missing.
        :param device_id: An optional device ID to use. Will be auto-generated if missing.
        """
        self._anisette: BaseAnisetteProvider = anisette
        self._uid: str = user_id or str(uuid.uuid4())
        self._devid: str = device_id or str(uuid.uuid4())

        self._username: str | None = None
        self._password: str | None = None

        self._login_state: LoginState = LoginState.LOGGED_OUT
        self._login_state_data: dict = {}

        self._account_info: _AccountInfo | None = None

        self._http: HttpSession = HttpSession()

    def _set_login_state(
        self,
        state: LoginState,
        data: dict | None = None,
    ) -> LoginState:
        # clear account info if downgrading state (e.g. LOGGED_IN -> LOGGED_OUT)
        if state < self._login_state:
            logging.debug("Clearing cached account information")
            self._account_info = None

        logging.info("Transitioning login state: %s -> %s", self._login_state, state)
        self._login_state = state
        self._login_state_data = data or {}

        return state

    @property
    def login_state(self) -> LoginState:
        """See `BaseAppleAccount.login_state`."""
        return self._login_state

    @property
    @require_login_state(
        LoginState.LOGGED_IN,
        LoginState.AUTHENTICATED,
        LoginState.REQUIRE_2FA,
    )
    def account_name(self) -> str | None:
        """See `BaseAppleAccount.account_name`."""
        return self._account_info["account_name"] if self._account_info else None

    @property
    @require_login_state(
        LoginState.LOGGED_IN,
        LoginState.AUTHENTICATED,
        LoginState.REQUIRE_2FA,
    )
    def first_name(self) -> str | None:
        """See `BaseAppleAccount.first_name`."""
        return self._account_info["first_name"] if self._account_info else None

    @property
    @require_login_state(
        LoginState.LOGGED_IN,
        LoginState.AUTHENTICATED,
        LoginState.REQUIRE_2FA,
    )
    def last_name(self) -> str | None:
        """See `BaseAppleAccount.last_name`."""
        return self._account_info["last_name"] if self._account_info else None

    def export(self) -> dict:
        """See `BaseAppleAccount.export`."""
        return {
            "ids": {"uid": self._uid, "devid": self._devid},
            "account": {
                "username": self._username,
                "password": self._password,
                "info": self._account_info,
            },
            "login_state": {
                "state": self._login_state.value,
                "data": self._login_state_data,
            },
        }

    def restore(self, data: dict) -> None:
        """See `BaseAppleAccount.restore`."""
        try:
            self._uid = data["ids"]["uid"]
            self._devid = data["ids"]["devid"]

            self._username = data["account"]["username"]
            self._password = data["account"]["password"]
            self._account_info = data["account"]["info"]

            self._login_state = LoginState(data["login_state"]["state"])
            self._login_state_data = data["login_state"]["data"]
        except KeyError as e:
            msg = f"Failed to restore account data: {e}"
            raise ValueError(msg) from None

    async def close(self) -> None:
        """
        Close any sessions or other resources in use by this object.

        Should be called when the object will no longer be used.
        """
        await self._anisette.close()
        await self._http.close()

    @require_login_state(LoginState.LOGGED_OUT)
    async def login(self, username: str, password: str) -> LoginState:
        """See `BaseAppleAccount.login`."""
        # LOGGED_OUT -> (REQUIRE_2FA or AUTHENTICATED)
        new_state = await self._gsa_authenticate(username, password)
        if new_state == LoginState.REQUIRE_2FA:  # pass control back to handle 2FA
            return new_state

        # AUTHENTICATED -> LOGGED_IN
        return await self._login_mobileme()

    @require_login_state(LoginState.REQUIRE_2FA)
    async def get_2fa_methods(self) -> list[AsyncSecondFactorMethod]:
        """See `BaseAppleAccount.get_2fa_methods`."""
        methods: list[AsyncSecondFactorMethod] = []

        # sms
        auth_page = await self._sms_2fa_request("GET", "https://gsa.apple.com/auth")
        try:
            phone_numbers = _extract_phone_numbers(auth_page)
            methods.extend(
                AsyncSmsSecondFactor(
                    self,
                    number.get("id"),
                    number.get("numberWithDialCode"),
                )
                for number in phone_numbers
            )
        except RuntimeError:
            logging.warning("Unable to extract phone numbers from login page")

        return methods

    @require_login_state(LoginState.REQUIRE_2FA)
    async def sms_2fa_request(self, phone_number_id: int) -> None:
        """See `BaseAppleAccount.sms_2fa_request`."""
        data = {"phoneNumber": {"id": phone_number_id}, "mode": "sms"}

        await self._sms_2fa_request(
            "PUT",
            "https://gsa.apple.com/auth/verify/phone",
            data,
        )

    @require_login_state(LoginState.REQUIRE_2FA)
    async def sms_2fa_submit(self, phone_number_id: int, code: str) -> LoginState:
        """See `BaseAppleAccount.sms_2fa_submit`."""
        data = {
            "phoneNumber": {"id": phone_number_id},
            "securityCode": {"code": str(code)},
            "mode": "sms",
        }

        await self._sms_2fa_request(
            "POST",
            "https://gsa.apple.com/auth/verify/phone/securitycode",
            data,
        )

        # REQUIRE_2FA -> AUTHENTICATED
        new_state = await self._gsa_authenticate()
        if new_state != LoginState.AUTHENTICATED:
            msg = f"Unexpected state after submitting 2FA: {new_state}"
            raise UnhandledProtocolError(msg)

        # AUTHENTICATED -> LOGGED_IN
        return await self._login_mobileme()

    @require_login_state(LoginState.LOGGED_IN)
    async def fetch_reports(
        self,
        keys: Sequence[KeyPair],
        date_from: datetime,
        date_to: datetime,
    ) -> dict[KeyPair, list[KeyReport]]:
        """See `BaseAppleAccount.fetch_reports`."""
        anisette_headers = await self.get_anisette_headers()

        return await fetch_reports(
            self._login_state_data["dsid"],
            self._login_state_data["mobileme_data"]["tokens"]["searchPartyToken"],
            anisette_headers,
            date_from,
            date_to,
            keys,
        )

    @require_login_state(LoginState.LOGGED_IN)
    async def fetch_last_reports(
        self,
        keys: Sequence[KeyPair],
        hours: int = 7 * 24,
    ) -> dict[KeyPair, list[KeyReport]]:
        """See `BaseAppleAccount.fetch_last_reports`."""
        end = datetime.now(tz=timezone.utc)
        start = end - timedelta(hours=hours)

        return await self.fetch_reports(keys, start, end)

    @require_login_state(LoginState.LOGGED_OUT, LoginState.REQUIRE_2FA)
    async def _gsa_authenticate(
        self,
        username: str | None = None,
        password: str | None = None,
    ) -> LoginState:
        # use stored values for re-authentication
        self._username = username or self._username
        self._password = password or self._password

        logging.info("Attempting authentication for user %s", self._username)

        if not self._username or not self._password:
            msg = "No username or password specified"
            raise ValueError(msg)

        logging.debug("Starting authentication with username")

        usr = srp.User(self._username, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048)
        _, a2k = usr.start_authentication()
        r = await self._gsa_request(
            {"A2k": a2k, "u": self._username, "ps": ["s2k", "s2k_fo"], "o": "init"},
        )

        logging.debug("Verifying response to auth request")

        if r["Status"].get("ec") != 0:
            msg = "Email verification failed: " + r["Status"].get("em")
            raise InvalidCredentialsError(msg)
        sp = r.get("sp")
        if sp != "s2k":
            msg = f"This implementation only supports s2k. Server returned {sp}"
            raise UnhandledProtocolError(msg)

        logging.debug("Attempting password challenge")

        usr.p = _encrypt_password(self._password, r["s"], r["i"])
        m1 = usr.process_challenge(r["s"], r["B"])
        if m1 is None:
            msg = "Failed to process challenge"
            raise UnhandledProtocolError(msg)
        r = await self._gsa_request(
            {"c": r["c"], "M1": m1, "u": self._username, "o": "complete"},
        )

        logging.debug("Verifying password challenge response")

        if r["Status"].get("ec") != 0:
            msg = "Password authentication failed: " + r["Status"].get("em")
            raise InvalidCredentialsError(msg)
        usr.verify_session(r.get("M2"))
        if not usr.authenticated():
            msg = "Failed to verify session"
            raise UnhandledProtocolError(msg)

        logging.debug("Decrypting SPD data in response")

        spd = _decrypt_cbc(usr.get_session_key(), r["spd"])
        spd = decode_plist(spd)

        logging.debug("Received account information")
        self._account_info: _AccountInfo = {
            "account_name": spd.get("acname"),
            "first_name": spd.get("fn"),
            "last_name": spd.get("ln"),
        }

        # TODO(malmeloo): support trusted device auth (need account to test)
        # https://github.com/malmeloo/FindMy.py/issues/1
        au = r["Status"].get("au")
        if au in ("secondaryAuth",):
            logging.info("Detected 2FA requirement: %s", au)

            return self._set_login_state(
                LoginState.REQUIRE_2FA,
                {"adsid": spd["adsid"], "idms_token": spd["GsIdmsToken"]},
            )
        if au is not None:
            msg = f"Unknown auth value: {au}"
            raise UnhandledProtocolError(msg)

        logging.info("GSA authentication successful")

        idms_pet = spd.get("t", {}).get("com.apple.gs.idms.pet", {}).get("token", "")
        return self._set_login_state(
            LoginState.AUTHENTICATED,
            {"idms_pet": idms_pet, "adsid": spd["adsid"]},
        )

    @require_login_state(LoginState.AUTHENTICATED)
    async def _login_mobileme(self) -> LoginState:
        logging.info("Logging into com.apple.mobileme")
        data = plistlib.dumps(
            {
                "apple-id": self._username,
                "delegates": {"com.apple.mobileme": {}},
                "password": self._login_state_data["idms_pet"],
                "client-id": self._uid,
            },
        )

        headers = {
            "X-Apple-ADSID": self._login_state_data["adsid"],
            "User-Agent": "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0",
            "X-Mme-Client-Info": "<MacBookPro18,3> <Mac OS X;13.4.1;22F8>"
            " <com.apple.AOSKit/282 (com.apple.accountsd/113)>",
        }
        headers.update(await self.get_anisette_headers())

        resp = await self._http.post(
            "https://setup.icloud.com/setup/iosbuddy/loginDelegates",
            auth=(self._username, self._login_state_data["idms_pet"]),
            data=data,
            headers=headers,
        )
        data = resp.plist()

        mobileme_data = data.get("delegates", {}).get("com.apple.mobileme", {})
        status = mobileme_data.get("status")
        if status != 0:
            status_message = mobileme_data.get("status-message")
            msg = f"com.apple.mobileme login failed with status {status}: {status_message}"
            raise UnhandledProtocolError(msg)

        return self._set_login_state(
            LoginState.LOGGED_IN,
            {"dsid": data["dsid"], "mobileme_data": mobileme_data["service-data"]},
        )

    async def _sms_2fa_request(
        self,
        method: str,
        url: str,
        data: dict | None = None,
    ) -> str:
        adsid = self._login_state_data["adsid"]
        idms_token = self._login_state_data["idms_token"]
        identity_token = base64.b64encode((adsid + ":" + idms_token).encode()).decode()

        headers = {
            "User-Agent": "Xcode",
            "Accept-Language": "en-us",
            "X-Apple-Identity-Token": identity_token,
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Xcode-Version": "11.2 (11B41)",
            "X-Mme-Client-Info": "<MacBookPro18,3> <Mac OS X;13.4.1;22F8>"
            " <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>",
        }
        headers.update(await self.get_anisette_headers())

        r = await self._http.request(
            method,
            url,
            json=data,
            headers=headers,
        )
        if not r.ok:
            msg = f"SMS 2FA request failed: {r.status_code}"
            raise UnhandledProtocolError(msg)

        return r.text()

    async def _gsa_request(self, params: dict[str, Any]) -> dict[Any, Any]:
        request_data = {
            "cpd": {
                "bootstrap": True,
                "icscrec": True,
                "pbe": False,
                "prkgen": True,
                "svct": "iCloud",
            },
        }
        request_data["cpd"].update(await self.get_anisette_headers())
        request_data.update(params)

        body = {
            "Header": {"Version": "1.0.1"},
            "Request": request_data,
        }

        headers = {
            "Content-Type": "text/x-xml-plist",
            "Accept": "*/*",
            "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
            "X-MMe-Client-Info": "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> "
            "<com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>",
        }

        resp = await self._http.post(
            "https://gsa.apple.com/grandslam/GsService2",
            headers=headers,
            data=plistlib.dumps(body),
        )
        if not resp.ok:
            msg = f"Error response for GSA request: {resp.status_code}"
            raise UnhandledProtocolError(msg)
        return resp.plist()["Response"]

    async def get_anisette_headers(self, serial: str = "0") -> dict[str, str]:
        """See `BaseAppleAccount.get_anisette_headers`."""
        return await self._anisette.get_headers(self._uid, self._devid, serial)


class AppleAccount(BaseAppleAccount):
    """
    A sync implementation of `BaseappleAccount`.

    Uses `AsyncappleAccount` internally.
    """

    def __init__(
        self,
        anisette: BaseAnisetteProvider,
        user_id: str | None = None,
        device_id: str | None = None,
    ) -> None:
        """See `AsyncAppleAccount.__init__`."""
        self._asyncacc = AsyncAppleAccount(anisette, user_id, device_id)

        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)

    def __del__(self) -> None:
        """Gracefully close the async instance's session when garbage collected."""
        coro = self._asyncacc.close()
        return self._loop.run_until_complete(coro)

    @property
    def login_state(self) -> LoginState:
        """See `AsyncAppleAccount.login_state`."""
        return self._asyncacc.login_state

    @property
    def account_name(self) -> str:
        """See `AsyncAppleAccount.login_state`."""
        return self._asyncacc.account_name

    @property
    def first_name(self) -> str | None:
        """See `AsyncAppleAccount.first_name`."""
        return self._asyncacc.first_name

    @property
    def last_name(self) -> str | None:
        """See `AsyncAppleAccount.last_name`."""
        return self._asyncacc.last_name

    def export(self) -> dict:
        """See `AsyncAppleAccount.export`."""
        return self._asyncacc.export()

    def restore(self, data: dict) -> None:
        """See `AsyncAppleAccount.restore`."""
        return self._asyncacc.restore(data)

    def login(self, username: str, password: str) -> LoginState:
        """See `AsyncAppleAccount.login`."""
        coro = self._asyncacc.login(username, password)
        return self._loop.run_until_complete(coro)

    def get_2fa_methods(self) -> list[SyncSecondFactorMethod]:
        """See `AsyncAppleAccount.get_2fa_methods`."""
        coro = self._asyncacc.get_2fa_methods()
        methods = self._loop.run_until_complete(coro)

        res = []
        for m in methods:
            if isinstance(m, AsyncSmsSecondFactor):
                res.append(SyncSmsSecondFactor(self, m.phone_number_id, m.phone_number))
            else:
                msg = (
                    f"Failed to cast 2FA object to sync alternative: {m}."
                    f" This is a bug, please report it."
                )
                raise TypeError(msg)

        return res

    def sms_2fa_request(self, phone_number_id: int) -> None:
        """See `AsyncAppleAccount.sms_2fa_request`."""
        coro = self._asyncacc.sms_2fa_request(phone_number_id)
        return self._loop.run_until_complete(coro)

    def sms_2fa_submit(self, phone_number_id: int, code: str) -> LoginState:
        """See `AsyncAppleAccount.sms_2fa_submit`."""
        coro = self._asyncacc.sms_2fa_submit(phone_number_id, code)
        return self._loop.run_until_complete(coro)

    def fetch_reports(
        self,
        keys: Sequence[KeyPair],
        date_from: datetime,
        date_to: datetime,
    ) -> dict[KeyPair, list[KeyReport]]:
        """See `AsyncAppleAccount.fetch_reports`."""
        coro = self._asyncacc.fetch_reports(keys, date_from, date_to)
        return self._loop.run_until_complete(coro)

    def fetch_last_reports(
        self,
        keys: Sequence[KeyPair],
        hours: int = 7 * 24,
    ) -> dict[KeyPair, list[KeyReport]]:
        """See `AsyncAppleAccount.fetch_last_reports`."""
        coro = self._asyncacc.fetch_last_reports(keys, hours)
        return self._loop.run_until_complete(coro)

    def get_anisette_headers(self, serial: str = "0") -> dict[str, str]:
        """See `AsyncAppleAccount.get_anisette_headers`."""
        coro = self._asyncacc.get_anisette_headers(serial)
        return self._loop.run_until_complete(coro)
