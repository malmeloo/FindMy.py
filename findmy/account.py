import asyncio
import base64
import hashlib
import hmac
import json
import logging
import plistlib
import uuid
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional, TypedDict, Any
from typing import Sequence

import bs4
import srp._pysrp as srp
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .anisette import AnisetteProvider
from .base import BaseAppleAccount, BaseSecondFactorMethod, LoginState
from .http import HttpSession
from .keys import KeyPair
from .reports import fetch_reports

logging.getLogger(__name__)

srp.rfc5054_enable()
srp.no_username_in_x()


class AccountInfo(TypedDict):
    account_name: str
    first_name: str
    last_name: str


class LoginException(Exception):
    pass


class InvalidStateException(RuntimeError):
    pass


class ExportRestoreError(ValueError):
    pass


def _load_plist(data: bytes) -> Any:
    plist_header = (
        b"<?xml version='1.0' encoding='UTF-8'?>"
        b"<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>"
    )

    if not data.startswith(b"<?xml"):
        data = plist_header + data

    return plistlib.loads(data)


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
        raise RuntimeError("Could not find HTML element containing phone numbers")

    data = json.loads(data_elem.text)
    return (
        data.get("direct", {})
        .get("phoneNumberVerification", {})
        .get("trustedPhoneNumbers", [])
    )


def _require_login_state(*states: LoginState):
    def decorator(func):
        @wraps(func)
        def wrapper(acc: "BaseAppleAccount", *args, **kwargs):
            if acc.login_state not in states:
                raise InvalidStateException(
                    f"Invalid login state! Currently: {acc.login_state} but should be one of: {states}"
                )

            return func(acc, *args, **kwargs)

        return wrapper

    return decorator


class AsyncSmsSecondFactor(BaseSecondFactorMethod):
    def __init__(self, account: "AsyncAppleAccount", number_id: int, phone_number: str):
        super().__init__(account)

        self._phone_number_id: int = number_id
        self._phone_number: str = phone_number

    @property
    def phone_number_id(self):
        return self._phone_number_id

    @property
    def phone_number(self):
        return self._phone_number

    async def request(self):
        return await self.account.sms_2fa_request(self._phone_number_id)

    async def submit(self, code: str) -> LoginState:
        return await self.account.sms_2fa_submit(self._phone_number_id, code)


class SmsSecondFactor(BaseSecondFactorMethod):
    def __init__(self, account: "AppleAccount", number_id: int, phone_number: str):
        super().__init__(account)

        self._phone_number_id: int = number_id
        self._phone_number: str = phone_number

    @property
    def phone_number(self):
        return self._phone_number

    def request(self) -> None:
        return self.account.sms_2fa_request(self._phone_number_id)

    def submit(self, code: str) -> LoginState:
        return self.account.sms_2fa_submit(self._phone_number_id, code)


class AsyncAppleAccount(BaseAppleAccount):
    def __init__(
        self, anisette: AnisetteProvider, user_id: str = None, device_id: str = None
    ):
        self._anisette: AnisetteProvider = anisette
        self._uid: str = user_id or str(uuid.uuid4())
        self._devid: str = device_id or str(uuid.uuid4())

        self._username: Optional[str] = None
        self._password: Optional[str] = None

        self._login_state: LoginState = LoginState.LOGGED_OUT
        self._login_state_data: dict = {}

        self._account_info: Optional[AccountInfo] = None

        self._http = HttpSession()

    def _set_login_state(
        self, state: LoginState, data: Optional[dict] = None
    ) -> LoginState:
        # clear account info if downgrading state (e.g. LOGGED_IN -> LOGGED_OUT)
        if state < self._login_state:
            logging.debug("Clearing cached account information")
            self._account_info = None

        logging.info(f"Transitioning login state: {self._login_state} -> {state}")
        self._login_state = state
        self._login_state_data = data or {}

        return state

    @property
    def login_state(self):
        return self._login_state

    @property
    @_require_login_state(
        LoginState.LOGGED_IN, LoginState.AUTHENTICATED, LoginState.REQUIRE_2FA
    )
    def account_name(self):
        return self._account_info["account_name"] if self._account_info else None

    @property
    @_require_login_state(
        LoginState.LOGGED_IN, LoginState.AUTHENTICATED, LoginState.REQUIRE_2FA
    )
    def first_name(self):
        return self._account_info["first_name"] if self._account_info else None

    @property
    @_require_login_state(
        LoginState.LOGGED_IN, LoginState.AUTHENTICATED, LoginState.REQUIRE_2FA
    )
    def last_name(self):
        return self._account_info["last_name"] if self._account_info else None

    def export(self) -> dict:
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

    def restore(self, data: dict):
        try:
            self._uid = data["ids"]["uid"]
            self._devid = data["ids"]["devid"]

            self._username = data["account"]["username"]
            self._password = data["account"]["password"]
            self._account_info = data["account"]["info"]

            self._login_state = LoginState(data["login_state"]["state"])
            self._login_state_data = data["login_state"]["data"]
        except KeyError as e:
            raise ExportRestoreError(f"Failed to restore account data: {e}")

    async def close(self):
        await self._anisette.close()
        await self._http.close()

    @_require_login_state(LoginState.LOGGED_OUT)
    async def login(self, username: str, password: str) -> LoginState:
        # LOGGED_OUT -> (REQUIRE_2FA or AUTHENTICATED)
        new_state = await self._gsa_authenticate(username, password)
        if new_state == LoginState.REQUIRE_2FA:  # pass control back to handle 2FA
            return new_state

        # AUTHENTICATED -> LOGGED_IN
        return await self._login_mobileme()

    @_require_login_state(LoginState.REQUIRE_2FA)
    async def get_2fa_methods(self) -> list[BaseSecondFactorMethod]:
        methods: list[BaseSecondFactorMethod] = []

        # sms
        auth_page = await self._sms_2fa_request("GET", "https://gsa.apple.com/auth")
        try:
            phone_numbers = _extract_phone_numbers(auth_page)
        except RuntimeError:
            logging.warning("Unable to extract phone numbers from login page")

        methods.extend(
            AsyncSmsSecondFactor(
                self, number.get("id"), number.get("numberWithDialCode")
            )
            for number in phone_numbers
        )

        return methods

    @_require_login_state(LoginState.REQUIRE_2FA)
    async def sms_2fa_request(self, phone_number_id: int):
        data = {"phoneNumber": {"id": phone_number_id}, "mode": "sms"}

        await self._sms_2fa_request(
            "PUT", "https://gsa.apple.com/auth/verify/phone", data
        )

    @_require_login_state(LoginState.REQUIRE_2FA)
    async def sms_2fa_submit(self, phone_number_id: int, code: str) -> LoginState:
        data = {
            "phoneNumber": {"id": phone_number_id},
            "securityCode": {"code": str(code)},
            "mode": "sms",
        }

        await self._sms_2fa_request(
            "POST", "https://gsa.apple.com/auth/verify/phone/securitycode", data
        )

        # REQUIRE_2FA -> AUTHENTICATED
        new_state = await self._gsa_authenticate()
        if new_state != LoginState.AUTHENTICATED:
            raise LoginException(f"Unexpected state after submitting 2FA: {new_state}")

        # AUTHENTICATED -> LOGGED_IN
        return await self._login_mobileme()

    @_require_login_state(LoginState.LOGGED_IN)
    async def fetch_reports(
        self, keys: Sequence[KeyPair], date_from: datetime, date_to: datetime
    ):
        anisette_headers = await self.get_anisette_headers()

        return await fetch_reports(
            self._login_state_data["dsid"],
            self._login_state_data["mobileme_data"]["tokens"]["searchPartyToken"],
            anisette_headers,
            date_from,
            date_to,
            keys,
        )

    @_require_login_state(LoginState.LOGGED_IN)
    async def fetch_last_reports(
        self,
        keys: Sequence[KeyPair],
        hours: int = 7 * 24,
    ):
        end = datetime.now()
        start = end - timedelta(hours=hours)

        return await self.fetch_reports(keys, start, end)

    @_require_login_state(LoginState.LOGGED_OUT, LoginState.REQUIRE_2FA)
    async def _gsa_authenticate(
        self, username: Optional[str] = None, password: Optional[str] = None
    ) -> LoginState:
        self._username = username or self._username
        self._password = password or self._password

        logging.info(f"Attempting authentication for user {self._username}")

        if not self._username or not self._password:
            raise ValueError("No username or password to log in")

        logging.debug("Starting authentication with username")

        usr = srp.User(self._username, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048)
        _, a2k = usr.start_authentication()
        r = await self._gsa_request(
            {"A2k": a2k, "u": self._username, "ps": ["s2k", "s2k_fo"], "o": "init"}
        )

        logging.debug("Verifying response to auth request")

        if r["Status"].get("ec") != 0:
            message = r["Status"].get("em")
            raise LoginException(f"Email verify failed: {message}")
        sp = r.get("sp")
        if sp != "s2k":
            raise LoginException(
                f"This implementation only supports s2k. Server returned {sp}"
            )

        logging.debug("Attempting password challenge")

        usr.p = _encrypt_password(self._password, r["s"], r["i"])
        m1 = usr.process_challenge(r["s"], r["B"])
        if m1 is None:
            raise LoginException("Failed to process challenge")
        r = await self._gsa_request(
            {"c": r["c"], "M1": m1, "u": self._username, "o": "complete"}
        )

        logging.debug("Verifying password challenge response")

        if r["Status"].get("ec") != 0:
            message = r["Status"].get("em")
            raise LoginException(f"Password authentication failed: {message}")
        usr.verify_session(r.get("M2"))
        if not usr.authenticated():
            raise LoginException("Failed to verify session")

        logging.debug("Decrypting SPD data in response")

        spd = _decrypt_cbc(usr.get_session_key(), r["spd"])
        spd = _load_plist(spd)

        logging.debug("Received account information")
        self._account_info: AccountInfo = {
            "account_name": spd.get("acname"),
            "first_name": spd.get("fn"),
            "last_name": spd.get("ln"),
        }

        # TODO: support trusted device auth (need account to test)
        au = r["Status"].get("au")
        if au in ("secondaryAuth",):
            logging.info(f"Detected 2FA requirement: {au}")

            return self._set_login_state(
                LoginState.REQUIRE_2FA,
                {"adsid": spd["adsid"], "idms_token": spd["GsIdmsToken"]},
            )
        elif au is not None:
            raise LoginException(f"Unknown auth value: {au}")

        logging.info("GSA authentication successful")

        idms_pet = spd.get("t", {}).get("com.apple.gs.idms.pet", {}).get("token", "")
        return self._set_login_state(
            LoginState.AUTHENTICATED, {"idms_pet": idms_pet, "adsid": spd["adsid"]}
        )

    @_require_login_state(LoginState.AUTHENTICATED)
    async def _login_mobileme(self):
        logging.info("Logging into com.apple.mobileme")
        data = plistlib.dumps(
            {
                "apple-id": self._username,
                "delegates": {"com.apple.mobileme": {}},
                "password": self._login_state_data["idms_pet"],
                "client-id": self._uid,
            }
        )

        headers = {
            "X-Apple-ADSID": self._login_state_data["adsid"],
            "User-Agent": "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0",
            "X-Mme-Client-Info": "<MacBookPro18,3> <Mac OS X;13.4.1;22F8>"
            " <com.apple.AOSKit/282 (com.apple.accountsd/113)>",
        }
        headers.update(await self.get_anisette_headers())

        async with await self._http.post(
            "https://setup.icloud.com/setup/iosbuddy/loginDelegates",
            auth=(self._username, self._login_state_data["idms_pet"]),
            data=data,
            headers=headers,
        ) as r:
            content = await r.content.read()
            resp = _load_plist(content)

        mobileme_data = resp.get("delegates", {}).get("com.apple.mobileme", {})
        status = mobileme_data.get("status")
        if status != 0:
            message = mobileme_data.get("status-message")
            raise LoginException(
                f"com.apple.mobileme login failed with status {status}: {message}"
            )

        return self._set_login_state(
            LoginState.LOGGED_IN,
            {"dsid": resp["dsid"], "mobileme_data": mobileme_data["service-data"]},
        )

    async def _sms_2fa_request(
        self, method: str, url: str, data: Optional[dict] = None
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

        async with await self._http.request(
            method, url, json=data, headers=headers
        ) as r:
            if not r.ok:
                raise LoginException(f"HTTP request failed: {r.status_code}")

            return await r.text()

    async def _gsa_request(self, params):
        request_data = {
            "cpd": {
                "bootstrap": True,
                "icscrec": True,
                "pbe": False,
                "prkgen": True,
                "svct": "iCloud",
            }
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

        async with await self._http.post(
            "https://gsa.apple.com/grandslam/GsService2",
            headers=headers,
            data=plistlib.dumps(body),
        ) as r:
            content = await r.content.read()
            return _load_plist(content)["Response"]

    async def get_anisette_headers(self, serial: str = "0") -> dict[str, str]:
        return await self._anisette.get_headers(self._uid, self._devid, serial)


class AppleAccount(BaseAppleAccount):
    def __init__(
        self, anisette: AnisetteProvider, user_id: str = None, device_id: str = None
    ):
        self._asyncacc = AsyncAppleAccount(anisette, user_id, device_id)

        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)

    def __del__(self) -> None:
        coro = self._asyncacc.close()
        return self._loop.run_until_complete(coro)

    @property
    def login_state(self):
        return self._asyncacc.login_state

    @property
    def account_name(self):
        return self._asyncacc.account_name

    @property
    def first_name(self):
        return self._asyncacc.first_name

    @property
    def last_name(self):
        return self._asyncacc.last_name

    def export(self) -> dict:
        return self._asyncacc.export()

    def restore(self, data: dict):
        return self._asyncacc.restore(data)

    def login(self, username: str, password: str) -> LoginState:
        coro = self._asyncacc.login(username, password)
        return self._loop.run_until_complete(coro)

    def get_2fa_methods(self) -> list[BaseSecondFactorMethod]:
        coro = self._asyncacc.get_2fa_methods()
        methods = self._loop.run_until_complete(coro)

        res = []
        for m in methods:
            if isinstance(m, AsyncSmsSecondFactor):
                res.append(SmsSecondFactor(self, m.phone_number_id, m.phone_number))
            else:
                raise RuntimeError(
                    f"Failed to cast 2FA object to sync alternative: {m}. This is a bug, please report it."
                )

        return res

    def sms_2fa_request(self, phone_number_id: int):
        coro = self._asyncacc.sms_2fa_request(phone_number_id)
        return self._loop.run_until_complete(coro)

    def sms_2fa_submit(self, phone_number_id: int, code: str) -> LoginState:
        coro = self._asyncacc.sms_2fa_submit(phone_number_id, code)
        return self._loop.run_until_complete(coro)

    def fetch_reports(
        self, keys: Sequence[KeyPair], date_from: datetime, date_to: datetime
    ):
        coro = self._asyncacc.fetch_reports(keys, date_from, date_to)
        return self._loop.run_until_complete(coro)

    def fetch_last_reports(self, keys: Sequence[KeyPair], hours: int = 7 * 24):
        coro = self._asyncacc.fetch_last_reports(keys, hours)
        return self._loop.run_until_complete(coro)

    def get_anisette_headers(self, serial: str = "0") -> dict[str, str]:
        coro = self._asyncacc.get_anisette_headers()
        return self._loop.run_until_complete(coro)
