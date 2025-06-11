"""Module containing most of the code necessary to interact with an Apple account."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import plistlib
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    TypedDict,
    TypeVar,
    cast,
    overload,
)

import bs4
import srp._pysrp as srp
from typing_extensions import Concatenate, ParamSpec, override

from findmy.errors import (
    InvalidCredentialsError,
    InvalidStateError,
    UnauthorizedError,
    UnhandledProtocolError,
)
from findmy.util import crypto
from findmy.util.closable import Closable
from findmy.util.http import HttpResponse, HttpSession, decode_plist

from .reports import LocationReport, LocationReportsFetcher
from .state import LoginState
from .twofactor import (
    AsyncSecondFactorMethod,
    AsyncSmsSecondFactor,
    AsyncTrustedDeviceSecondFactor,
    BaseSecondFactorMethod,
    SyncSecondFactorMethod,
    SyncSmsSecondFactor,
    SyncTrustedDeviceSecondFactor,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from findmy.accessory import RollingKeyPairSource
    from findmy.keys import HasHashedPublicKey
    from findmy.util.types import MaybeCoro

    from .anisette import BaseAnisetteProvider

logger = logging.getLogger(__name__)

srp.rfc5054_enable()
srp.no_username_in_x()


class _AccountInfo(TypedDict):
    account_name: str
    first_name: str
    last_name: str
    trusted_device_2fa: bool


_P = ParamSpec("_P")
_R = TypeVar("_R")
_A = TypeVar("_A", bound="BaseAppleAccount")
_F = Callable[Concatenate[_A, _P], _R]


def require_login_state(*states: LoginState) -> Callable[[_F], _F]:
    """Enforce a login state as precondition for a method."""

    def decorator(func: _F) -> _F:
        @wraps(func)
        def wrapper(acc: _A, *args: _P.args, **kwargs: _P.kwargs) -> _R:  # pyright: ignore [reportInvalidTypeVarUse]
            if not isinstance(acc, BaseAppleAccount):
                msg = "This decorator can only be used on instances of BaseAppleAccount."
                raise TypeError(msg)

            if acc.login_state not in states:
                msg = (
                    f"Invalid login state! Currently: {acc.login_state}"
                    f" but should be one of: {states}"
                )
                raise InvalidStateError(msg)

            return func(acc, *args, **kwargs)

        return wrapper

    return decorator


def _extract_phone_numbers(html: str) -> list[dict]:
    soup = bs4.BeautifulSoup(html, features="html.parser")
    data_elem = soup.find("script", {"class": "boot_args"})
    if not data_elem:
        msg = "Could not find HTML element containing phone numbers"
        raise RuntimeError(msg)

    data = json.loads(data_elem.text)
    return data.get("direct", {}).get("phoneNumberVerification", {}).get("trustedPhoneNumbers", [])


class BaseAppleAccount(Closable, ABC):
    """Base class for an Apple account."""

    @property
    @abstractmethod
    def login_state(self) -> LoginState:
        """The current login state of the account."""
        raise NotImplementedError

    @property
    @abstractmethod
    def account_name(self) -> str | None:
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
    def to_json(self, path: str | Path | None = None) -> dict:
        """
        Export the current state of the account as a JSON-serializable dictionary.

        If `path` is provided, the output will also be written to that file.

        The output of this method is guaranteed to be JSON-serializable, and passing
        the return value of this function as an argument to `BaseAppleAccount.from_json`
        will always result in an exact copy of the internal state as it was when exported.

        This method is especially useful to avoid having to keep going through the login flow.
        """
        raise NotImplementedError

    @abstractmethod
    def from_json(self, json_: str | Path | Mapping, /) -> None:
        """
        Restore the state from a previous `BaseAppleAccount.to_json` export.

        If given a str or Path, it must point to a json file from `BaseAppleAccount.to_json`.
        Otherwise it should be the Mapping itself.

        See `BaseAppleAccount.to_json` for more information.
        """
        raise NotImplementedError

    @abstractmethod
    def login(self, username: str, password: str) -> MaybeCoro[LoginState]:
        """Log in to an Apple account using a username and password."""
        raise NotImplementedError

    @abstractmethod
    def get_2fa_methods(self) -> MaybeCoro[Sequence[BaseSecondFactorMethod]]:
        """
        Get a list of 2FA methods that can be used as a secondary challenge.

        Currently, only SMS-based 2FA methods are supported.
        """
        raise NotImplementedError

    @abstractmethod
    def sms_2fa_request(self, phone_number_id: int) -> MaybeCoro[None]:
        """
        Request a 2FA code to be sent to a specific phone number ID.

        Consider using `BaseSecondFactorMethod.request` instead.
        """
        raise NotImplementedError

    @abstractmethod
    def sms_2fa_submit(self, phone_number_id: int, code: str) -> MaybeCoro[LoginState]:
        """
        Submit a 2FA code that was sent to a specific phone number ID.

        Consider using `BaseSecondFactorMethod.submit` instead.
        """
        raise NotImplementedError

    @abstractmethod
    def td_2fa_request(self) -> MaybeCoro[None]:
        """
        Request a 2FA code to be sent to a trusted device.

        Consider using `BaseSecondFactorMethod.request` instead.
        """
        raise NotImplementedError

    @abstractmethod
    def td_2fa_submit(self, code: str) -> MaybeCoro[LoginState]:
        """
        Submit a 2FA code that was sent to a trusted device.

        Consider using `BaseSecondFactorMethod.submit` instead.
        """
        raise NotImplementedError

    @overload
    @abstractmethod
    def fetch_reports(
        self,
        keys: HasHashedPublicKey,
        date_from: datetime,
        date_to: datetime | None,
    ) -> MaybeCoro[list[LocationReport]]: ...

    @overload
    @abstractmethod
    def fetch_reports(
        self,
        keys: RollingKeyPairSource,
        date_from: datetime,
        date_to: datetime | None,
    ) -> MaybeCoro[list[LocationReport]]: ...

    @overload
    @abstractmethod
    def fetch_reports(
        self,
        keys: Sequence[HasHashedPublicKey | RollingKeyPairSource],
        date_from: datetime,
        date_to: datetime | None,
    ) -> MaybeCoro[dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]]: ...

    @abstractmethod
    def fetch_reports(
        self,
        keys: HasHashedPublicKey
        | Sequence[HasHashedPublicKey | RollingKeyPairSource]
        | RollingKeyPairSource,
        date_from: datetime,
        date_to: datetime | None,
    ) -> MaybeCoro[
        list[LocationReport] | dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]
    ]:
        """
        Fetch location reports for `HasHashedPublicKey`s between `date_from` and `date_end`.

        Returns a dictionary mapping `HasHashedPublicKey`s to a list of their location reports.
        """
        raise NotImplementedError

    @overload
    @abstractmethod
    def fetch_last_reports(
        self,
        keys: HasHashedPublicKey,
        hours: int = 7 * 24,
    ) -> MaybeCoro[list[LocationReport]]: ...

    @overload
    @abstractmethod
    def fetch_last_reports(
        self,
        keys: RollingKeyPairSource,
        hours: int = 7 * 24,
    ) -> MaybeCoro[list[LocationReport]]: ...

    @overload
    @abstractmethod
    def fetch_last_reports(
        self,
        keys: Sequence[HasHashedPublicKey | RollingKeyPairSource],
        hours: int = 7 * 24,
    ) -> MaybeCoro[dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]]: ...

    @abstractmethod
    def fetch_last_reports(
        self,
        keys: HasHashedPublicKey
        | RollingKeyPairSource
        | Sequence[HasHashedPublicKey | RollingKeyPairSource],
        hours: int = 7 * 24,
    ) -> MaybeCoro[
        list[LocationReport] | dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]
    ]:
        """
        Fetch location reports for a sequence of `HasHashedPublicKey`s for the last `hours` hours.

        Utility method as an alternative to using `BaseAppleAccount.fetch_reports` directly.
        """
        raise NotImplementedError

    @abstractmethod
    def get_anisette_headers(
        self,
        with_client_info: bool = False,
        serial: str = "0",
    ) -> MaybeCoro[dict[str, str]]:
        """
        Retrieve a complete dictionary of Anisette headers.

        Utility method for `AnisetteProvider.get_headers` using this account's user and device ID.
        """
        raise NotImplementedError


class AsyncAppleAccount(BaseAppleAccount):
    """An async implementation of `BaseAppleAccount`."""

    # auth endpoints
    _ENDPOINT_GSA = "https://gsa.apple.com/grandslam/GsService2"
    _ENDPOINT_LOGIN_MOBILEME = "https://setup.icloud.com/setup/iosbuddy/loginDelegates"

    # 2fa auth endpoints
    _ENDPOINT_2FA_METHODS = "https://gsa.apple.com/auth"
    _ENDPOINT_2FA_SMS_REQUEST = "https://gsa.apple.com/auth/verify/phone"
    _ENDPOINT_2FA_SMS_SUBMIT = "https://gsa.apple.com/auth/verify/phone/securitycode"
    _ENDPOINT_2FA_TD_REQUEST = "https://gsa.apple.com/auth/verify/trusteddevice"
    _ENDPOINT_2FA_TD_SUBMIT = "https://gsa.apple.com/grandslam/GsService2/validate"

    # reports endpoints
    _ENDPOINT_REPORTS_FETCH = "https://gateway.icloud.com/acsnservice/fetch"

    def __init__(
        self,
        *,
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
        super().__init__()

        self._anisette: BaseAnisetteProvider = anisette
        self._uid: str = user_id or str(uuid.uuid4())
        self._devid: str = device_id or str(uuid.uuid4())

        self._username: str | None = None
        self._password: str | None = None

        self._login_state: LoginState = LoginState.LOGGED_OUT
        self._login_state_data: dict = {}

        self._account_info: _AccountInfo | None = None

        self._http: HttpSession = HttpSession()
        self._reports: LocationReportsFetcher = LocationReportsFetcher(self)

    def _set_login_state(
        self,
        state: LoginState,
        data: dict | None = None,
    ) -> LoginState:
        # clear account info if downgrading state (e.g. LOGGED_IN -> LOGGED_OUT)
        if state < self._login_state:
            logger.debug("Clearing cached account information")
            self._account_info = None

        logger.info("Transitioning login state: %s -> %s", self._login_state, state)
        self._login_state = state
        self._login_state_data = data or {}

        return state

    @property
    @override
    def login_state(self) -> LoginState:
        """See `BaseAppleAccount.login_state`."""
        return self._login_state

    @property
    @require_login_state(
        LoginState.LOGGED_IN,
        LoginState.AUTHENTICATED,
        LoginState.REQUIRE_2FA,
    )
    @override
    def account_name(self) -> str | None:
        """See `BaseAppleAccount.account_name`."""
        return self._account_info["account_name"] if self._account_info else None

    @property
    @require_login_state(
        LoginState.LOGGED_IN,
        LoginState.AUTHENTICATED,
        LoginState.REQUIRE_2FA,
    )
    @override
    def first_name(self) -> str | None:
        """See `BaseAppleAccount.first_name`."""
        return self._account_info["first_name"] if self._account_info else None

    @property
    @require_login_state(
        LoginState.LOGGED_IN,
        LoginState.AUTHENTICATED,
        LoginState.REQUIRE_2FA,
    )
    @override
    def last_name(self) -> str | None:
        """See `BaseAppleAccount.last_name`."""
        return self._account_info["last_name"] if self._account_info else None

    @override
    def to_json(self, path: str | Path | None = None) -> dict:
        result = {
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
        if path is not None:
            Path(path).write_text(json.dumps(result, indent=4))
        return result

    @override
    def from_json(self, json_: str | Path | Mapping, /) -> None:
        data = json.loads(Path(json_).read_text()) if isinstance(json_, (str, Path)) else json_
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

    @override
    async def close(self) -> None:
        """
        Close any sessions or other resources in use by this object.

        Should be called when the object will no longer be used.
        """
        await self._anisette.close()
        await self._http.close()

    @require_login_state(LoginState.LOGGED_OUT)
    @override
    async def login(self, username: str, password: str) -> LoginState:
        """See `BaseAppleAccount.login`."""
        # LOGGED_OUT -> (REQUIRE_2FA or AUTHENTICATED)
        new_state = await self._gsa_authenticate(username, password)
        if new_state == LoginState.REQUIRE_2FA:  # pass control back to handle 2FA
            return new_state

        # AUTHENTICATED -> LOGGED_IN
        return await self._login_mobileme()

    @require_login_state(LoginState.REQUIRE_2FA)
    @override
    async def get_2fa_methods(self) -> Sequence[AsyncSecondFactorMethod]:
        """See `BaseAppleAccount.get_2fa_methods`."""
        methods: list[AsyncSecondFactorMethod] = []

        if self._account_info is None:
            return []

        if self._account_info["trusted_device_2fa"]:
            methods.append(AsyncTrustedDeviceSecondFactor(self))

        # sms
        auth_page = await self._sms_2fa_request("GET", self._ENDPOINT_2FA_METHODS)
        try:
            phone_numbers = _extract_phone_numbers(auth_page)
            methods.extend(
                AsyncSmsSecondFactor(
                    self,
                    number.get("id") or -1,
                    number.get("numberWithDialCode") or "-",
                )
                for number in phone_numbers
            )
        except RuntimeError:
            logger.warning("Unable to extract phone numbers from login page")

        return methods

    @require_login_state(LoginState.REQUIRE_2FA)
    @override
    async def sms_2fa_request(self, phone_number_id: int) -> None:
        """See `BaseAppleAccount.sms_2fa_request`."""
        data = {"phoneNumber": {"id": phone_number_id}, "mode": "sms"}

        await self._sms_2fa_request(
            "PUT",
            self._ENDPOINT_2FA_SMS_REQUEST,
            data,
        )

    @require_login_state(LoginState.REQUIRE_2FA)
    @override
    async def sms_2fa_submit(self, phone_number_id: int, code: str) -> LoginState:
        """See `BaseAppleAccount.sms_2fa_submit`."""
        data = {
            "phoneNumber": {"id": phone_number_id},
            "securityCode": {"code": str(code)},
            "mode": "sms",
        }

        await self._sms_2fa_request(
            "POST",
            self._ENDPOINT_2FA_SMS_SUBMIT,
            data,
        )

        # REQUIRE_2FA -> AUTHENTICATED
        new_state = await self._gsa_authenticate()
        if new_state != LoginState.AUTHENTICATED:
            msg = f"Unexpected state after submitting 2FA: {new_state}"
            raise UnhandledProtocolError(msg)

        # AUTHENTICATED -> LOGGED_IN
        return await self._login_mobileme()

    @require_login_state(LoginState.REQUIRE_2FA)
    @override
    async def td_2fa_request(self) -> None:
        """See `BaseAppleAccount.td_2fa_request`."""
        headers = {
            "Content-Type": "text/x-xml-plist",
            "Accept": "text/x-xml-plist",
        }
        await self._sms_2fa_request(
            "GET",
            self._ENDPOINT_2FA_TD_REQUEST,
            headers=headers,
        )

    @require_login_state(LoginState.REQUIRE_2FA)
    @override
    async def td_2fa_submit(self, code: str) -> LoginState:
        """See `BaseAppleAccount.td_2fa_submit`."""
        headers = {
            "security-code": code,
            "Content-Type": "text/x-xml-plist",
            "Accept": "text/x-xml-plist",
        }
        await self._sms_2fa_request(
            "GET",
            self._ENDPOINT_2FA_TD_SUBMIT,
            headers=headers,
        )

        # REQUIRE_2FA -> AUTHENTICATED
        new_state = await self._gsa_authenticate()
        if new_state != LoginState.AUTHENTICATED:
            msg = f"Unexpected state after submitting 2FA: {new_state}"
            raise UnhandledProtocolError(msg)

        # AUTHENTICATED -> LOGGED_IN
        return await self._login_mobileme()

    @require_login_state(LoginState.LOGGED_IN)
    async def fetch_raw_reports(self, start: int, end: int, ids: list[str]) -> dict[str, Any]:
        """Make a request for location reports, returning raw data."""
        auth = (
            self._login_state_data["dsid"],
            self._login_state_data["mobileme_data"]["tokens"]["searchPartyToken"],
        )
        data = {"search": [{"startDate": start, "endDate": end, "ids": ids}]}

        async def _do_request() -> HttpResponse:
            return await self._http.post(
                self._ENDPOINT_REPORTS_FETCH,
                auth=auth,
                headers=await self.get_anisette_headers(),
                json=data,
            )

        r = await _do_request()
        if r.status_code == 401:
            logger.info("Got 401 while fetching reports, redoing login")

            new_state = await self._gsa_authenticate()
            if new_state != LoginState.AUTHENTICATED:
                msg = f"Unexpected login state after reauth: {new_state}. Please log in again."
                raise UnauthorizedError(msg)
            await self._login_mobileme()

            r = await _do_request()

        if r.status_code == 401:
            msg = "Not authorized to fetch reports."
            raise UnauthorizedError(msg)

        try:
            resp = r.json()
        except json.JSONDecodeError:
            resp = {}
        if not r.ok or resp.get("statusCode") != "200":
            msg = f"Failed to fetch reports: {resp.get('statusCode')}"
            raise UnhandledProtocolError(msg)

        return resp

    @overload
    async def fetch_reports(
        self,
        keys: HasHashedPublicKey,
        date_from: datetime,
        date_to: datetime | None,
    ) -> list[LocationReport]: ...

    @overload
    async def fetch_reports(
        self,
        keys: RollingKeyPairSource,
        date_from: datetime,
        date_to: datetime | None,
    ) -> list[LocationReport]: ...

    @overload
    async def fetch_reports(
        self,
        keys: Sequence[HasHashedPublicKey | RollingKeyPairSource],
        date_from: datetime,
        date_to: datetime | None,
    ) -> dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]: ...

    @require_login_state(LoginState.LOGGED_IN)
    @override
    async def fetch_reports(
        self,
        keys: HasHashedPublicKey
        | RollingKeyPairSource
        | Sequence[HasHashedPublicKey | RollingKeyPairSource],
        date_from: datetime,
        date_to: datetime | None,
    ) -> (
        list[LocationReport] | dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]
    ):
        """See `BaseAppleAccount.fetch_reports`."""
        date_to = date_to or datetime.now().astimezone()

        return await self._reports.fetch_reports(
            date_from,
            date_to,
            keys,
        )

    @overload
    async def fetch_last_reports(
        self,
        keys: HasHashedPublicKey,
        hours: int = 7 * 24,
    ) -> list[LocationReport]: ...

    @overload
    async def fetch_last_reports(
        self,
        keys: RollingKeyPairSource,
        hours: int = 7 * 24,
    ) -> list[LocationReport]: ...

    @overload
    async def fetch_last_reports(
        self,
        keys: Sequence[HasHashedPublicKey | RollingKeyPairSource],
        hours: int = 7 * 24,
    ) -> dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]: ...

    @require_login_state(LoginState.LOGGED_IN)
    @override
    async def fetch_last_reports(
        self,
        keys: HasHashedPublicKey
        | RollingKeyPairSource
        | Sequence[HasHashedPublicKey | RollingKeyPairSource],
        hours: int = 7 * 24,
    ) -> (
        list[LocationReport] | dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]
    ):
        """See `BaseAppleAccount.fetch_last_reports`."""
        end = datetime.now(tz=timezone.utc)
        start = end - timedelta(hours=hours)

        return await self.fetch_reports(keys, start, end)

    @require_login_state(LoginState.LOGGED_OUT, LoginState.REQUIRE_2FA, LoginState.LOGGED_IN)
    async def _gsa_authenticate(
        self,
        username: str | None = None,
        password: str | None = None,
    ) -> LoginState:
        # use stored values for re-authentication
        self._username = username or self._username
        self._password = password or self._password

        logger.info("Attempting authentication for user %s", self._username)

        if not self._username or not self._password:
            msg = "No username or password specified"
            raise ValueError(msg)

        logger.debug("Starting authentication with username")

        usr = srp.User(self._username, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048)
        _, a2k = usr.start_authentication()
        r = await self._gsa_request(
            {"A2k": a2k, "u": self._username, "ps": ["s2k", "s2k_fo"], "o": "init"},
        )

        logger.debug("Verifying response to auth request")

        if r["Status"].get("ec") != 0:
            msg = "Email verification failed: " + r["Status"].get("em")
            raise InvalidCredentialsError(msg)
        sp = r.get("sp")
        if not isinstance(sp, str) or sp not in {"s2k", "s2k_fo"}:
            msg = f"This implementation only supports s2k and sk2_fo. Server returned {sp}"
            raise UnhandledProtocolError(msg)

        logger.debug("Attempting password challenge")

        usr.p = crypto.encrypt_password(self._password, r["s"], r["i"], sp)
        m1 = usr.process_challenge(r["s"], r["B"])
        if m1 is None:
            msg = "Failed to process challenge"
            raise UnhandledProtocolError(msg)
        r = await self._gsa_request(
            {"c": r["c"], "M1": m1, "u": self._username, "o": "complete"},
        )

        logger.debug("Verifying password challenge response")

        if r["Status"].get("ec") != 0:
            msg = "Password authentication failed: " + r["Status"].get("em")
            raise InvalidCredentialsError(msg)
        usr.verify_session(r.get("M2"))
        if not usr.authenticated():
            msg = "Failed to verify session"
            raise UnhandledProtocolError(msg)

        logger.debug("Decrypting SPD data in response")

        spd = decode_plist(
            crypto.decrypt_spd_aes_cbc(
                usr.get_session_key() or b"",
                r["spd"],
            ),
        )

        logger.debug("Received account information")
        self._account_info = cast(
            "_AccountInfo",
            {
                "account_name": spd.get("acname"),
                "first_name": spd.get("fn"),
                "last_name": spd.get("ln"),
                "trusted_device_2fa": False,
            },
        )

        au = r["Status"].get("au")
        if au in ("secondaryAuth", "trustedDeviceSecondaryAuth"):
            logger.info("Detected 2FA requirement: %s", au)

            self._account_info["trusted_device_2fa"] = au == "trustedDeviceSecondaryAuth"

            return self._set_login_state(
                LoginState.REQUIRE_2FA,
                {"adsid": spd["adsid"], "idms_token": spd["GsIdmsToken"]},
            )
        if au is None:
            logger.info("GSA authentication successful")

            idms_pet = spd.get("t", {}).get("com.apple.gs.idms.pet", {}).get("token", "")
            return self._set_login_state(
                LoginState.AUTHENTICATED,
                {"idms_pet": idms_pet, "adsid": spd["adsid"]},
            )

        msg = f"Unknown auth value: {au}"
        raise UnhandledProtocolError(msg)

    @require_login_state(LoginState.AUTHENTICATED)
    async def _login_mobileme(self) -> LoginState:
        logger.info("Logging into com.apple.mobileme")
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
            self._ENDPOINT_LOGIN_MOBILEME,
            auth=(self._username or "", self._login_state_data["idms_pet"]),
            data=data,
            headers=headers,
        )
        data = resp.plist()

        mobileme_data = data.get("delegates", {}).get("com.apple.mobileme", {})
        status = mobileme_data.get("status") or data.get("status")
        if status != 0:
            status_message = mobileme_data.get("status-message") or data.get("status-message")
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
        data: dict[str, Any] | None = None,
        headers: dict[str, Any] | None = None,
    ) -> str:
        adsid = self._login_state_data["adsid"]
        idms_token = self._login_state_data["idms_token"]
        identity_token = base64.b64encode((adsid + ":" + idms_token).encode()).decode()

        headers = headers or {}
        headers.update(
            {
                "User-Agent": "Xcode",
                "Accept-Language": "en-us",
                "X-Apple-Identity-Token": identity_token,
            },
        )
        headers.update(await self.get_anisette_headers(with_client_info=True))

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

    async def _gsa_request(self, parameters: dict[str, Any]) -> dict[str, Any]:
        body = {
            "Header": {
                "Version": "1.0.1",
            },
            "Request": {
                "cpd": await self._anisette.get_cpd(
                    self._uid,
                    self._devid,
                ),
                **parameters,
            },
        }

        headers = {
            "Content-Type": "text/x-xml-plist",
            "Accept": "*/*",
            "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
            "X-MMe-Client-Info": self._anisette.client,
        }

        resp = await self._http.post(
            self._ENDPOINT_GSA,
            headers=headers,
            data=plistlib.dumps(body),
        )
        if not resp.ok:
            msg = f"Error response for GSA request: {resp.status_code}"
            raise UnhandledProtocolError(msg)
        return resp.plist()["Response"]

    @override
    async def get_anisette_headers(
        self,
        with_client_info: bool = False,
        serial: str = "0",
    ) -> dict[str, str]:
        """See `BaseAppleAccount.get_anisette_headers`."""
        return await self._anisette.get_headers(self._uid, self._devid, serial, with_client_info)


class AppleAccount(BaseAppleAccount):
    """
    A sync implementation of `BaseappleAccount`.

    Uses `AsyncappleAccount` internally.
    """

    def __init__(
        self,
        *,
        anisette: BaseAnisetteProvider,
        user_id: str | None = None,
        device_id: str | None = None,
    ) -> None:
        """See `AsyncAppleAccount.__init__`."""
        self._asyncacc = AsyncAppleAccount(anisette=anisette, user_id=user_id, device_id=device_id)

        try:
            self._evt_loop = asyncio.get_running_loop()
        except RuntimeError:
            self._evt_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._evt_loop)

        super().__init__(self._evt_loop)

    @override
    async def close(self) -> None:
        """See `AsyncAppleAccount.close`."""
        await self._asyncacc.close()

    @property
    @override
    def login_state(self) -> LoginState:
        """See `AsyncAppleAccount.login_state`."""
        return self._asyncacc.login_state

    @property
    @override
    def account_name(self) -> str | None:
        """See `AsyncAppleAccount.login_state`."""
        return self._asyncacc.account_name

    @property
    @override
    def first_name(self) -> str | None:
        """See `AsyncAppleAccount.first_name`."""
        return self._asyncacc.first_name

    @property
    @override
    def last_name(self) -> str | None:
        """See `AsyncAppleAccount.last_name`."""
        return self._asyncacc.last_name

    @override
    def to_json(self, path: str | Path | None = None) -> dict:
        return self._asyncacc.to_json(path)

    @override
    def from_json(self, json_: str | Path | Mapping, /) -> None:
        return self._asyncacc.from_json(json_)

    @override
    def login(self, username: str, password: str) -> LoginState:
        """See `AsyncAppleAccount.login`."""
        coro = self._asyncacc.login(username, password)
        return self._evt_loop.run_until_complete(coro)

    @override
    def get_2fa_methods(self) -> Sequence[SyncSecondFactorMethod]:
        """See `AsyncAppleAccount.get_2fa_methods`."""
        coro = self._asyncacc.get_2fa_methods()
        methods = self._evt_loop.run_until_complete(coro)

        res = []
        for m in methods:
            if isinstance(m, AsyncSmsSecondFactor):
                res.append(SyncSmsSecondFactor(self, m.phone_number_id, m.phone_number))
            elif isinstance(m, AsyncTrustedDeviceSecondFactor):
                res.append(SyncTrustedDeviceSecondFactor(self))
            else:
                msg = (
                    f"Failed to cast 2FA object to sync alternative: {m}."
                    f" This is a bug, please report it."
                )
                raise TypeError(msg)

        return res

    @override
    def sms_2fa_request(self, phone_number_id: int) -> None:
        """See `AsyncAppleAccount.sms_2fa_request`."""
        coro = self._asyncacc.sms_2fa_request(phone_number_id)
        return self._evt_loop.run_until_complete(coro)

    @override
    def sms_2fa_submit(self, phone_number_id: int, code: str) -> LoginState:
        """See `AsyncAppleAccount.sms_2fa_submit`."""
        coro = self._asyncacc.sms_2fa_submit(phone_number_id, code)
        return self._evt_loop.run_until_complete(coro)

    @override
    def td_2fa_request(self) -> None:
        """See `AsyncAppleAccount.td_2fa_request`."""
        coro = self._asyncacc.td_2fa_request()
        return self._evt_loop.run_until_complete(coro)

    @override
    def td_2fa_submit(self, code: str) -> LoginState:
        """See `AsyncAppleAccount.td_2fa_submit`."""
        coro = self._asyncacc.td_2fa_submit(code)
        return self._evt_loop.run_until_complete(coro)

    @overload
    def fetch_reports(
        self,
        keys: HasHashedPublicKey,
        date_from: datetime,
        date_to: datetime | None,
    ) -> list[LocationReport]: ...

    @overload
    def fetch_reports(
        self,
        keys: RollingKeyPairSource,
        date_from: datetime,
        date_to: datetime | None,
    ) -> list[LocationReport]: ...

    @overload
    def fetch_reports(
        self,
        keys: Sequence[HasHashedPublicKey | RollingKeyPairSource],
        date_from: datetime,
        date_to: datetime | None,
    ) -> dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]: ...

    @override
    def fetch_reports(
        self,
        keys: HasHashedPublicKey
        | Sequence[HasHashedPublicKey | RollingKeyPairSource]
        | RollingKeyPairSource,
        date_from: datetime,
        date_to: datetime | None,
    ) -> (
        list[LocationReport] | dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]
    ):
        """See `AsyncAppleAccount.fetch_reports`."""
        coro = self._asyncacc.fetch_reports(keys, date_from, date_to)
        return self._evt_loop.run_until_complete(coro)

    @overload
    def fetch_last_reports(
        self,
        keys: HasHashedPublicKey,
        hours: int = 7 * 24,
    ) -> list[LocationReport]: ...

    @overload
    def fetch_last_reports(
        self,
        keys: RollingKeyPairSource,
        hours: int = 7 * 24,
    ) -> list[LocationReport]: ...

    @overload
    def fetch_last_reports(
        self,
        keys: Sequence[HasHashedPublicKey | RollingKeyPairSource],
        hours: int = 7 * 24,
    ) -> dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]: ...

    @override
    def fetch_last_reports(
        self,
        keys: HasHashedPublicKey
        | RollingKeyPairSource
        | Sequence[HasHashedPublicKey | RollingKeyPairSource],
        hours: int = 7 * 24,
    ) -> (
        list[LocationReport] | dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]
    ):
        """See `AsyncAppleAccount.fetch_last_reports`."""
        coro = self._asyncacc.fetch_last_reports(keys, hours)
        return self._evt_loop.run_until_complete(coro)

    @override
    def get_anisette_headers(
        self,
        with_client_info: bool = False,
        serial: str = "0",
    ) -> dict[str, str]:
        """See `AsyncAppleAccount.get_anisette_headers`."""
        coro = self._asyncacc.get_anisette_headers(with_client_info, serial)
        return self._evt_loop.run_until_complete(coro)
