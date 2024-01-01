"""Module that contains base classes for various other modules. For internal use only."""
from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import TYPE_CHECKING, Sequence, TypeVar

if TYPE_CHECKING:
    from datetime import datetime

    from .keys import KeyPair
    from .reports import KeyReport


class LoginState(Enum):
    """Enum of possible login states. Used for `AppleAccount`'s internal state machine."""

    LOGGED_OUT = 0
    REQUIRE_2FA = 1
    AUTHENTICATED = 2
    LOGGED_IN = 3

    def __lt__(self, other: LoginState) -> bool:
        """Compare against another `LoginState`.

        A `LoginState` is said to be "less than" another `LoginState` iff it is in
        an "earlier" stage of the login process, going from LOGGED_OUT to LOGGED_IN.
        """
        if isinstance(other, LoginState):
            return self.value < other.value

        return NotImplemented

    def __repr__(self) -> str:
        """Human-readable string representation of the state."""
        return self.__str__()


T = TypeVar("T", bound="BaseAppleAccount")


class BaseSecondFactorMethod(ABC):
    """Base class for a second-factor authentication method for an Apple account."""

    def __init__(self, account: T) -> None:
        """Initialize the second-factor method."""
        self._account: T = account

    @property
    def account(self) -> T:
        """The account associated with the second-factor method."""
        return self._account

    @abstractmethod
    def request(self) -> None:
        """Put in a request for the second-factor challenge.

        Exact meaning is up to the implementing class.
        """
        raise NotImplementedError

    @abstractmethod
    def submit(self, code: str) -> LoginState:
        """Submit a code to complete the second-factor challenge."""
        raise NotImplementedError


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
        """The name of the account as reported by Apple.

        This is usually an e-mail address.
        May be None in some cases, such as when not logged in.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def first_name(self) -> str | None:
        """First name of the account holder as reported by Apple.

        May be None in some cases, such as when not logged in.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def last_name(self) -> str | None:
        """Last name of the account holder as reported by Apple.

        May be None in some cases, such as when not logged in.
        """
        raise NotImplementedError

    @abstractmethod
    def export(self) -> dict:
        """Export a representation of the current state of the account as a dictionary.

        The output of this method is guaranteed to be JSON-serializable, and passing
        the return value of this function as an argument to `BaseAppleAccount.restore`
        will always result in an exact copy of the internal state as it was when exported.

        This method is especially useful to avoid having to keep going through the login flow.
        """
        raise NotImplementedError

    @abstractmethod
    def restore(self, data: dict) -> None:
        """Restore a previous export of the internal state of the account.

        See `BaseAppleAccount.export` for more information.
        """
        raise NotImplementedError

    @abstractmethod
    def login(self, username: str, password: str) -> LoginState:
        """Log in to an Apple account using a username and password."""
        raise NotImplementedError

    @abstractmethod
    def get_2fa_methods(self) -> list[BaseSecondFactorMethod]:
        """Get a list of 2FA methods that can be used as a secondary challenge.

        Currently, only SMS-based 2FA methods are supported.
        """
        raise NotImplementedError

    @abstractmethod
    def sms_2fa_request(self, phone_number_id: int) -> None:
        """Request a 2FA code to be sent to a specific phone number ID.

        Consider using `BaseSecondFactorMethod.request` instead.
        """
        raise NotImplementedError

    @abstractmethod
    def sms_2fa_submit(self, phone_number_id: int, code: str) -> LoginState:
        """Submit a 2FA code that was sent to a specific phone number ID.

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
        """Fetch location reports for a sequence of `KeyPair`s between `date_from` and `date_end`.

        Returns a dictionary mapping `KeyPair`s to a list of their location reports.
        """
        raise NotImplementedError

    @abstractmethod
    def fetch_last_reports(
        self,
        keys: Sequence[KeyPair],
        hours: int = 7 * 24,
    ) -> dict[KeyPair, list[KeyReport]]:
        """Fetch location reports for a sequence of `KeyPair`s for the last `hours` hours.

        Utility method as an alternative to using `BaseAppleAccount.fetch_reports` directly.
        """
        raise NotImplementedError

    @abstractmethod
    def get_anisette_headers(self, serial: str = "0") -> dict[str, str]:
        """Retrieve a complete dictionary of Anisette headers.

        Utility method for `AnisetteProvider.get_headers` using this account's user and device ID.
        """
        raise NotImplementedError
