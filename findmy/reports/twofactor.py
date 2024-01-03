"""Public classes related to handling two-factor authentication."""
from abc import ABCMeta, abstractmethod
from typing import TYPE_CHECKING, TypeVar

from .state import LoginState

if TYPE_CHECKING:
    # noinspection PyUnresolvedReferences
    from .account import AppleAccount, AsyncAppleAccount, BaseAppleAccount

T = TypeVar("T", bound="BaseAppleAccount")


class BaseSecondFactorMethod(metaclass=ABCMeta):
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
        """
        Put in a request for the second-factor challenge.

        Exact meaning is up to the implementing class.
        """
        raise NotImplementedError

    @abstractmethod
    def submit(self, code: str) -> LoginState:
        """Submit a code to complete the second-factor challenge."""
        raise NotImplementedError


class AsyncSecondFactorMethod(BaseSecondFactorMethod, metaclass=ABCMeta):
    """
    An asynchronous implementation of a second-factor authentication method.

    Intended as a base class for actual implementations to inherit from.
    """

    def __init__(self, account: "AsyncAppleAccount") -> None:
        """Initialize the second-factor method."""
        super().__init__(account)

    @property
    def account(self) -> "AsyncAppleAccount":
        """The account associated with the second-factor method."""
        return self._account


class SyncSecondFactorMethod(BaseSecondFactorMethod, metaclass=ABCMeta):
    """
    A synchronous implementation of a second-factor authentication method.

    Intended as a base class for actual implementations to inherit from.
    """

    def __init__(self, account: "AppleAccount") -> None:
        """Initialize the second-factor method."""
        super().__init__(account)

    @property
    def account(self) -> "AppleAccount":
        """The account associated with the second-factor method."""
        return self._account


class SmsSecondFactorMethod(BaseSecondFactorMethod, metaclass=ABCMeta):
    """Base class for SMS-based two-factor authentication."""

    @property
    @abstractmethod
    def phone_number_id(self) -> int:
        """The phone number's ID. You most likely don't need this."""
        raise NotImplementedError

    @property
    @abstractmethod
    def phone_number(self) -> str:
        """
        The 2FA method's phone number.

        May be masked using unicode characters; should only be used for identification purposes.
        """
        raise NotImplementedError


class AsyncSmsSecondFactor(AsyncSecondFactorMethod, SmsSecondFactorMethod):
    """An async implementation of a second-factor method."""

    def __init__(
        self,
        account: "AsyncAppleAccount",
        number_id: int,
        phone_number: str,
    ) -> None:
        """
        Initialize the second factor method.

        Should not be done manually; use `AsyncAppleAccount.get_2fa_methods` instead.
        """
        super().__init__(account)

        self._phone_number_id: int = number_id
        self._phone_number: str = phone_number

    @property
    def phone_number_id(self) -> int:
        """The phone number's ID. You most likely don't need this."""
        return self._phone_number_id

    @property
    def phone_number(self) -> str:
        """
        The 2FA method's phone number.

        May be masked using unicode characters; should only be used for identification purposes.
        """
        return self._phone_number

    async def request(self) -> None:
        """Request an SMS to the corresponding phone number containing a 2FA code."""
        return await self.account.sms_2fa_request(self._phone_number_id)

    async def submit(self, code: str) -> LoginState:
        """See `BaseSecondFactorMethod.submit`."""
        return await self.account.sms_2fa_submit(self._phone_number_id, code)


class SyncSmsSecondFactor(SyncSecondFactorMethod, SmsSecondFactorMethod):
    """
    A sync implementation of `BaseSecondFactorMethod`.

    Uses `AsyncSmsSecondFactor` internally.
    """

    def __init__(
        self,
        account: "AppleAccount",
        number_id: int,
        phone_number: str,
    ) -> None:
        """See `AsyncSmsSecondFactor.__init__`."""
        super().__init__(account)

        self._phone_number_id: int = number_id
        self._phone_number: str = phone_number

    @property
    def phone_number_id(self) -> int:
        """See `AsyncSmsSecondFactor.phone_number_id`."""
        return self._phone_number_id

    @property
    def phone_number(self) -> str:
        """See `AsyncSmsSecondFactor.phone_number`."""
        return self._phone_number

    def request(self) -> None:
        """See `AsyncSmsSecondFactor.request`."""
        return self.account.sms_2fa_request(self._phone_number_id)

    def submit(self, code: str) -> LoginState:
        """See `AsyncSmsSecondFactor.submit`."""
        return self.account.sms_2fa_submit(self._phone_number_id, code)
