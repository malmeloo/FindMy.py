"""Public classes related to handling two-factor authentication."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Generic, TypeVar

from typing_extensions import override

from findmy.util.types import MaybeCoro

from .state import LoginState

if TYPE_CHECKING:
    # noinspection PyUnresolvedReferences
    from .account import AppleAccount, AsyncAppleAccount, BaseAppleAccount

_AccType = TypeVar("_AccType", bound="BaseAppleAccount")


class BaseSecondFactorMethod(ABC, Generic[_AccType]):
    """Base class for a second-factor authentication method for an Apple account."""

    def __init__(self, account: _AccType) -> None:
        """Initialize the second-factor method."""
        self._account: _AccType = account

    @property
    def account(self) -> _AccType:
        """The account associated with the second-factor method."""
        return self._account

    @abstractmethod
    def request(self) -> MaybeCoro[None]:
        """
        Put in a request for the second-factor challenge.

        Exact meaning is up to the implementing class.
        """
        raise NotImplementedError

    @abstractmethod
    def submit(self, code: str) -> MaybeCoro[LoginState]:
        """Submit a code to complete the second-factor challenge."""
        raise NotImplementedError


class AsyncSecondFactorMethod(BaseSecondFactorMethod, ABC):
    """
    An asynchronous implementation of a second-factor authentication method.

    Intended as a base class for actual implementations to inherit from.
    """

    def __init__(self, account: "AsyncAppleAccount") -> None:
        """Initialize the second-factor method."""
        super().__init__(account)

    @property
    @override
    def account(self) -> "AsyncAppleAccount":
        """The account associated with the second-factor method."""
        return self._account

    @override
    @abstractmethod
    async def request(self) -> None:
        """See `BaseSecondFactorMethod.request`."""
        raise NotImplementedError

    @override
    @abstractmethod
    async def submit(self, code: str) -> LoginState:
        """See `BaseSecondFactorMethod.submit`."""
        raise NotImplementedError


class SyncSecondFactorMethod(BaseSecondFactorMethod, ABC):
    """
    A synchronous implementation of a second-factor authentication method.

    Intended as a base class for actual implementations to inherit from.
    """

    def __init__(self, account: "AppleAccount") -> None:
        """Initialize the second-factor method."""
        super().__init__(account)

    @property
    @override
    def account(self) -> "AppleAccount":
        """The account associated with the second-factor method."""
        return self._account

    @override
    @abstractmethod
    def request(self) -> None:
        """See `BaseSecondFactorMethod.request`."""
        raise NotImplementedError

    @override
    @abstractmethod
    def submit(self, code: str) -> LoginState:
        """See `BaseSecondFactorMethod.submit`."""
        raise NotImplementedError


class SmsSecondFactorMethod(BaseSecondFactorMethod, ABC):
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


class TrustedDeviceSecondFactorMethod(BaseSecondFactorMethod, ABC):
    """Base class for trusted device-based two-factor authentication."""


class AsyncSmsSecondFactor(AsyncSecondFactorMethod, SmsSecondFactorMethod):
    """An async implementation of `SmsSecondFactorMethod`."""

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
    @override
    def phone_number_id(self) -> int:
        """The phone number's ID. You most likely don't need this."""
        return self._phone_number_id

    @property
    @override
    def phone_number(self) -> str:
        """
        The 2FA method's phone number.

        May be masked using unicode characters; should only be used for identification purposes.
        """
        return self._phone_number

    @override
    async def request(self) -> None:
        """Request an SMS to the corresponding phone number containing a 2FA code."""
        return await self.account.sms_2fa_request(self._phone_number_id)

    @override
    async def submit(self, code: str) -> LoginState:
        """Submit the 2FA code as received over SMS."""
        return await self.account.sms_2fa_submit(self._phone_number_id, code)


class SyncSmsSecondFactor(SyncSecondFactorMethod, SmsSecondFactorMethod):
    """A sync implementation of `SmsSecondFactorMethod`."""

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
    @override
    def phone_number_id(self) -> int:
        """See `AsyncSmsSecondFactor.phone_number_id`."""
        return self._phone_number_id

    @property
    @override
    def phone_number(self) -> str:
        """See `AsyncSmsSecondFactor.phone_number`."""
        return self._phone_number

    @override
    def request(self) -> None:
        """See `AsyncSmsSecondFactor.request`."""
        return self.account.sms_2fa_request(self._phone_number_id)

    @override
    def submit(self, code: str) -> LoginState:
        """See `AsyncSmsSecondFactor.submit`."""
        return self.account.sms_2fa_submit(self._phone_number_id, code)


class AsyncTrustedDeviceSecondFactor(AsyncSecondFactorMethod, TrustedDeviceSecondFactorMethod):
    """An async implementation of `TrustedDeviceSecondFactorMethod`."""

    @override
    async def request(self) -> None:
        return await self.account.td_2fa_request()

    @override
    async def submit(self, code: str) -> LoginState:
        return await self.account.td_2fa_submit(code)


class SyncTrustedDeviceSecondFactor(SyncSecondFactorMethod, TrustedDeviceSecondFactorMethod):
    """A sync implementation of `TrustedDeviceSecondFactorMethod`."""

    @override
    def request(self) -> None:
        """See `AsyncTrustedDeviceSecondFactor.request`."""
        return self.account.td_2fa_request()

    @override
    def submit(self, code: str) -> LoginState:
        """See `AsyncTrustedDeviceSecondFactor.submit`."""
        return self.account.td_2fa_submit(code)
