"""Public classes related to handling two-factor authentication."""

from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Generic, TypeVar

from typing_extensions import override

from findmy.util.types import MaybeCoro

from .security_key import SecurityKeyAssertion, SecurityKeyChallenge
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
        """See :meth:`BaseSecondFactorMethod.request`."""
        raise NotImplementedError

    @override
    @abstractmethod
    async def submit(self, code: str) -> LoginState:
        """See :meth:`BaseSecondFactorMethod.submit`."""
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
        """See :meth:`BaseSecondFactorMethod.request`."""
        raise NotImplementedError

    @override
    @abstractmethod
    def submit(self, code: str) -> LoginState:
        """See :meth:`BaseSecondFactorMethod.submit`."""
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


class SecurityKeySecondFactorMethod(BaseSecondFactorMethod, ABC):
    """Base class for Apple HSA2 hardware-security-key second factors."""

    @property
    @abstractmethod
    def challenge(self) -> SecurityKeyChallenge:
        """The current validated challenge."""
        raise NotImplementedError


class AsyncSecurityKeySecondFactor(AsyncSecondFactorMethod, SecurityKeySecondFactorMethod):
    """An async Apple HSA2 hardware-security-key second-factor method."""

    def __init__(
        self,
        account: "AsyncAppleAccount",
        challenge: SecurityKeyChallenge,
    ) -> None:
        """Initialize from a challenge returned by ``get_2fa_methods``."""
        super().__init__(account)
        self._challenge = challenge
        self._attempted = False

    @property
    @override
    def challenge(self) -> SecurityKeyChallenge:
        """The current challenge. Its representation omits credential material."""
        return self._challenge

    @override
    async def request(self) -> None:
        """Refresh the challenge without signing or submitting anything."""
        if self._attempted:
            msg = "This security-key method has already been consumed."
            raise RuntimeError(msg)
        self._challenge = await self.account.security_key_2fa_request()

    @override
    async def submit(self, code: str) -> LoginState:
        """Reject code submission; use :meth:`authenticate` with an authenticator callback."""
        del code
        msg = "Security-key methods require authenticate(signer), not submit(code)."
        raise TypeError(msg)

    async def authenticate(
        self,
        signer: Callable[[SecurityKeyChallenge], Awaitable[SecurityKeyAssertion]],
    ) -> LoginState:
        """Sign the current challenge once and complete Apple authentication."""
        if self._attempted:
            msg = "This security-key method has already been consumed."
            raise RuntimeError(msg)
        self._attempted = True
        self._challenge.validate()
        assertion = await signer(self._challenge)
        return await self.account.security_key_2fa_submit(self._challenge, assertion)


class SyncSecurityKeySecondFactor(SyncSecondFactorMethod, SecurityKeySecondFactorMethod):
    """A sync Apple HSA2 hardware-security-key second-factor method."""

    def __init__(
        self,
        account: "AppleAccount",
        challenge: SecurityKeyChallenge,
    ) -> None:
        """Initialize from a challenge returned by ``get_2fa_methods``."""
        super().__init__(account)
        self._challenge = challenge
        self._attempted = False

    @property
    @override
    def challenge(self) -> SecurityKeyChallenge:
        """The current challenge. Its representation omits credential material."""
        return self._challenge

    @override
    def request(self) -> None:
        """Refresh the challenge without signing or submitting anything."""
        if self._attempted:
            msg = "This security-key method has already been consumed."
            raise RuntimeError(msg)
        self._challenge = self.account.security_key_2fa_request()

    @override
    def submit(self, code: str) -> LoginState:
        """Reject code submission; use :meth:`authenticate` with an authenticator callback."""
        del code
        msg = "Security-key methods require authenticate(signer), not submit(code)."
        raise TypeError(msg)

    def authenticate(
        self,
        signer: Callable[[SecurityKeyChallenge], SecurityKeyAssertion],
    ) -> LoginState:
        """Sign the current challenge once and complete Apple authentication."""
        if self._attempted:
            msg = "This security-key method has already been consumed."
            raise RuntimeError(msg)
        self._attempted = True
        self._challenge.validate()
        assertion = signer(self._challenge)
        return self.account.security_key_2fa_submit(self._challenge, assertion)


class AsyncSmsSecondFactor(AsyncSecondFactorMethod, SmsSecondFactorMethod):
    """An async implementation of :meth:`SmsSecondFactorMethod`."""

    def __init__(
        self,
        account: "AsyncAppleAccount",
        number_id: int,
        phone_number: str,
    ) -> None:
        """
        Initialize the second factor method.

        Should not be done manually; use :meth:`AsyncAppleAccount.get_2fa_methods` instead.
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
    """A sync implementation of :meth:`SmsSecondFactorMethod`."""

    def __init__(
        self,
        account: "AppleAccount",
        number_id: int,
        phone_number: str,
    ) -> None:
        """See :meth:`AsyncSmsSecondFactor.__init__`."""
        super().__init__(account)

        self._phone_number_id: int = number_id
        self._phone_number: str = phone_number

    @property
    @override
    def phone_number_id(self) -> int:
        """See :meth:`AsyncSmsSecondFactor.phone_number_id`."""
        return self._phone_number_id

    @property
    @override
    def phone_number(self) -> str:
        """See :meth:`AsyncSmsSecondFactor.phone_number`."""
        return self._phone_number

    @override
    def request(self) -> None:
        """See :meth:`AsyncSmsSecondFactor.request`."""
        return self.account.sms_2fa_request(self._phone_number_id)

    @override
    def submit(self, code: str) -> LoginState:
        """See :meth:`AsyncSmsSecondFactor.submit`."""
        return self.account.sms_2fa_submit(self._phone_number_id, code)


class AsyncTrustedDeviceSecondFactor(AsyncSecondFactorMethod, TrustedDeviceSecondFactorMethod):
    """An async implementation of :meth:`TrustedDeviceSecondFactorMethod`."""

    @override
    async def request(self) -> None:
        return await self.account.td_2fa_request()

    @override
    async def submit(self, code: str) -> LoginState:
        return await self.account.td_2fa_submit(code)


class SyncTrustedDeviceSecondFactor(SyncSecondFactorMethod, TrustedDeviceSecondFactorMethod):
    """A sync implementation of :meth:`TrustedDeviceSecondFactorMethod`."""

    @override
    def request(self) -> None:
        """See :meth:`AsyncTrustedDeviceSecondFactor.request`."""
        return self.account.td_2fa_request()

    @override
    def submit(self, code: str) -> LoginState:
        """See :meth:`AsyncTrustedDeviceSecondFactor.submit`."""
        return self.account.td_2fa_submit(code)
