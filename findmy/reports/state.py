"""Code related to internal account state handling."""
from enum import Enum
from functools import wraps
from typing import Callable, Concatenate, ParamSpec, TypeVar

from typing_extensions import override

from findmy.util.errors import InvalidStateError

from .account import BaseAppleAccount


class LoginState(Enum):
    """Enum of possible login states. Used for `AppleAccount`'s internal state machine."""

    LOGGED_OUT = 0
    REQUIRE_2FA = 1
    AUTHENTICATED = 2
    LOGGED_IN = 3

    def __lt__(self, other: "LoginState") -> bool:
        """
        Compare against another `LoginState`.

        A `LoginState` is said to be "less than" another `LoginState` iff it is in
        an "earlier" stage of the login process, going from LOGGED_OUT to LOGGED_IN.
        """
        if isinstance(other, LoginState):
            return self.value < other.value

        return NotImplemented

    @override
    def __repr__(self) -> str:
        """Human-readable string representation of the state."""
        return self.__str__()


_P = ParamSpec("_P")
_R = TypeVar("_R")
_A = TypeVar("_A", bound="BaseAppleAccount")
_F = Callable[Concatenate[_A, _P], _R]


def require_login_state(*states: LoginState) -> Callable[[_F], _F]:
    """Enforce a login state as precondition for a method."""

    def decorator(func: _F) -> _F:
        @wraps(func)
        def wrapper(acc: _A, *args: _P.args, **kwargs: _P.kwargs) -> _R:  # pyright: ignore [reportInvalidTypeVarUse]
            if not isinstance(args[0], BaseAppleAccount):
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
