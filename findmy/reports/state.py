"""Code related to internal account state handling."""
from enum import Enum
from functools import wraps
from typing import TYPE_CHECKING, Callable, Concatenate, ParamSpec, TypeVar

from findmy.util.errors import InvalidStateError

if TYPE_CHECKING:
    # noinspection PyUnresolvedReferences
    from .account import BaseAppleAccount

P = ParamSpec("P")
R = TypeVar("R")
A = TypeVar("A", bound="BaseAppleAccount")
F = Callable[Concatenate[A, P], R]


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

    def __repr__(self) -> str:
        """Human-readable string representation of the state."""
        return self.__str__()


def require_login_state(*states: LoginState) -> Callable[[F], F]:
    """Enforce a login state as precondition for a method."""

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(acc: A, *args: P.args, **kwargs: P.kwargs) -> R:
            if acc.login_state not in states:
                msg = (
                    f"Invalid login state! Currently: {acc.login_state}"
                    f" but should be one of: {states}"
                )
                raise InvalidStateError(msg)

            return func(acc, *args, **kwargs)

        return wrapper

    return decorator
