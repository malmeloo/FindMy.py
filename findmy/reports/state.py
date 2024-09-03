"""Account  login state."""

from enum import Enum

from typing_extensions import override


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
