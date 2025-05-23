"""Exception classes."""

from typing import Any


class InvalidCredentialsError(Exception):
    """Raised when credentials are incorrect."""


class UnauthorizedError(Exception):
    """Raised when an authorization error occurs."""


class UnhandledProtocolError(RuntimeError):
    """
    Raised when an unexpected error occurs while communicating with Apple servers.

    This is almost always a bug, so please report it.
    """


class InvalidStateError(RuntimeError):
    """
    Raised when a method is used that is in conflict with the internal account state.

    For example: calling `BaseAppleAccount.login` while already logged in.
    """


class BadPlistError(RuntimeError):
    """Raised when a .plist file is not in the expected format."""

    def __init__(self, plist_data: Any, message: str) -> None:  # noqa: ANN401
        """
        Initialize the `BadPlistError` with the invalid plist.

        :param plist: The invalid plist data.
        :param message: A message describing the error.
        """
        self.plist = plist_data
        self.message = message
        super().__init__(f"Invalid plist: {message}")
