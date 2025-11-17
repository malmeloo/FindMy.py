"""Exception classes."""


class InvalidCredentialsError(Exception):
    """Raised when credentials are incorrect."""


class UnauthorizedError(Exception):
    """Raised when an authorization error occurs."""


class UnhandledProtocolError(RuntimeError):
    """
    Raised when an unexpected error occurs while communicating with Apple servers.

    This is almost always a bug, so please report it.
    """


class EmptyResponseError(RuntimeError):
    """
    Raised when Apple servers return an empty response when querying location reports.

    This is a bug on Apple's side. More info: https://github.com/malmeloo/FindMy.py/issues/185
    """


class InvalidStateError(RuntimeError):
    """
    Raised when a method is used that is in conflict with the internal account state.

    For example: calling :meth:`BaseAppleAccount.login` while already logged in.
    """
