"""Expose only SDK enum codes, never exception strings, cause text or payloads."""

from fido2.client import ClientError
from fido2.ctap import CtapError


def safe_fido_error(error: ClientError) -> dict[str, object]:
    result = {
        "status": "failed",
        "error_type": "ClientError",
        "retry": False,
        "details_suppressed": True,
    }
    code = error.code
    result["client_code"] = code.name if isinstance(code, ClientError.ERR) else "UNKNOWN"
    cause = error.cause
    if isinstance(cause, CtapError):
        result["ctap_code"] = (
            cause.code.name if isinstance(cause.code, CtapError.ERR) else "UNKNOWN"
        )
    else:
        result["ctap_code"] = "UNAVAILABLE"
    ctap = result["ctap_code"]
    if ctap in ("PIN_INVALID", "PIN_AUTH_INVALID"):
        reason = "Key rejected PIN verification. Do not retry or guess the PIN."
    elif ctap in ("PIN_BLOCKED", "PIN_AUTH_BLOCKED", "UV_BLOCKED"):
        reason = "Key verification is blocked. Stop; do not reset the key."
    elif ctap in ("NO_CREDENTIALS", "INVALID_CREDENTIAL"):
        reason = "No matching credential; review required, without account changes."
    elif code == ClientError.ERR.TIMEOUT or ctap in (
        "KEEPALIVE_CANCEL",
        "ACTION_TIMEOUT",
        "USER_ACTION_TIMEOUT",
    ):
        reason = "Key operation timed out or was cancelled; this does not prove an incorrect PIN."
    elif code == ClientError.ERR.CONFIGURATION_UNSUPPORTED:
        reason = "Client reported an unsupported security-key configuration."
    else:
        reason = "Key operation did not complete; diagnostic code contains no account data."
    result["reason"] = reason
    return result
