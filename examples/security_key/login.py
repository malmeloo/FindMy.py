#!/usr/bin/env python3
"""Private, one-attempt Apple FIDO login. Default use: --preflight (no account access)."""

import argparse
import asyncio
import functools
import getpass
import json
import logging
import os
import resource
import stat
import sys
from pathlib import Path

from apple_fido import ORIGIN, CheckedHttpSession, FidoAppleAccount, FidoError, sign_usb
from fido2.client import ClientError, UserInteraction
from fido2.ctap2.pin import ClientPin
from fido2.hid import CtapHidDevice
from typing_extensions import override

from findmy import LocalAnisetteProvider, LoginState

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"


def emit(**values: object) -> None:
    print(json.dumps(values, ensure_ascii=False), flush=True)


class TerminalInteraction(UserInteraction):
    def __init__(self) -> None:
        self.pin_requested = False

    @override
    def prompt_up(self) -> None:
        print("Touch the security key to approve Apple login.", file=sys.stderr)

    @override
    def request_pin(self, permissions: ClientPin.PERMISSION, rp_id: str | None) -> str:
        if self.pin_requested:
            message = "PIN retry refused to avoid locking the security key."
            raise FidoError(message)
        self.pin_requested = True
        print(
            "PIN entry and touch must finish within 90 seconds of starting the operation.",
            file=sys.stderr,
        )
        return getpass.getpass("Security-key PIN (not Apple password; hidden): ")

    @override
    def request_uv(self, permissions: ClientPin.PERMISSION, rp_id: str | None) -> bool:
        print("Verify your identity on the security key.", file=sys.stderr)
        return True


def devices() -> list[CtapHidDevice]:
    return list(CtapHidDevice.list_devices())


def prepare_private_directory(*, fresh: bool = False) -> Path:
    DATA.mkdir(mode=0o700, exist_ok=True)
    st = DATA.lstat()
    if (
        not stat.S_ISDIR(st.st_mode)
        or st.st_uid != os.getuid()
        or stat.S_IMODE(st.st_mode) != 0o700
    ):
        message = "Data directory must be owned by this user, mode 0700, not a symlink."
        raise FidoError(message)
    if fresh:
        import tempfile

        return Path(tempfile.mkdtemp(prefix="login-", dir=DATA))
    for name in ("session.json", "anisette.bin"):
        if (DATA / name).exists() or (DATA / name).is_symlink():
            message = "Previous attempt data exists; not reading or overwriting it."
            raise FidoError(message)
    return DATA


def save_session(account: FidoAppleAccount, directory: Path | None = None) -> None:
    if account.login_state != LoginState.LOGGED_IN:
        message = "Refusing to save an unconfirmed session."
        raise FidoError(message)
    value = account.to_json()
    value["account"]["password"] = None
    # Only a successfully issued search-party session meets this experiment's goal.
    if (
        not value["login"]["data"]
        .get("mobileme_data", {})
        .get("tokens", {})
        .get("searchPartyToken")
    ):
        message = "Missing FindMy session token; not reporting success."
        raise FidoError(message)
    raw = json.dumps(value).encode()
    directory = DATA if directory is None else directory
    st = directory.lstat()
    if (
        not stat.S_ISDIR(st.st_mode)
        or st.st_uid != os.getuid()
        or stat.S_IMODE(st.st_mode) != 0o700
    ):
        message = "Invalid private session directory."
        raise FidoError(message)
    destination = directory / "session.json"
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        # Private local readback, never printed: exact bytes and password exclusion.
        check = destination.read_bytes()
        if check != raw or json.loads(check)["account"]["password"] is not None:
            message = "Private session readback verification failed."
            raise FidoError(message)
        if stat.S_IMODE(destination.stat().st_mode) != 0o600:
            message = "Incorrect saved session permissions."
            raise FidoError(message)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


async def preflight() -> int:
    found = devices()
    count = len(found)
    for d in found:
        d.close()
    http = CheckedHttpSession()
    try:
        resp = await http.get(ORIGIN + "/auth")
        emit(
            stage="preflight",
            usb_fido_accessible=count,
            apple_tls_verified=True,
            unauthenticated_http_status=resp.status_code,
            account_login_attempted=False,
            location_accessed=False,
            ready_for_private_attempt=count == 1 and resp.status_code == 401,
        )
        return 0 if count == 1 and resp.status_code == 401 else 2
    finally:
        await http.close()


async def login() -> int:
    if not sys.stdin.isatty() or not sys.stdout.isatty() or not sys.stderr.isatty():
        message = "Login requires a private interactive terminal; disable terminal recording."
        raise FidoError(message)
    found = devices()
    try:
        if len(found) != 1:
            message = (
                "Attach exactly one USB FIDO key to this Linux host. SSH does not forward USB."
            )
            raise FidoError(message)
        print("EXPERIMENT: one Apple login using FindMy and a hardware security key.")
        print("Local Anisette may provision an Apple client identity. Password stays in memory.")
        print("No accessory export, locations, account-security changes or automatic retries.")
        print("Each attempt uses data/login-*. Password-free session: session.json (0600).")
        print("Previous attempts are not read or overwritten. No automatic login retry.")
        if input("Consent to this attempt - type YES: ") != "YES":
            message = "Cancelled before login."
            raise FidoError(message)
        attempt = prepare_private_directory(fresh=True)
        account = FidoAppleAccount(LocalAnisetteProvider(libs_path=attempt / "anisette.bin"))
        account.on_progress = lambda event: emit(**event)
        try:
            username = input("Apple ID: ")
            password = getpass.getpass("Apple password (hidden): ")
            emit(stage="grandslam_password_auth")
            state = await account.login(username, password)
            password = None  # SDK keeps it in memory until the second SRP completes.
            if state == LoginState.REQUIRE_2FA:
                emit(stage="security_key_challenge")
                signer = functools.partial(
                    sign_usb, device=found[0], interaction=TerminalInteraction()
                )
                state = await account.authenticate_security_key(signer)
            if state != LoginState.LOGGED_IN:
                message = "Nie uzyskano sesji FindMy."
                raise FidoError(message)
            save_session(account, directory=attempt)
            emit(
                stage="session_saved",
                password_saved=False,
                location_accessed=False,
                file=str(attempt / "session.json"),
                note="Session issued. No location access or accessory export in this invocation.",
            )
        finally:
            account._password = None
            await account.close()
    finally:
        for d in found:
            d.close()
    return 0


async def diagnose_auth() -> int:
    """One human-assisted SRP attempt then GET auth schema; NEVER sign or finish login."""
    import tempfile

    from auth_schema import summarize_auth_page

    if not sys.stdin.isatty() or not sys.stdout.isatty() or not sys.stderr.isatty():
        message = "Diagnostics require a private interactive terminal."
        raise FidoError(message)
    print("DIAGNOSTIC: one password-auth attempt and inspection of the Apple 2FA schema.")
    print("No signature, PIN, location access or session save. Existing data stays unchanged.")
    print("Only allowlisted field names/types and recognized factors are recorded; no secrets.")
    if input("Consent to this diagnostic attempt - type YES: ") != "YES":
        message = "Cancelled before diagnostics."
        raise FidoError(message)
    DATA.mkdir(mode=0o700, exist_ok=True)
    st = DATA.lstat()
    if (
        not stat.S_ISDIR(st.st_mode)
        or st.st_uid != os.getuid()
        or stat.S_IMODE(st.st_mode) != 0o700
    ):
        message = "Diagnostic directory must be user-owned, mode 0700, not a symlink."
        raise FidoError(message)
    attempt = Path(tempfile.mkdtemp(prefix="schema-", dir=DATA))
    account = FidoAppleAccount(LocalAnisetteProvider(libs_path=attempt / "anisette.bin"))
    password = None
    try:
        username = input("Apple ID: ")
        password = getpass.getpass("Apple password (hidden): ")
        emit(stage="diagnostic_grandslam_auth")
        state = await account._gsa_authenticate(username, password)
        password = None
        if state != LoginState.REQUIRE_2FA:
            message = "No second-factor state; diagnostics stopped without completing login."
            raise FidoError(message)
        html = await account._fido_request("GET", "/auth")
        summary = summarize_auth_page(html)
        html = None
        output = attempt / "diagnostic.json"
        raw = json.dumps(summary, ensure_ascii=True, indent=2).encode()
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        if output.read_bytes() != raw or stat.S_IMODE(output.stat().st_mode) != 0o600:
            message = "Diagnostic write verification failed."
            raise FidoError(message)
        emit(
            stage="diagnostic_saved",
            file=str(output),
            raw_values_saved=False,
            key_signature_requested=False,
            account_login_completed=False,
        )
        return 0
    finally:
        password = None
        account._password = None
        await account.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version", action="version", version=(ROOT / "VERSION").read_text().strip()
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--login", action="store_true")
    mode.add_argument("--diagnose-auth", action="store_true")
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        operation = preflight if args.preflight else diagnose_auth if args.diagnose_auth else login
        return asyncio.run(operation())
    except FidoError as e:
        emit(status="blocked", reason=str(e), retry=False)
        return 2
    except (KeyboardInterrupt, EOFError):
        emit(status="cancelled", retry=False)
        return 2
    except ClientError as e:
        from fido_errors import safe_fido_error

        emit(**safe_fido_error(e))
        return 1
    except Exception as e:
        # Third-party exceptions can contain passwords, assertions or server bodies.
        emit(status="failed", error_type=type(e).__name__, details_suppressed=True, retry=False)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
