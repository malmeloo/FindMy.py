from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Sequence

from .keys import KeyPair


class LoginState(Enum):
    LOGGED_OUT = 0
    REQUIRE_2FA = 1
    AUTHENTICATED = 2
    LOGGED_IN = 3

    def __lt__(self, other):
        if isinstance(other, LoginState):
            return self.value < other.value

        return NotImplemented

    def __repr__(self):
        return self.__str__()


class BaseSecondFactorMethod(ABC):
    def __init__(self, account: "BaseAppleAccount"):
        self._account = account

    @property
    def account(self):
        return self._account

    @abstractmethod
    def request(self) -> None:
        raise NotImplementedError()

    @abstractmethod
    def submit(self, code: str) -> LoginState:
        raise NotImplementedError()


class BaseAppleAccount(ABC):
    @property
    @abstractmethod
    def login_state(self):
        return NotImplemented

    @property
    @abstractmethod
    def account_name(self):
        return NotImplemented

    @property
    @abstractmethod
    def first_name(self):
        return NotImplemented

    @property
    @abstractmethod
    def last_name(self):
        return NotImplemented

    @abstractmethod
    def export(self) -> dict:
        return NotImplemented

    @abstractmethod
    def restore(self, data: dict):
        return NotImplemented

    @abstractmethod
    def login(self, username: str, password: str) -> LoginState:
        return NotImplemented

    @abstractmethod
    def get_2fa_methods(self) -> list[BaseSecondFactorMethod]:
        return NotImplemented

    @abstractmethod
    def sms_2fa_request(self, phone_number_id: int):
        return NotImplemented

    @abstractmethod
    def sms_2fa_submit(self, phone_number_id: int, code: str) -> LoginState:
        return NotImplemented

    @abstractmethod
    def fetch_reports(self, keys: Sequence[KeyPair], date_from: datetime, date_to: datetime):
        return NotImplemented

    @abstractmethod
    def fetch_last_reports(
        self,
        keys: Sequence[KeyPair],
        hours: int = 7 * 24,
    ):
        return NotImplemented

    @abstractmethod
    def get_anisette_headers(self, serial: str = "0") -> dict[str, str]:
        return NotImplemented
