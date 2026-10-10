"""Tests for accessory alignment updates from location reports."""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import pytest
from typing_extensions import override

from findmy import FindMyAccessory, KeyPair
from findmy.reports.reports import LocationReport, LocationReportsFetcher, _key_index_bounds

if TYPE_CHECKING:
    from collections.abc import Iterator

INTERVAL = timedelta(minutes=15)
# LocationReport timestamps count seconds from 2001-01-01.
APPLE_EPOCH_OFFSET = 60 * 60 * 24 * 11323


def _accessory(index: int, at: datetime) -> FindMyAccessory:
    return FindMyAccessory(
        master_key=KeyPair.new().private_key_bytes,
        skn=os.urandom(32),
        sks=os.urandom(32),
        paired_at=at - index * INTERVAL,
        alignment_date=at,
        alignment_index=index,
    )


class _FakeReport(LocationReport):
    """Report for a key at a given time, without an encrypted location."""

    def __init__(self, key: KeyPair, timestamp: datetime) -> None:
        payload = (int(timestamp.timestamp()) - APPLE_EPOCH_OFFSET).to_bytes(4, "big")
        super().__init__(payload, key.hashed_adv_key_bytes)

    @override
    def decrypt(self, key: KeyPair) -> None:
        self._decrypted_data = (key, bytes(10))


class _FakeAccount:
    """Account that returns a report for every requested key in `reports`."""

    def __init__(self, reports: dict[str, LocationReport]) -> None:
        self._reports = reports

    async def fetch_raw_reports(
        self,
        devices: list[tuple[list[str], list[str]]],
    ) -> list[LocationReport]:
        return [
            self._reports[key]
            for primary, secondary in devices
            for key in (*primary, *secondary)
            if key in self._reports
        ]


def _patch_clock(monkeypatch: pytest.MonkeyPatch, clock: list[datetime]) -> None:
    """Make `datetime.now()` in the fetcher return `clock[0]`."""

    class _Clock(datetime):
        @classmethod
        @override
        def now(cls, tz: timezone | None = None) -> datetime:  # pyright: ignore[reportIncompatibleMethodOverride]
            return clock[0] if tz is None else clock[0].astimezone(tz)

    monkeypatch.setattr("findmy.reports.reports.datetime", _Clock)


def _fetch_secondary_reports(
    monkeypatch: pytest.MonkeyPatch,
    acc: FindMyAccessory,
    start: datetime,
    first_index: int,
) -> Iterator[tuple[datetime, int]]:
    """
    Fetch every 15 minutes, each time finding a report for the accessory's secondary key.

    The accessory rolls its primary index every 15 minutes and stays on one secondary key, which is
    shared by indices up to two days ahead of the primary one. Reports arrive two hours late.
    Yields the time of each fetch and the primary index the accessory uses at that time.
    """
    secondary_key = acc._secondary_gen[first_index // 96 + 2]  # noqa: SLF001
    clock = [start]
    _patch_clock(monkeypatch, clock)

    for fetch in range(1, 11):
        clock[0] = start + fetch * INTERVAL

        report = _FakeReport(secondary_key, clock[0] - timedelta(hours=2))
        account = _FakeAccount({secondary_key.hashed_adv_key_b64: report})
        fetcher = LocationReportsFetcher(account)  # pyright: ignore[reportArgumentType]

        reports = asyncio.run(fetcher._fetch_accessory_reports(acc, only_latest=True))  # noqa: SLF001
        assert reports == [report]

        yield clock[0], first_index + fetch


@pytest.mark.parametrize("offset", [0, 1, 2])
def test_secondary_key_index_bounds(offset: int) -> None:
    """A secondary key spans every primary index that may use it, not only the generated ones."""
    acc = _accessory(index=10_000, at=datetime.now(tz=timezone.utc))
    secondary = 10_000 // 96 + 2
    key = acc._secondary_gen[secondary]  # noqa: SLF001

    # only part of the range is known, e.g. because keys were generated in a batch
    known = {(secondary - 1) * 96 + offset}
    bounds = ((secondary - 2) * 96, secondary * 96 - 1)
    assert _key_index_bounds(acc, key, known, {}) == bounds


def test_secondary_key_index_bounds_are_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    """The range of a secondary key is searched once per fetch, not once per report."""
    acc = _accessory(index=10_000, at=datetime.now(tz=timezone.utc))
    key = acc._secondary_gen[10_000 // 96 + 2]  # noqa: SLF001
    cache: dict[KeyPair, tuple[int, int]] = {}
    bounds = _key_index_bounds(acc, key, {10_000}, cache)

    def _no_keys(_ind: int) -> set[KeyPair]:
        pytest.fail("keys_at called for cached bounds")

    monkeypatch.setattr(acc, "keys_at", _no_keys)
    assert _key_index_bounds(acc, key, {10_001}, cache) == bounds


def test_primary_key_index_bounds() -> None:
    """A primary key belongs to a single index."""
    acc = _accessory(index=10_000, at=datetime.now(tz=timezone.utc))
    key = acc._primary_gen[10_005]  # noqa: SLF001

    assert _key_index_bounds(acc, key, {10_005}, {}) == (10_005, 10_005)


def test_secondary_reports_do_not_move_alignment_ahead(monkeypatch: pytest.MonkeyPatch) -> None:
    """Secondary key reports do not move a fresh alignment ahead of the accessory."""
    start = datetime(2026, 10, 3, 9, 0, tzinfo=timezone.utc)
    first_index = 10_000 * 96 + 20  # early in a secondary key period
    acc = _accessory(index=first_index, at=start)

    for clock, current in _fetch_secondary_reports(monkeypatch, acc, start, first_index):
        assert acc.get_min_index(clock) <= current <= acc.get_max_index(clock)
        # local matching only has to look a short way around the accessory's alignment
        assert acc.get_max_index(clock) - current <= 2 * 96


def test_secondary_reports_align_stale_accessory(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Secondary key reports bring a week-old alignment close to the accessory, but not past it.

    A report proves the accessory was within the key's range at the time of the report, so the
    alignment may move up to the lower end of that range.
    """
    start = datetime(2026, 10, 3, 9, 0, tzinfo=timezone.utc)
    first_index = 10_000 * 96 + 20
    acc = _accessory(index=first_index - 7 * 96, at=start - timedelta(days=7))

    for clock, current in _fetch_secondary_reports(monkeypatch, acc, start, first_index):
        assert current - 2 * 96 <= acc.get_min_index(clock) <= current
        assert current <= acc.get_max_index(clock) <= current + 2 * 96
