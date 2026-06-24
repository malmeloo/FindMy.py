"""Location report fetcher tests."""

import asyncio
from datetime import datetime

from typing_extensions import override

from findmy import KeyPair
from findmy.accessory import RollingKeyPairSource
from findmy.reports.reports import LocationReport, LocationReportsFetcher


class DummyAccessory(RollingKeyPairSource):
    """Minimal rolling key source for dispatch tests."""

    @override
    def get_min_index(self, dt: datetime) -> int:
        """Return a dummy minimum key index."""
        _ = dt
        return 0

    @override
    def get_max_index(self, dt: datetime) -> int:
        """Return a dummy maximum key index."""
        _ = dt
        return 0

    @override
    def update_alignment(self, dt: datetime, index: int) -> None:
        """Ignore alignment updates."""
        _ = (dt, index)

    @override
    def keys_at(self, ind: int) -> set[KeyPair]:
        """Return no keys."""
        _ = ind
        return set()


class RecordingFetcher(LocationReportsFetcher):
    """Fetcher that records only_latest values passed to accessory fetching."""

    def __init__(self, accessory: RollingKeyPairSource) -> None:
        """Initialize the recording fetcher."""
        super().__init__(account=None)  # type: ignore[arg-type]
        self.accessory = accessory
        self.calls: list[bool] = []

    @override
    async def _fetch_accessory_reports(
        self,
        accessory: RollingKeyPairSource,
        only_latest: bool = False,
    ) -> list[LocationReport]:
        assert accessory is self.accessory
        self.calls.append(only_latest)
        return []


def test_fetch_location_history_fetches_full_rolling_history_by_default() -> None:
    """Rolling-key history should not stop after the latest report."""
    accessory = DummyAccessory()
    fetcher = RecordingFetcher(accessory)

    result = asyncio.run(fetcher.fetch_location_history(accessory))

    assert result == []
    assert fetcher.calls == [False]


def test_fetch_location_history_can_fetch_latest_rolling_report() -> None:
    """Internal latest-location callers can still stop after the latest report."""
    accessory = DummyAccessory()
    fetcher = RecordingFetcher(accessory)

    result = asyncio.run(fetcher.fetch_location_history([accessory], only_latest=True))

    assert result == {accessory: []}
    assert fetcher.calls == [True]
