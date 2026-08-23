"""Tests for rolling-key accessory current-key/current-MAC helpers."""

import re
import secrets
from datetime import datetime, timedelta, timezone

MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")


def test_fixed_rolling_current_keys() -> None:
    """current_keys()/current_mac_addresses() on a fixed-key accessory return all its keys."""
    import findmy

    keys = [findmy.KeyPair.new() for _ in range(3)]
    accessory = findmy.FixedRollingKeyPairAccessory(
        private_keys=[key.private_key_bytes for key in keys],
        name="test",
        identifier=None,
    )

    current = accessory.current_keys()
    assert {key.adv_key_bytes for key in current} == {key.adv_key_bytes for key in keys}

    macs = accessory.current_mac_addresses()
    assert set(macs) == {key.mac_address for key in keys}
    for mac in macs:
        assert MAC_RE.match(mac)


def test_findmy_accessory_current_keys_matches_keys_at_alignment() -> None:
    """At the alignment date itself, current_keys() must match keys_at(alignment_index)."""
    import findmy

    paired_at = datetime.now(timezone.utc)
    accessory = findmy.FindMyAccessory(
        master_key=secrets.token_bytes(28),
        skn=secrets.token_bytes(32),
        sks=secrets.token_bytes(32),
        paired_at=paired_at,
    )

    expected = accessory.keys_at(0)
    current = accessory.current_keys(paired_at)
    assert {key.adv_key_bytes for key in current} == {key.adv_key_bytes for key in expected}

    expected_macs = {key.mac_address for key in expected}
    assert set(accessory.current_mac_addresses(paired_at)) == expected_macs
    for mac in expected_macs:
        assert MAC_RE.match(mac)


def test_findmy_accessory_current_keys_defaults_to_now() -> None:
    """Calling current_keys()/current_mac_addresses() without an explicit `now` must not raise."""
    import findmy

    accessory = findmy.FindMyAccessory(
        master_key=secrets.token_bytes(28),
        skn=secrets.token_bytes(32),
        sks=secrets.token_bytes(32),
        paired_at=datetime.now(timezone.utc),
    )

    assert len(accessory.current_keys()) > 0
    assert len(accessory.current_mac_addresses()) > 0


def test_a_margin_reaches_indices_below_the_alignment_point() -> None:
    """
    The backwards half, which is the half the margin exists for.

    An accessory whose true index has ended up *below* where alignment believes it is
    falls outside the range entirely and is never matched. That can only happen once
    alignment is above zero, so it can only be tested there: with the default
    `alignment_index == 0` every negative index yields nothing and the widening comes
    entirely from the forward side.
    """
    import findmy

    now = datetime.now(timezone.utc)
    accessory = findmy.FindMyAccessory(
        master_key=secrets.token_bytes(28),
        skn=secrets.token_bytes(32),
        sks=secrets.token_bytes(32),
        paired_at=now - timedelta(days=30),
    )
    accessory.update_alignment(now, 2880)

    behind = {k.adv_key_bytes for k in accessory.keys_at(2879)}
    with_margin = {k.adv_key_bytes for k in accessory.current_keys(now, margin=timedelta(hours=12))}
    forward_only = {
        k.adv_key_bytes for _, k in accessory.keys_between(now, now + timedelta(hours=12))
    }

    assert behind, "the fixture should have keys at the index just behind alignment"
    assert behind <= with_margin
    assert not (behind <= forward_only), (
        "if this passes, the forward half alone covers it and the test proves nothing"
    )


def test_no_margin_behaves_exactly_as_before() -> None:
    """The parameter is additive: omitting it must not change what existing callers get."""
    import findmy

    paired_at = datetime.now(timezone.utc)
    accessory = findmy.FindMyAccessory(
        master_key=secrets.token_bytes(28),
        skn=secrets.token_bytes(32),
        sks=secrets.token_bytes(32),
        paired_at=paired_at,
    )

    assert {k.adv_key_bytes for k in accessory.current_keys(paired_at)} == {
        k.adv_key_bytes for k in accessory.current_keys(paired_at, margin=timedelta(0))
    }


def test_the_margin_reaches_mac_addresses_too() -> None:
    import findmy

    accessory = findmy.FindMyAccessory(
        master_key=secrets.token_bytes(28),
        skn=secrets.token_bytes(32),
        sks=secrets.token_bytes(32),
        paired_at=datetime.now(timezone.utc),
    )

    assert len(accessory.current_mac_addresses(margin=timedelta(hours=12))) > len(
        accessory.current_mac_addresses()
    )


def test_the_index_comes_back_with_each_candidate() -> None:
    """
    The index is what makes the cheap path reachable.

    A scanner that matches an advertisement has to be able to report *which* index it
    matched, or it cannot call update_alignment and every later call pays for the wide
    range again.
    """
    import findmy

    now = datetime.now(timezone.utc)
    accessory = findmy.FindMyAccessory(
        master_key=secrets.token_bytes(28),
        skn=secrets.token_bytes(32),
        sks=secrets.token_bytes(32),
        paired_at=now - timedelta(days=30),
    )
    accessory.update_alignment(now, 2880)

    candidates = accessory.current_mac_addresses(now, margin=timedelta(hours=12))
    known_mac = next(iter(accessory.keys_at(2879))).mac_address

    # The index reported is the first one in the searched range at which that key is
    # valid, not necessarily the only one: a secondary key covers 96 primary indices,
    # so for those it is a lower bound. What has to hold is that the key really does
    # occur there, which is what makes it safe to hand to update_alignment.
    reported = candidates[known_mac]
    assert known_mac in {k.mac_address for k in accessory.keys_at(reported)}


def test_feeding_a_matched_index_back_collapses_the_next_call() -> None:
    """The pattern the docstring recommends, pinned end to end."""
    import findmy

    now = datetime.now(timezone.utc)
    accessory = findmy.FindMyAccessory(
        master_key=secrets.token_bytes(28),
        skn=secrets.token_bytes(32),
        sks=secrets.token_bytes(32),
        paired_at=now - timedelta(days=30),
    )
    accessory.update_alignment(now - timedelta(days=1), 2784)

    wide = accessory.current_mac_addresses(now, margin=timedelta(hours=12))
    seen_mac, seen_index = next(iter(wide.items()))

    accessory.update_alignment(now, seen_index)
    narrow = accessory.current_mac_addresses(now)

    assert len(narrow) < len(wide)
    assert seen_mac in wide
