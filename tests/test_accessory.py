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
    assert macs == {key.mac_address for key in keys}
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
    assert accessory.current_mac_addresses(paired_at) == expected_macs
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


def test_a_margin_widens_the_candidate_set_both_ways() -> None:
    """
    The margin is what makes an accessory findable when alignment has drifted ahead of it.

    Without one the range starts at the alignment index, so a true index below that is
    excluded and the accessory is never matched - observed on real hardware, advertising a
    metre away and absent from its own candidate set.
    """
    import findmy

    paired_at = datetime.now(timezone.utc)
    accessory = findmy.FindMyAccessory(
        master_key=secrets.token_bytes(28),
        skn=secrets.token_bytes(32),
        sks=secrets.token_bytes(32),
        paired_at=paired_at,
    )

    without = accessory.current_keys(paired_at)
    with_margin = accessory.current_keys(paired_at, margin=timedelta(hours=12))

    assert len(with_margin) > len(without)
    assert {k.adv_key_bytes for k in without} <= {k.adv_key_bytes for k in with_margin}


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
