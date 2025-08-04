"""Key generation tests."""

import pytest


@pytest.mark.parametrize("execution_number", range(100))
def test_keypair(execution_number: int) -> None:  # noqa: ARG001
    """Test generation of new keypairs."""
    import findmy

    kp = findmy.KeyPair.new()
    assert len(kp.private_key_bytes) == 28
    assert len(kp.adv_key_bytes) == 28
    assert len(kp.hashed_adv_key_bytes) == 32
