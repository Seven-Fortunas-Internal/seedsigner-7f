import pytest

from seedsigner.chains.evm.units import format_units


def test_whole_eth_amount():
    assert format_units(2_000_000_000_000_000_000, 18) == "2"


def test_fractional_eth_amount():
    # 0.05 ETH
    assert format_units(50_000_000_000_000_000, 18) == "0.05"


def test_zero_amount():
    assert format_units(0, 18) == "0"


def test_smallest_unit_amount():
    assert format_units(1, 18) == "0.000000000000000001"


def test_usdc_six_decimals():
    # 1,000.50 USDC (6 decimals)
    assert format_units(1_000_500_000, 6) == "1000.5"


def test_zero_decimals_returns_raw_integer_string():
    assert format_units(42, 0) == "42"


def test_negative_amount_rejected():
    with pytest.raises(ValueError):
        format_units(-1, 18)
