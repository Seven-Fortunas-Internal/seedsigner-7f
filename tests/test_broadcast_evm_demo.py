"""
    Cross-verifies tools/broadcast_evm_demo.py's manual RLP signed-transaction
    assembly against eth_account's own sign_transaction() output, using a throwaway
    test key (never used for anything real) -- not the device's key, which this
    script never sees or needs. Confirms build_signed_tx(scenario, r, s, y_parity)
    produces byte-identical output to what eth_account would produce for the exact
    same (unsigned tx fields, signature) pair, for every broadcastable demo scenario.
"""
import importlib.util
import os

import pytest
from eth_account import Account

TOOLS_DIR = os.path.join(os.path.dirname(__file__), "..", "tools")


def _load_broadcast_module():
    spec = importlib.util.spec_from_file_location(
        "broadcast_evm_demo", os.path.join(TOOLS_DIR, "broadcast_evm_demo.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


broadcast_tool = _load_broadcast_module()

Account.enable_unaudited_hdwallet_features()
TEST_PRIVATE_KEY = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"


def _reference_signed_tx(scenario: str) -> tuple[bytes, tuple[int, int, int]]:
    """Signs the exact fields the given demo scenario decodes to, using eth_account
    with a throwaway key -- the reference implementation."""
    tx_obj = broadcast_tool.UnsignedEip1559Transaction(broadcast_tool.DEMO_SCENARIOS[scenario])
    tx = {
        "type": 2,
        "chainId": tx_obj.chain_id,
        "nonce": tx_obj.nonce,
        "maxPriorityFeePerGas": tx_obj.max_priority_fee_per_gas,
        "maxFeePerGas": tx_obj.max_fee_per_gas,
        "gas": tx_obj.gas_limit,
        "to": tx_obj.to_checksum_address,
        "value": tx_obj.value,
        "data": tx_obj.data,
    }
    acct = Account.from_key(TEST_PRIVATE_KEY)
    signed = Account.sign_transaction(tx, acct.key)
    return bytes(signed.raw_transaction), (signed.r, signed.s, signed.v)


@pytest.mark.parametrize("scenario", broadcast_tool.BROADCASTABLE_SCENARIOS)
def test_build_signed_tx_matches_eth_account_reference_byte_for_byte(scenario):
    reference_raw_tx, (r, s, y_parity) = _reference_signed_tx(scenario)
    ours, chain_id = broadcast_tool.build_signed_tx(scenario, r, s, y_parity)
    assert ours == reference_raw_tx
    assert chain_id == 10


def test_build_signed_tx_rejects_non_broadcastable_scenario():
    with pytest.raises(ValueError, match="still Phase 1"):
        broadcast_tool.build_signed_tx("permit", 1, 1, 0)


def test_build_signed_tx_rejects_unknown_scenario():
    with pytest.raises(ValueError, match="Unknown scenario"):
        broadcast_tool.build_signed_tx("not_a_real_scenario", 1, 1, 0)


def test_parse_signature_roundtrips_with_reference_signature():
    _, (r, s, y_parity) = _reference_signed_tx("transfer")
    signature_hex = r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + y_parity.to_bytes(1, "big").hex()

    parsed = broadcast_tool.parse_signature(signature_hex)
    assert parsed == (r, s, y_parity)


def test_parse_signature_accepts_device_qr_format_with_prefix():
    _, (r, s, y_parity) = _reference_signed_tx("transfer")
    signature_hex = r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + y_parity.to_bytes(1, "big").hex()

    parsed = broadcast_tool.parse_signature(f"EVM-DEMO-SIG:{signature_hex}")
    assert parsed == (r, s, y_parity)


def test_parse_signature_accepts_0x_prefix():
    _, (r, s, y_parity) = _reference_signed_tx("transfer")
    signature_hex = r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + y_parity.to_bytes(1, "big").hex()

    parsed = broadcast_tool.parse_signature(f"0x{signature_hex}")
    assert parsed == (r, s, y_parity)


def test_parse_signature_rejects_wrong_length():
    with pytest.raises(ValueError, match="65-byte"):
        broadcast_tool.parse_signature("abcd")
