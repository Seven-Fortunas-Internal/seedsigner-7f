"""
    Plugin-level tests for the real EIP-1559 transaction path in
    seedsigner.chains.evm.plugin -- specifically the two gaps a code-review pass
    found and this file locks in the fix for:

    1. sign() must refuse an unrecognized contract call exactly like
       parse_sign_request() does, not just rely on a caller having already called
       parse_sign_request() first.
    2. Native ETH `value` attached to a transaction that also carries a recognized
       ERC-20 call must be shown to the operator, not silently omitted.

    Also covers the access-list warning field. Uses eth_account/rlp (test-only) to
    build real, well-formed reference transactions -- see test_evm_transaction.py.
"""
import rlp
import pytest
from eth_account import Account

from seedsigner.chains import ChainRegistry
from seedsigner.chains.evm.plugin import DERIVATION_PATH_TEMPLATE
from seedsigner.chains.evm.transaction import TX_TYPE_EIP1559

Account.enable_unaudited_hdwallet_features()

TEST_PRIVATE_KEY = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
USDC_OPTIMISM_SEPOLIA = "0x5fd84259d66Cd46123540766Be93DFE6D43130D7"
SOME_ADDRESS = "0x4A3F9c8e1b2D7A6F5e0C9b8A7D6e5f4c3B2a1908"

BASE_TX = {
    "type": 2,
    "chainId": 11155420,
    "nonce": 0,
    "maxPriorityFeePerGas": 1_000_000_000,
    "maxFeePerGas": 2_000_000_000,
    "gas": 60_000,
    "to": USDC_OPTIMISM_SEPOLIA,
    "value": 0,
    "data": b"",
}


def _unsigned_payload(tx: dict) -> bytes:
    acct = Account.from_key(TEST_PRIVATE_KEY)
    signed = Account.sign_transaction(tx, acct.key)
    raw = bytes(signed.raw_transaction)
    fields = rlp.decode(raw[1:], strict=True)
    return bytes([TX_TYPE_EIP1559]) + rlp.encode(fields[:9])


def _erc20_transfer_calldata(to_hex: str, amount: int) -> bytes:
    selector = bytes.fromhex("a9059cbb")
    return selector + b"\x00" * 12 + bytes.fromhex(to_hex[2:]) + amount.to_bytes(32, "big")


def _seed_bytes():
    from embit.bip39 import mnemonic_to_seed
    return mnemonic_to_seed("abandon " * 11 + "about", password="")


UNRECOGNIZED_CALLDATA = bytes.fromhex("deadbeef") + b"\x00" * 64


def test_parse_refuses_unrecognized_contract_call():
    payload = _unsigned_payload({**BASE_TX, "data": UNRECOGNIZED_CALLDATA})
    plugin = ChainRegistry.get("evm")
    with pytest.raises(ValueError, match="unrecognized contract call"):
        plugin.parse_sign_request(payload)


def test_sign_also_refuses_unrecognized_contract_call():
    """The actual bug this locks in: sign() must independently enforce the same
    refusal, not just parse_sign_request() -- a caller reaching sign() directly with
    an unrecognized call must not get back a usable signature."""
    payload = _unsigned_payload({**BASE_TX, "data": UNRECOGNIZED_CALLDATA})
    plugin = ChainRegistry.get("evm")
    path = DERIVATION_PATH_TEMPLATE.format(account=0, index=0)

    with pytest.raises(ValueError, match="unrecognized contract call"):
        plugin.sign(_seed_bytes(), path, payload)


def test_sign_still_works_for_a_recognized_erc20_call():
    """Confirms the new refusal check in sign() doesn't also block legitimate calls."""
    payload = _unsigned_payload({
        **BASE_TX, "data": _erc20_transfer_calldata(SOME_ADDRESS, 1_000_000)})
    plugin = ChainRegistry.get("evm")
    path = DERIVATION_PATH_TEMPLATE.format(account=0, index=0)

    signature = plugin.sign(_seed_bytes(), path, payload)
    assert len(signature.signature_bytes) == 65


def test_native_value_alongside_erc20_call_is_flagged():
    tx = {
        **BASE_TX,
        "value": 1_000_000_000_000_000,  # 0.001 ETH attached alongside a token call
        "data": _erc20_transfer_calldata(SOME_ADDRESS, 5_000_000),
    }
    payload = _unsigned_payload(tx)
    plugin = ChainRegistry.get("evm")

    parsed = plugin.parse_sign_request(payload)
    value_field = next((f for f in parsed.review_fields if f.label == "Value (native ETH)"), None)

    assert value_field is not None
    assert value_field.is_warning is True
    assert value_field.value == "0.001 ETH"


def test_zero_value_erc20_call_has_no_value_field():
    payload = _unsigned_payload({
        **BASE_TX, "value": 0, "data": _erc20_transfer_calldata(SOME_ADDRESS, 1)})
    plugin = ChainRegistry.get("evm")

    parsed = plugin.parse_sign_request(payload)
    assert not any(f.label == "Value (native ETH)" for f in parsed.review_fields)


def test_nonempty_access_list_is_flagged():
    acct = Account.from_key(TEST_PRIVATE_KEY)
    tx = {**BASE_TX, "data": _erc20_transfer_calldata(SOME_ADDRESS, 1),
          "accessList": [{"address": SOME_ADDRESS, "storageKeys": []}]}
    signed = Account.sign_transaction(tx, acct.key)
    raw = bytes(signed.raw_transaction)
    fields = rlp.decode(raw[1:], strict=True)
    payload = bytes([TX_TYPE_EIP1559]) + rlp.encode(fields[:9])

    plugin = ChainRegistry.get("evm")
    parsed = plugin.parse_sign_request(payload)
    access_list_field = next((f for f in parsed.review_fields if f.label == "Access list"), None)

    assert access_list_field is not None
    assert access_list_field.is_warning is True
    assert access_list_field.value == "1 entries"
