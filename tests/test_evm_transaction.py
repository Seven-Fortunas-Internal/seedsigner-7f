"""
    Cross-verifies seedsigner.chains.evm.transaction against a real eth_account-signed
    transaction: decode the reference tx's own RLP fields, strip its signature to
    reconstruct the unsigned payload, confirm our decoder reads the same field values,
    and confirm our signing_hash() is exactly what the reference signature was made
    over (by recovering the signer's address from the reference r/s/v against our
    hash). eth_account/eth_keys/rlp are test-only dependencies -- see test_evm_crypto.py.
"""
import rlp
import pytest
from eth_account import Account
from eth_keys import keys as eth_keys

from seedsigner.chains.evm.transaction import (
    MalformedTransactionError,
    TX_TYPE_EIP1559,
    UnsignedEip1559Transaction,
)

Account.enable_unaudited_hdwallet_features()

TEST_PRIVATE_KEY = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"


def _reference_unsigned_payload(tx: dict) -> tuple[bytes, "Account", object]:
    """Builds+signs `tx` with eth_account, then reconstructs the unsigned payload
    bytes from the signed tx's own RLP encoding (strips the trailing r/s/v fields)."""
    acct = Account.from_key(TEST_PRIVATE_KEY)
    signed = Account.sign_transaction(tx, acct.key)
    raw = bytes(signed.raw_transaction)
    assert raw[0] == TX_TYPE_EIP1559
    fields = rlp.decode(raw[1:], strict=True)
    unsigned_payload = bytes([TX_TYPE_EIP1559]) + rlp.encode(fields[:9])
    return unsigned_payload, acct, signed


BASE_TX = {
    "type": 2,
    "chainId": 11155420,
    "nonce": 5,
    "maxPriorityFeePerGas": 1_000_000_000,
    "maxFeePerGas": 2_000_000_000,
    "gas": 21_000,
    "to": "0x5fd84259d66Cd46123540766Be93DFE6D43130D7",
    "value": 0,
    "data": b"",
}


def test_decodes_reference_transaction_fields():
    payload, acct, _ = _reference_unsigned_payload(BASE_TX)
    parsed = UnsignedEip1559Transaction(payload)

    assert parsed.chain_id == 11155420
    assert parsed.nonce == 5
    assert parsed.max_priority_fee_per_gas == 1_000_000_000
    assert parsed.max_fee_per_gas == 2_000_000_000
    assert parsed.gas_limit == 21_000
    assert parsed.to_checksum_address == "0x5fd84259d66Cd46123540766Be93DFE6D43130D7"
    assert parsed.value == 0
    assert parsed.data == b""
    assert parsed.access_list_entry_count == 0


def test_decodes_transaction_with_eth_value():
    tx = {**BASE_TX, "to": "0x4A3F9c8e1b2D7A6F5e0C9b8A7D6e5f4c3B2a1908", "value": 50_000_000_000_000_000}
    payload, _, _ = _reference_unsigned_payload(tx)
    parsed = UnsignedEip1559Transaction(payload)
    assert parsed.value == 50_000_000_000_000_000


def test_signing_hash_matches_what_reference_signature_was_made_over():
    payload, acct, signed = _reference_unsigned_payload(BASE_TX)
    parsed = UnsignedEip1559Transaction(payload)

    signature = eth_keys.Signature(vrs=(signed.v, signed.r, signed.s))
    recovered_address = signature.recover_public_key_from_msg_hash(
        parsed.signing_hash()).to_checksum_address()

    assert recovered_address == acct.address


def test_rejects_wrong_type_byte():
    with pytest.raises(MalformedTransactionError):
        UnsignedEip1559Transaction(b"\x01" + b"\x00")


def test_rejects_empty_payload():
    with pytest.raises(MalformedTransactionError):
        UnsignedEip1559Transaction(b"")


def test_rejects_malformed_rlp():
    with pytest.raises(MalformedTransactionError):
        UnsignedEip1559Transaction(bytes([TX_TYPE_EIP1559]) + b"\xff\xff\xff")


def test_rejects_wrong_field_count():
    # A well-formed RLP list, but only 3 fields instead of the required 9.
    bad_payload = bytes([TX_TYPE_EIP1559]) + rlp.encode([b"\x01", b"\x02", b"\x03"])
    with pytest.raises(MalformedTransactionError):
        UnsignedEip1559Transaction(bad_payload)


def test_rejects_wrong_length_to_address():
    tx = {**BASE_TX}
    payload, _, _ = _reference_unsigned_payload(tx)
    fields = rlp.decode(payload[1:], strict=True)
    fields = list(fields)
    fields[5] = fields[5][:-1]  # truncate the 20-byte `to` field by one byte
    bad_payload = bytes([TX_TYPE_EIP1559]) + rlp.encode(fields)
    with pytest.raises(MalformedTransactionError):
        UnsignedEip1559Transaction(bad_payload)
