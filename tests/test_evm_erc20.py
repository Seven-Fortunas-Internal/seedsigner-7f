from Cryptodome.Hash import keccak

from seedsigner.chains.evm.erc20 import (
    SELECTOR_APPROVE,
    SELECTOR_TRANSFER,
    UINT256_MAX,
    decode_erc20_call,
)


def _keccak256(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def _encode_call(selector: bytes, address_hex: str, amount: int) -> bytes:
    address_word = b"\x00" * 12 + bytes.fromhex(address_hex[2:])
    amount_word = amount.to_bytes(32, "big")
    return selector + address_word + amount_word


ADDRESS = "0x5fd84259d66Cd46123540766Be93DFE6D43130D7"


def test_selectors_match_keccak_of_function_signature():
    """The two hardcoded selector constants aren't just transcribed from memory --
    confirmed here against the actual keccak256 of the function signatures."""
    assert SELECTOR_TRANSFER == _keccak256(b"transfer(address,uint256)")[:4]
    assert SELECTOR_APPROVE == _keccak256(b"approve(address,uint256)")[:4]


def test_decodes_transfer_call():
    data = _encode_call(SELECTOR_TRANSFER, ADDRESS, 1_500_000)
    call = decode_erc20_call(data)
    assert call is not None
    assert call.function == "transfer"
    assert call.recipient_or_spender == ADDRESS
    assert call.amount == 1_500_000
    assert not call.is_unlimited_approval


def test_decodes_approve_call():
    data = _encode_call(SELECTOR_APPROVE, ADDRESS, 42)
    call = decode_erc20_call(data)
    assert call.function == "approve"
    assert call.amount == 42
    assert not call.is_unlimited_approval


def test_flags_unlimited_approval():
    data = _encode_call(SELECTOR_APPROVE, ADDRESS, UINT256_MAX)
    call = decode_erc20_call(data)
    assert call.is_unlimited_approval


def test_unlimited_transfer_is_not_flagged_as_unlimited_approval():
    """is_unlimited_approval is specific to approve -- a transfer of UINT256_MAX
    tokens (nonsensical but not attacker-controlled-approval-shaped) must not trip
    the same warning path."""
    data = _encode_call(SELECTOR_TRANSFER, ADDRESS, UINT256_MAX)
    call = decode_erc20_call(data)
    assert not call.is_unlimited_approval


def test_returns_none_for_unrecognized_selector():
    data = b"\xde\xad\xbe\xef" + b"\x00" * 64
    assert decode_erc20_call(data) is None


def test_returns_none_for_wrong_length():
    data = _encode_call(SELECTOR_TRANSFER, ADDRESS, 1)[:-1]
    assert decode_erc20_call(data) is None


def test_returns_none_when_address_word_high_bytes_nonzero():
    """A nonzero high 12 bytes doesn't match ABI's zero-padding for a 20-byte value --
    refused rather than silently masked off (could otherwise hide a crafted word)."""
    selector = SELECTOR_TRANSFER
    bad_word = b"\xff" * 12 + bytes.fromhex(ADDRESS[2:])
    data = selector + bad_word + (1).to_bytes(32, "big")
    assert decode_erc20_call(data) is None
