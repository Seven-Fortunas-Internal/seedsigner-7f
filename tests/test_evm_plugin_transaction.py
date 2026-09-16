"""
    Plugin-level tests for the real EIP-1559 transaction path in
    seedsigner.chains.evm.plugin -- specifically the gaps code-review passes found
    and this file locks in the fix for:

    1. sign() must refuse an unrecognized contract call exactly like
       parse_sign_request() does, not just rely on a caller having already called
       parse_sign_request() first.
    2. Native ETH `value` attached to a transaction that also carries a recognized
       ERC-20 call must be shown to the operator, not silently omitted.
    3. sign() must refuse a derivation path outside this plugin's own
       m/44'/60'/{account}'/0/{index} namespace -- an ERC-4527 scan-and-sign
       adversarial-review finding: a scanned eth-sign-request's crypto-keypath is
       fully attacker-controlled, and without this, it could name any BIP-32 path
       on the shared seed (e.g. one also used for Bitcoin), turning the free-form
       sign flow into a general-purpose signing oracle rather than one scoped to
       EVM.
    4. is_real_transaction_payload() must reflect the actual dispatch signal (the
       payload's own type-tag byte), not a separately-claimed label -- a
       code-review finding: an eth-sign-request's `data_type` field could claim
       "real transaction" while `sign_data` is actually shaped like the
       still-mocked permit JSON demo, which parse_sign_request()/sign() would
       otherwise silently accept as if it were the gated, real flow.

    Also covers the access-list warning field. Uses eth_account/rlp (test-only) to
    build real, well-formed reference transactions -- see test_evm_transaction.py.
"""
import rlp
import pytest
from eth_account import Account

from seedsigner.chains import ChainRegistry
from seedsigner.chains.evm.plugin import DEMO_SCENARIOS, DERIVATION_PATH_TEMPLATE
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


def test_unrecognized_token_contract_flags_token_field_and_keeps_address_out_of_warning_text():
    """A known-token transfer shows the address inline in a warning sentence used to
    overflow this screen (a real bug caught by screenshot rendering) -- fixed by
    giving the token contract its own field, flagged, with a short warning that
    doesn't repeat the address."""
    unknown_contract = "0x7F1A2e3d4C5B6a7988776655443322112233eEDC"
    payload = _unsigned_payload({
        **BASE_TX, "to": unknown_contract,
        "data": _erc20_transfer_calldata(SOME_ADDRESS, 1_000_000)})
    plugin = ChainRegistry.get("evm")

    parsed = plugin.parse_sign_request(payload)
    by_label = {f.label: f for f in parsed.review_fields}

    assert by_label["Token"].is_warning is True
    assert unknown_contract in by_label["Token"].value
    # The address must not also be repeated inside another field's warning text.
    assert unknown_contract not in by_label["Amount"].warning_detail


def test_known_token_contract_does_not_flag_token_field():
    payload = _unsigned_payload({
        **BASE_TX, "data": _erc20_transfer_calldata(SOME_ADDRESS, 1_000_000)})
    plugin = ChainRegistry.get("evm")

    parsed = plugin.parse_sign_request(payload)
    token_field = next(f for f in parsed.review_fields if f.label == "Token")
    assert token_field.is_warning is False
    assert token_field.value == "USDC"


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


def test_sign_refuses_a_non_evm_derivation_path():
    """The critical bug this locks in: a scanned eth-sign-request's derivation path
    is fully attacker-controlled -- sign() must refuse a path outside
    m/44'/60'/{account}'/0/{index} rather than derive and sign with whatever key
    the request names, e.g. a path this same seed also uses for Bitcoin."""
    payload = _unsigned_payload({**BASE_TX, "data": _erc20_transfer_calldata(SOME_ADDRESS, 1_000_000)})
    plugin = ChainRegistry.get("evm")

    with pytest.raises(ValueError, match="not a recognized Ethereum account path"):
        plugin.sign(_seed_bytes(), "m/84'/0'/0'/0/0", payload)  # a Bitcoin native-segwit path


@pytest.mark.parametrize("bad_path", [
    "m/44'/0'/0'/0/0",    # wrong coin_type (Bitcoin's, not Ethereum's)
    "m/44'/60'/0'/1/0",   # internal/change chain, not external
    "m/44'/60'/0/0/0",    # account not hardened
    "m/44'/60'/0'/0/0'",  # index hardened (should never be)
    f"m/44'/60'/0'/0/{2**31}",  # index at/above the non-hardened bound
    "m/44'/60'/0'/0",     # missing index component
    "not/a/path",
])
def test_validate_derivation_path_rejects_every_non_evm_shape(bad_path):
    plugin = ChainRegistry.get("evm")
    with pytest.raises(ValueError):
        plugin.validate_derivation_path(bad_path)


def test_validate_derivation_path_accepts_the_real_template_for_any_account_or_index():
    plugin = ChainRegistry.get("evm")
    plugin.validate_derivation_path(DERIVATION_PATH_TEMPLATE.format(account=0, index=0))
    plugin.validate_derivation_path(DERIVATION_PATH_TEMPLATE.format(account=7, index=123))
    plugin.validate_derivation_path(DERIVATION_PATH_TEMPLATE.format(account=0, index=2**31 - 1))


def test_is_real_transaction_payload_rejects_the_permit_demo_json_shape():
    """The HIGH bug this locks in: an eth-sign-request's `data_type` field claiming
    "real transaction" must not be trusted on its own -- a scanned request could set
    that field while sign_data is actually shaped like the still-mocked permit JSON
    demo below, which parse_sign_request()/sign() would otherwise silently accept
    (fully attacker-authored review content, then a signature that's just
    os.urandom(65), not tied to the key at all)."""
    plugin = ChainRegistry.get("evm")
    fake_permit_payload = DEMO_SCENARIOS["permit"]  # real internal demo shape, attacker could reproduce it

    assert plugin.is_real_transaction_payload(fake_permit_payload) is False


def test_is_real_transaction_payload_accepts_a_real_eip1559_payload():
    plugin = ChainRegistry.get("evm")
    payload = _unsigned_payload({**BASE_TX, "data": _erc20_transfer_calldata(SOME_ADDRESS, 1)})

    assert plugin.is_real_transaction_payload(payload) is True
