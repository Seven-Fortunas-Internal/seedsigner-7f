"""
    Cross-verifies seedsigner.chains.evm.crypto against eth_account/eth_keys -- the
    reference implementations web3.py itself uses. This is the automated equivalent
    of docs/multi-chain/evm-test-plan.md's Stage 1 manual cross-check (an independent
    tool re-deriving the same address from the same mnemonic): here it runs every test
    pass instead of once by hand, and covers signing too, which a manual address-only
    check can't.

    eth_account / eth_keys are dev/test-only dependencies (tests/requirements.txt) --
    never shipped on-device. The device's own signing path stays on embit's existing
    secp256k1 binding; nothing here changes what actually runs at signing time.
"""
import pytest
from embit.bip39 import mnemonic_to_seed
from eth_account import Account
from eth_keys import keys as eth_keys
from eth_utils import to_checksum_address as reference_to_checksum_address
from hypothesis import given, settings, strategies as st

from seedsigner.chains.evm.crypto import (
    address_bytes_to_checksum,
    derive_private_key,
    keccak256,
    private_key_to_checksum_address,
    sign_hash_recoverable,
)

Account.enable_unaudited_hdwallet_features()

# Well-known Hardhat/Anvil default test mnemonic -- used here only as a fixed,
# reproducible input, not because it has any real-world value.
TEST_MNEMONIC = "test test test test test test test test test test test junk"


def test_keccak256_matches_known_vector():
    # keccak256("") -- a standard published test vector (distinct from SHA3-256's
    # empty-input digest, which is the easiest way to catch an accidental SHA3 swap).
    # Cross-checked against eth_utils.keccak(b"") to confirm the literal below.
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"


def test_derive_private_key_matches_eth_account():
    seed = mnemonic_to_seed(TEST_MNEMONIC, password="")
    path = "m/44'/60'/0'/0/0"

    ours = derive_private_key(seed, path)
    reference = Account.from_mnemonic(TEST_MNEMONIC, account_path=path)

    assert ours == reference.key


def test_derive_private_key_honors_passphrase():
    """Unlike the (paused) 7F work, EVM honors a BIP-39 passphrase -- confirms it
    changes the derived key, and still matches a reference derivation with the same
    passphrase (i.e. it's honored the *standard* way, not a bespoke variant)."""
    seed_no_pass = mnemonic_to_seed(TEST_MNEMONIC, password="")
    seed_with_pass = mnemonic_to_seed(TEST_MNEMONIC, password="my-test-passphrase")
    path = "m/44'/60'/0'/0/0"

    key_no_pass = derive_private_key(seed_no_pass, path)
    key_with_pass = derive_private_key(seed_with_pass, path)
    assert key_no_pass != key_with_pass

    reference = Account.from_mnemonic(
        TEST_MNEMONIC, passphrase="my-test-passphrase", account_path=path)
    assert key_with_pass == reference.key


def test_derive_private_key_different_indices_differ():
    seed = mnemonic_to_seed(TEST_MNEMONIC, password="")
    key0 = derive_private_key(seed, "m/44'/60'/0'/0/0")
    key1 = derive_private_key(seed, "m/44'/60'/0'/0/1")
    account1 = derive_private_key(seed, "m/44'/60'/1'/0/0")
    assert len({key0, key1, account1}) == 3


def test_checksum_address_matches_eth_account():
    seed = mnemonic_to_seed(TEST_MNEMONIC, password="")
    path = "m/44'/60'/0'/0/0"
    private_key = derive_private_key(seed, path)

    address = private_key_to_checksum_address(private_key)
    reference = Account.from_mnemonic(TEST_MNEMONIC, account_path=path)

    assert address == reference.address
    # EIP-55 mixed-case, not all-lowercase or all-uppercase -- confirms the checksum
    # casing actually ran rather than accidentally passing on an all-same-case digest.
    assert address != address.lower()
    assert address != address.upper()


def test_sign_hash_recoverable_matches_eth_keys_and_recovers_correct_address():
    seed = mnemonic_to_seed(TEST_MNEMONIC, password="")
    path = "m/44'/60'/0'/0/0"
    private_key = derive_private_key(seed, path)
    address = private_key_to_checksum_address(private_key)

    msg_hash = keccak256(b"a 32-byte message hash stand-in for a real tx hash")

    r, s, y_parity = sign_hash_recoverable(private_key, msg_hash)

    signature = eth_keys.Signature(vrs=(y_parity, r, s))
    recovered_address = signature.recover_public_key_from_msg_hash(msg_hash).to_checksum_address()

    assert recovered_address == address

    reference_key = eth_keys.PrivateKey(private_key)
    assert reference_key.public_key.verify_msg_hash(msg_hash, signature)


def test_sign_hash_recoverable_rejects_wrong_length_hash():
    with pytest.raises(ValueError):
        sign_hash_recoverable(b"\x01" * 32, b"too short")


# --- Property-based tests (Hypothesis): address_bytes_to_checksum (EIP-55) -----
#
# The fixed test above (test_checksum_address_matches_eth_account) only exercises
# whatever address a single fixed mnemonic/path derives. EIP-55 casing is a pure
# function of the 20 raw address bytes, so the real input space here is "any 20
# bytes" -- including this codebase's own second call site (recovering a checksum
# address from raw transaction/calldata bytes, chains/evm/transaction.py and
# chains/evm/erc20.py), which is attacker-controlled, not derived from a key at
# all. Properties below cover that whole space, not just key-derived addresses.

@given(address_bytes=st.binary(min_size=20, max_size=20))
@settings(max_examples=300)
def test_property_checksum_matches_eth_utils_reference(address_bytes):
    """Oracle property: byte-for-byte identical to eth_utils' own EIP-55
    implementation (what eth_account/web3.py use) for arbitrary 20-byte input, not
    just addresses this codebase happens to derive from a key."""
    assert address_bytes_to_checksum(address_bytes) == reference_to_checksum_address(address_bytes)


@given(address_bytes=st.binary(min_size=20, max_size=20))
@settings(max_examples=300)
def test_property_checksum_is_case_insensitively_the_same_address(address_bytes):
    """The checksum casing must never change which address it denotes: lower-casing
    the result must always reproduce the plain lowercase hex encoding of the same
    bytes."""
    checksummed = address_bytes_to_checksum(address_bytes)
    assert checksummed.lower() == "0x" + address_bytes.hex()
    assert len(checksummed) == 42
    assert checksummed.startswith("0x")


@given(address_bytes=st.binary(min_size=20, max_size=20))
@settings(max_examples=300)
def test_property_checksum_is_idempotent_on_reparsed_bytes(address_bytes):
    """Idempotence: re-deriving the checksum from the exact same bytes (as a caller
    would after round-tripping through hex) always reproduces the identical
    string -- the casing decision doesn't depend on anything but the 20 bytes."""
    first = address_bytes_to_checksum(address_bytes)
    reparsed_bytes = bytes.fromhex(first[2:].lower())
    assert address_bytes_to_checksum(reparsed_bytes) == first


@given(address_bytes=st.binary(max_size=64).filter(lambda b: len(b) != 20))
@settings(max_examples=100)
def test_property_checksum_rejects_any_non_20_byte_input(address_bytes):
    """Boundary property: every length other than exactly 20 bytes must be refused
    outright, not silently truncated/padded -- callers rely on this to catch a
    malformed upstream address before it's ever displayed or signed against."""
    with pytest.raises(ValueError):
        address_bytes_to_checksum(address_bytes)


"""
    Zeroize-audit / constant-time-analysis regressions (see trailofbits:zeroize-audit
    and trailofbits:constant-time-analysis skill reports). Python `bytes` can't be
    zeroized in place, so what's testable is narrower: an error path involving key
    material must never embed the actual secret bytes in its exception message
    (that message is logged and, if ever uncaught, shown on the device's crash
    screen -- see Controller.handle_exception).
"""

# A private key value that's easy to recognize in a failure message if it ever
# leaked -- distinct from all-zeros/all-ones edge cases secp256k1 itself rejects.
_MARKER_KEY_32 = bytes.fromhex("ab" * 32)


def test_sign_hash_recoverable_wrong_length_key_does_not_leak_it_in_error():
    """Length checks happen before any use of the key material; the resulting
    error must be a static, key-independent message."""
    too_short_key = _MARKER_KEY_32[:16]

    with pytest.raises(ValueError) as exc_info:
        sign_hash_recoverable(too_short_key, b"\x00" * 32)

    assert too_short_key.hex() not in str(exc_info.value)
    assert "ab" * 16 not in str(exc_info.value)


def test_sign_hash_recoverable_wrong_length_hash_does_not_leak_key_in_error():
    """The msg_hash length check in sign_hash_recoverable() itself fires first --
    confirms the private key is never touched (let alone echoed) on this path."""
    with pytest.raises(ValueError) as exc_info:
        sign_hash_recoverable(_MARKER_KEY_32, b"\x00" * 16)

    assert "msg_hash must be 32 bytes" == str(exc_info.value)
    assert _MARKER_KEY_32.hex() not in str(exc_info.value)


def test_private_key_to_checksum_address_invalid_key_does_not_leak_it_in_error():
    """embit's PrivateKey() rejects a wrong-length secret with a static message --
    confirms it never echoes the actual (marker) bytes it was given."""
    too_long_key = _MARKER_KEY_32 + b"\x00"

    with pytest.raises(Exception) as exc_info:
        private_key_to_checksum_address(too_long_key)

    assert too_long_key.hex() not in str(exc_info.value)
    assert "ab" * 16 not in str(exc_info.value)
