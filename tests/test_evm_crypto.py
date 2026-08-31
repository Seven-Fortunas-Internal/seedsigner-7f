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

from seedsigner.chains.evm.crypto import (
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
