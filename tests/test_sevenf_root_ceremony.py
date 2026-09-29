"""
    Tests seedsigner.models.sevenf.root_ceremony -- the derivation-layer
    half of the Root ceremony (7f-signing-support-root-ceremony-key-derivation,
    docs/7f-integration/root-key-ceremony-plan.md).

    Requires firmware/mldsa7f's compiled library (see test_sevenf_mldsa.py's
    own docstring); skips cleanly if it's missing.
"""
import hashlib

import pytest
from embit.bip39 import mnemonic_to_seed

from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf.constants import ChainKind, MASTER_SEED_LEN
from seedsigner.models.sevenf.root_ceremony import (
    SigningNotConfirmedError,
    derive_root_ceremony_keys,
    sign_with_devfund,
    sign_with_root_ca,
)


def _lib_available() -> bool:
    try:
        mldsa._lib_handle()
        return True
    except FileNotFoundError:
        return False


pytestmark = pytest.mark.skipif(
    not _lib_available(),
    reason="firmware/mldsa7f not built -- run `cargo build --release` in firmware/mldsa7f/ first",
)

FIXED_SEED = bytes([0x2A] * MASTER_SEED_LEN)

# A standard BIP-39 test-vector mnemonic (Trezor test vectors, all-"abandon"
# family) -- not a real, funded phrase. Used to confirm this module works
# end-to-end from an actual mnemonic through embit's own mnemonic_to_seed,
# exactly the path SeedSigner's Seed.seed_bytes takes (models/seed.py),
# not just from an arbitrary fixed byte pattern.
TEST_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def test_derive_root_ceremony_keys_matches_rust_kat():
    """ Pinned against the same fixed-seed KAT as test_sevenf_mldsa.py --
        confirms this higher-level function derives the exact same keys as
        calling mldsa.derive_pubkey directly with the documented paths,
        not a subtly different path string. """
    keys = derive_root_ceremony_keys(FIXED_SEED, ChainKind.TESTNET)
    assert keys.chain_kind == ChainKind.TESTNET
    assert hashlib.sha256(keys.root_ca.public_key).hexdigest() == \
        "35dcb73976fb10ad1d9393d742e33bba9ac890c449a26fe90d0a93d786e1396a"
    assert keys.root_ca.address == "t1w65hh4c5ft3anmvc5nd57209vd9pw88un6ekd2hkqavajwc"
    assert hashlib.sha256(keys.devfund.public_key).hexdigest() == \
        "72bf15c60c1ba2f6a7a778910ec974c5eb4d240fe8544ce87bb0691ca467bccc"
    assert keys.devfund.address == "t1wxrtaq8t5cuuvea5gm9uzfagggxpasrpc5m93jkvmaqs7ea"


def test_root_ca_and_devfund_addresses_differ():
    keys = derive_root_ceremony_keys(FIXED_SEED, ChainKind.TESTNET)
    assert keys.root_ca.address != keys.devfund.address
    assert keys.root_ca.public_key != keys.devfund.public_key


def test_keys_differ_across_chain_kinds():
    testnet_keys = derive_root_ceremony_keys(FIXED_SEED, ChainKind.TESTNET)
    mainnet_keys = derive_root_ceremony_keys(FIXED_SEED, ChainKind.MAINNET)
    assert testnet_keys.root_ca.address != mainnet_keys.root_ca.address
    assert testnet_keys.root_ca.public_key != mainnet_keys.root_ca.public_key


def test_addresses_carry_the_expected_network_prefix():
    """ testnet addresses start with 't1'; mainnet with '7f' -- confirmed
        against firmware/mldsa7f/src/address.rs's own PREFIXES table. """
    testnet_keys = derive_root_ceremony_keys(FIXED_SEED, ChainKind.TESTNET)
    mainnet_keys = derive_root_ceremony_keys(FIXED_SEED, ChainKind.MAINNET)
    assert testnet_keys.root_ca.address.startswith("t1")
    assert testnet_keys.devfund.address.startswith("t1")
    assert mainnet_keys.root_ca.address.startswith("7f")
    assert mainnet_keys.devfund.address.startswith("7f")


def test_end_to_end_from_a_real_mnemonic():
    """ Confirms the whole path works from an actual BIP-39 mnemonic
        through embit's mnemonic_to_seed -- the exact function
        SeedSigner's own Seed.seed_bytes uses (models/seed.py) -- not just
        from an arbitrary 64-byte fixture. Doesn't assert a specific KAT
        value (this mnemonic's derived keys weren't independently
        captured from the Rust side), only that the whole chain runs and
        produces well-formed output. """
    seed_bytes = mnemonic_to_seed(TEST_MNEMONIC, password="")
    assert len(seed_bytes) == MASTER_SEED_LEN

    keys = derive_root_ceremony_keys(seed_bytes, ChainKind.TESTNET)
    assert len(keys.root_ca.public_key) == 1952
    assert len(keys.root_ca.address) == 49
    assert keys.root_ca.address.startswith("t1")

    # Deterministic: re-deriving from the same mnemonic gives the same keys.
    keys_again = derive_root_ceremony_keys(seed_bytes, ChainKind.TESTNET)
    assert keys_again.root_ca.public_key == keys.root_ca.public_key
    assert keys_again.root_ca.address == keys.root_ca.address


def test_sign_with_root_ca_produces_a_verifiable_signature_shape():
    """ Shape/consistency check -- actual ML-DSA-65 verification of the
        produced signature is covered by firmware/mldsa7f's own Rust test
        suite (see test_sevenf_mldsa.py's test_signature_verifies_against_derived_pubkey
        docstring for why this Python layer doesn't re-implement a
        verifier). """
    message = b"genesis-config canonical bytes for testnet"
    pk, sig = sign_with_root_ca(FIXED_SEED, ChainKind.TESTNET, message, confirmed=True)

    keys = derive_root_ceremony_keys(FIXED_SEED, ChainKind.TESTNET)
    assert pk == keys.root_ca.public_key, "sign_with_root_ca must use the same key derive_root_ceremony_keys does"
    assert len(sig) == 3309


def test_sign_with_root_ca_refuses_without_confirmation():
    """ The architectural review-before-sign gate an adversarial review
        found missing: sign_with_root_ca must not sign unless the caller
        explicitly passes confirmed=True. """
    message = b"genesis-config canonical bytes for testnet"
    with pytest.raises(SigningNotConfirmedError):
        sign_with_root_ca(FIXED_SEED, ChainKind.TESTNET, message, confirmed=False)


def test_sign_with_root_ca_requires_confirmed_as_keyword():
    """ confirmed has no default and is keyword-only -- there is no way to
        accidentally call this function without explicitly deciding the
        value, and no way to pass it positionally by habit either. """
    message = b"genesis-config canonical bytes for testnet"
    with pytest.raises(TypeError):
        sign_with_root_ca(FIXED_SEED, ChainKind.TESTNET, message, True)  # positional -- must fail
    with pytest.raises(TypeError):
        sign_with_root_ca(FIXED_SEED, ChainKind.TESTNET, message)  # omitted entirely -- must fail


def test_sign_with_devfund_produces_a_verifiable_signature_shape():
    message = b"devfund-config canonical bytes for testnet"
    pk, sig = sign_with_devfund(FIXED_SEED, ChainKind.TESTNET, message, confirmed=True)

    keys = derive_root_ceremony_keys(FIXED_SEED, ChainKind.TESTNET)
    assert pk == keys.devfund.public_key, "sign_with_devfund must use the same key derive_root_ceremony_keys does"
    assert len(sig) == 3309


def test_sign_with_devfund_uses_a_different_key_than_sign_with_root_ca():
    """ The exact risk this function's own docstring names: using the
        wrong derived key would silently produce a signature under the
        wrong identity with no error at signing time. Confirms the two
        signing functions actually derive from different paths, not just
        that each is internally self-consistent. """
    message = b"same message, different intended signer"
    root_pk, _ = sign_with_root_ca(FIXED_SEED, ChainKind.TESTNET, message, confirmed=True)
    devfund_pk, _ = sign_with_devfund(FIXED_SEED, ChainKind.TESTNET, message, confirmed=True)
    assert root_pk != devfund_pk


def test_sign_with_devfund_refuses_without_confirmation():
    message = b"devfund-config canonical bytes for testnet"
    with pytest.raises(SigningNotConfirmedError):
        sign_with_devfund(FIXED_SEED, ChainKind.TESTNET, message, confirmed=False)


def test_sign_with_devfund_requires_confirmed_as_keyword():
    message = b"devfund-config canonical bytes for testnet"
    with pytest.raises(TypeError):
        sign_with_devfund(FIXED_SEED, ChainKind.TESTNET, message, True)  # positional -- must fail
    with pytest.raises(TypeError):
        sign_with_devfund(FIXED_SEED, ChainKind.TESTNET, message)  # omitted entirely -- must fail
