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
        confirms this higher-level function derives the exact same key as
        calling mldsa.derive_pubkey directly with the documented path, not
        a subtly different path string. RE-CAPTURED 2026-10-03 (R27): the
        two-level purpose/role-path grammar collapsed into one path, which
        moves this pinned key, and `devfund` is now the SAME key as
        `root_ca` (see root_ceremony.py's own BUG FIX note) rather than a
        separately-pinned one. """
    keys = derive_root_ceremony_keys(FIXED_SEED, ChainKind.TESTNET)
    assert keys.chain_kind == ChainKind.TESTNET
    assert hashlib.sha256(keys.root_ca.public_key).hexdigest() == \
        "920d8addc431773ed0f40e441593b609353b3f2ed18181fb21213743059a19f0"
    assert keys.root_ca.address == "t136pq48mt9f3ym9dn3k3nh6f8dkpw6uje40rjx9djfnqg28v"
    assert keys.devfund.public_key == keys.root_ca.public_key
    assert keys.devfund.address == keys.root_ca.address


def test_root_ca_matches_7fchains_real_canonical_vector():
    """ Ground-truth cross-verification, not internal self-consistency: 7fchain's
        crates/sf-keytree/tests/path_vectors.rs (repinned 2026-10-01 for the
        single-grammar change, R27) checks the device's FFI against real
        sf-keytree output, using the canonical all-zero 24-word BIP-39 vector
        ("abandon ... art") so the comparison is reproducible by anyone
        without sharing a real phrase.

        This is the single most direct proof this device derives the same
        Root key sf-root itself would for the same seed -- the exact
        correctness question this whole file exists to answer, now checked
        against the real federation software's own pinned output rather than
        only against another run of our own port. """
    canonical_phrase = (
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon art"
    )
    seed_bytes = mnemonic_to_seed(canonical_phrase, password="")

    keys = derive_root_ceremony_keys(seed_bytes, ChainKind.TESTNET)

    # First 64 hex characters, matching path_vectors.rs's own pinning
    # convention ("a prefix that long is a collision nobody is going to
    # stumble into").
    pk_hex = keys.root_ca.public_key.hex()[:64]
    assert pk_hex == "cf7586cee76af9b1447b0fb77432c06e71fcf9a43d3a232bf9a496e94ac807a6", (
        "Root public key no longer matches 7fchain's real pinned vector "
        "(sf-keytree/tests/path_vectors.rs::ROOT_TESTNET) for the canonical "
        "all-zero BIP-39 phrase at root/testnet/0/ml-dsa/v1 -- this device "
        "would sign under a different key than sf-root expects."
    )


def test_root_ca_ski_matches_real_sf_wallet_gov_sign_root_cert():
    """ End-to-end against the real federation binary, not our own port:
        `sf-wallet-gov sign-root-cert --index 0` (7fchain 416f576, run
        2026-10-07 in a sandboxed HOME from a testnet directory) on the
        canonical "abandon ... art" phrase, empty BIP-39 passphrase, printed
        `subject key id: 591c511984a2d73c6bee1f4dc149d48f7f97fc55` and wrote
        `591c...fc55.vk` byte-identical to this device's derived key. This is
        the id the device must show and the stem the coordinator pairs
        signatures by. """
    from seedsigner.models.sevenf.review_format import ski

    canonical_phrase = " ".join(["abandon"] * 23 + ["art"])
    keys = derive_root_ceremony_keys(mnemonic_to_seed(canonical_phrase, password=""), ChainKind.TESTNET)

    assert ski(keys.root_ca.public_key.hex()) == "591c511984a2d73c6bee1f4dc149d48f7f97fc55"


def test_devfund_key_matches_real_sf_wallet_gov_derive_vk():
    """ End-to-end against the real binary: `sf-wallet-gov derive-vk --role
        devfund --index 0` (7fchain 416f576, sandboxed HOME, testnet dir) on
        the canonical "abandon ... art" phrase printed `subject key id:
        af11f8afb793df512bf35110890e15dc8b3a2720` for path
        devfund/testnet/0/ml-dsa/v1. The runbook (ceremony-federation-
        member.md Step 3) says a dev-fund id equal to the Root id means
        "something is wrong -- stop and call". """
    from seedsigner.models.sevenf.review_format import ski
    from seedsigner.models.sevenf.root_ceremony import derive_devfund_key

    seed = mnemonic_to_seed(" ".join(["abandon"] * 23 + ["art"]), password="")
    devfund = derive_devfund_key(seed, ChainKind.TESTNET)
    root = derive_root_ceremony_keys(seed, ChainKind.TESTNET).root_ca

    assert ski(devfund.public_key.hex()) == "af11f8afb793df512bf35110890e15dc8b3a2720"
    assert devfund.public_key != root.public_key


def test_root_ca_and_devfund_are_the_same_key():
    """ BUG FIX, 2026-10-03 (R27 re-port): this used to assert root_ca and
        devfund differ -- that was the bug. Direct reading of 7fchain's
        real sf-root.rs confirmed cmd_sign_genesis and cmd_sign_devfund
        both call the byte-identical root_key_from_file(..., index 0):
        genesis-config and devfund-config are signed by the SAME Root
        key. See root_ceremony.py's own BUG FIX note. """
    keys = derive_root_ceremony_keys(FIXED_SEED, ChainKind.TESTNET)
    assert keys.root_ca.address == keys.devfund.address
    assert keys.root_ca.public_key == keys.devfund.public_key


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
    pk, sig = sign_with_root_ca(FIXED_SEED, ChainKind.TESTNET, message, confirmed=True, index=0)

    keys = derive_root_ceremony_keys(FIXED_SEED, ChainKind.TESTNET)
    assert pk == keys.root_ca.public_key, "sign_with_root_ca must use the same key derive_root_ceremony_keys does"
    assert len(sig) == 3309


def test_sign_with_root_ca_refuses_without_confirmation():
    """ The architectural review-before-sign gate an adversarial review
        found missing: sign_with_root_ca must not sign unless the caller
        explicitly passes confirmed=True. """
    message = b"genesis-config canonical bytes for testnet"
    with pytest.raises(SigningNotConfirmedError):
        sign_with_root_ca(FIXED_SEED, ChainKind.TESTNET, message, confirmed=False, index=0)


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
    pk, sig = sign_with_devfund(FIXED_SEED, ChainKind.TESTNET, message, confirmed=True, index=0)

    keys = derive_root_ceremony_keys(FIXED_SEED, ChainKind.TESTNET)
    assert pk == keys.devfund.public_key, "sign_with_devfund must use the same key derive_root_ceremony_keys does"
    assert len(sig) == 3309


def test_sign_with_devfund_uses_the_same_key_as_sign_with_root_ca():
    """ BUG FIX, 2026-10-03 (R27 re-port): this used to assert the two
        signing functions use different keys -- that was the bug. Confirmed
        against 7fchain's real sf-root.rs (cmd_sign_genesis/cmd_sign_devfund
        both call the byte-identical root_key_from_file(..., index 0)): the
        same Root key signs both genesis-config and devfund-config. """
    message = b"same message, same intended signer"
    root_pk, _ = sign_with_root_ca(FIXED_SEED, ChainKind.TESTNET, message, confirmed=True, index=0)
    devfund_pk, _ = sign_with_devfund(FIXED_SEED, ChainKind.TESTNET, message, confirmed=True, index=0)
    assert root_pk == devfund_pk


def test_sign_with_devfund_refuses_without_confirmation():
    message = b"devfund-config canonical bytes for testnet"
    with pytest.raises(SigningNotConfirmedError):
        sign_with_devfund(FIXED_SEED, ChainKind.TESTNET, message, confirmed=False, index=0)


def test_sign_with_devfund_requires_confirmed_as_keyword():
    message = b"devfund-config canonical bytes for testnet"
    with pytest.raises(TypeError):
        sign_with_devfund(FIXED_SEED, ChainKind.TESTNET, message, True)  # positional -- must fail
    with pytest.raises(TypeError):
        sign_with_devfund(FIXED_SEED, ChainKind.TESTNET, message)  # omitted entirely -- must fail
