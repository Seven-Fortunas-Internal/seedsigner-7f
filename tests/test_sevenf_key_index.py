"""
    The Root and dev-fund key index (7f-signing-support-key-index-selector,
    docs/7f-integration/root-key-index-selector-plan.md): the paths, the
    derivation and the signing functions take an index, default 0.

    Reference skis come from the real federation binary, 7fchain 06a47ba,
    run 2026-10-08 in a sandboxed HOME from a testnet directory on the
    canonical "abandon x23 + art" phrase, empty BIP-39 passphrase:
    `sf-wallet-gov sign-root-cert --index N` and
    `sf-wallet-gov derive-vk --role devfund --index N`.
"""
import pytest
from embit.bip39 import mnemonic_to_seed

from seedsigner.models.sevenf import cert_request, mldsa
from seedsigner.models.sevenf.constants import MAX_KEY_INDEX, ChainKind
from seedsigner.models.sevenf.path_lexicon import devfund_path, root_path
from seedsigner.models.sevenf.review_format import ski
from seedsigner.models.sevenf.root_ceremony import (
    derive_devfund_key,
    derive_root_ceremony_keys,
    sign_with_root_ca,
)
from sevenf_helpers import sevenf_seed_from_bytes


def _lib_available() -> bool:
    try:
        mldsa._lib_handle()
        return True
    except FileNotFoundError:
        return False


needs_lib = pytest.mark.skipif(not _lib_available(), reason="mldsa7f library not built")

CANONICAL_SEED = mnemonic_to_seed(" ".join(["abandon"] * 23 + ["art"]), password="")

ROOT_SKI = {
    0: "591c511984a2d73c6bee1f4dc149d48f7f97fc55",
    1: "8b3a61c23ace9b5a6effb11fbfe00ff5132ad296",
    2: "5615fb6473f46b68e5dc35baf0621ae1ab997761",
    7: "83633bdec0b99ca67baf1bdac00b3ce1f41350cf",
}
DEVFUND_SKI = {
    0: "af11f8afb793df512bf35110890e15dc8b3a2720",
    1: "8dd11a91288f2e2af18d2b3198945edd0e23ec14",
    2: "7a0b9f074d71157a8edf5911ea14b876fa92af59",
    7: "06ff7a5b2a1581fd6106b44c861e33b5f4871184",
    4294967295: "f9cf2bc5499d8571309f7cb274bfc2e028b7ac82",
}


# --- paths ---------------------------------------------------------------

def test_default_paths_are_unchanged():
    assert root_path(ChainKind.TESTNET) == "root/testnet/0/ml-dsa/v1"
    assert devfund_path(ChainKind.TESTNET) == "devfund/testnet/0/ml-dsa/v1"


@pytest.mark.parametrize("index", [0, 1, 2, 7, MAX_KEY_INDEX])
def test_paths_carry_the_index_in_canonical_decimal(index):
    assert root_path(ChainKind.TESTNET, index) == f"root/testnet/{index}/ml-dsa/v1"
    assert devfund_path(ChainKind.MAINNET, index) == f"devfund/mainnet/{index}/ml-dsa/v1"


def test_max_key_index_is_u32_max():
    # sf-wallet-gov accepts 4294967295 and refuses 4294967296 (checked 2026-10-08).
    assert MAX_KEY_INDEX == 4294967295


@pytest.mark.parametrize("bad", [-1, MAX_KEY_INDEX + 1, True, False, 1.0, "1", None])
def test_paths_refuse_an_index_that_is_not_a_u32_int(bad):
    with pytest.raises((ValueError, TypeError)):
        root_path(ChainKind.TESTNET, bad)
    with pytest.raises((ValueError, TypeError)):
        devfund_path(ChainKind.TESTNET, bad)


# --- derivation, against sf-wallet-gov ----------------------------------

@needs_lib
@pytest.mark.parametrize("index", sorted(ROOT_SKI))
def test_root_key_at_index_matches_sf_wallet_gov(index):
    keys = derive_root_ceremony_keys(sevenf_seed_from_bytes(CANONICAL_SEED), ChainKind.TESTNET, index=index)
    assert ski(keys.root_ca.public_key.hex()) == ROOT_SKI[index]
    assert keys.index == index


@needs_lib
@pytest.mark.parametrize("index", sorted(DEVFUND_SKI))
def test_devfund_key_at_index_matches_sf_wallet_gov(index):
    devfund = derive_devfund_key(sevenf_seed_from_bytes(CANONICAL_SEED), ChainKind.TESTNET, index=index)
    assert ski(devfund.public_key.hex()) == DEVFUND_SKI[index]


@needs_lib
def test_derivation_defaults_to_index_0():
    assert derive_root_ceremony_keys(sevenf_seed_from_bytes(CANONICAL_SEED), ChainKind.TESTNET, index=0).index == 0
    assert ski(derive_root_ceremony_keys(sevenf_seed_from_bytes(CANONICAL_SEED), ChainKind.TESTNET, index=0).root_ca.public_key.hex()) == ROOT_SKI[0]
    assert ski(derive_devfund_key(sevenf_seed_from_bytes(CANONICAL_SEED), ChainKind.TESTNET, index=0).public_key.hex()) == DEVFUND_SKI[0]


# --- signing --------------------------------------------------------------

def _root_tbs_for(public_key: bytes) -> bytes:
    return cert_request.build_root_tbs(public_key, ChainKind.TESTNET, 1_791_000_000, cert_request.ROOT_DAYS, bytes(range(1, 17)))


@needs_lib
@pytest.mark.parametrize("sign", [sign_with_root_ca])
def test_signing_at_an_index_verifies_only_under_that_index_key(sign):
    """ A real verification, not a comparison (ML-DSA signing is hedged, so
        two signatures always differ): assemble_root_cert_der() verifies the
        signature against the subject key and refuses on mismatch. Both sign
        functions sign with the ROOT key at the given index. """
    index_2_vk = derive_root_ceremony_keys(sevenf_seed_from_bytes(CANONICAL_SEED), ChainKind.TESTNET, index=2).root_ca.public_key
    tbs = _root_tbs_for(index_2_vk)

    public_key, signature = sign(sevenf_seed_from_bytes(CANONICAL_SEED), ChainKind.TESTNET, tbs, confirmed=True, index=2)
    assert public_key == index_2_vk
    assert ski(public_key.hex()) == ROOT_SKI[2]
    cert_request.assemble_root_cert_der(tbs, signature, index_2_vk)

    _, index_0_signature = sign(sevenf_seed_from_bytes(CANONICAL_SEED), ChainKind.TESTNET, tbs, confirmed=True, index=0)
    with pytest.raises(cert_request.CertRequestError):
        cert_request.assemble_root_cert_der(tbs, index_0_signature, index_2_vk)


@pytest.mark.parametrize("sign", [sign_with_root_ca])
def test_signing_requires_the_index(sign):
    """ No default: a caller that forgets the index must fail, not sign at 0. """
    with pytest.raises(TypeError):
        sign(sevenf_seed_from_bytes(CANONICAL_SEED), ChainKind.TESTNET, b"x", confirmed=True)


@pytest.mark.parametrize("sign", [sign_with_root_ca])
def test_signing_refuses_a_bad_index_before_signing(sign):
    with pytest.raises((ValueError, TypeError)):
        sign(sevenf_seed_from_bytes(CANONICAL_SEED), ChainKind.TESTNET, b"x", index=-1, confirmed=True)


@pytest.mark.parametrize("derive", [derive_root_ceremony_keys, derive_devfund_key])
def test_derivation_requires_the_index(derive):
    """ No default: an enrollment that forgot the index would export the
        index-0 key under a screen that says index N, with no signature to
        catch it. """
    with pytest.raises(TypeError):
        derive(CANONICAL_SEED, ChainKind.TESTNET)


# --- story 1c (M-2): paths are built by 7fchain's path_for, not by Python ------

def test_paths_are_built_by_7fchains_path_for(monkeypatch):
    from seedsigner.models.sevenf import mldsa, path_lexicon
    calls = []
    monkeypatch.setattr(mldsa, "path_for", lambda role, kind, index: calls.append((role, kind, index)) or f"<{role}>")
    assert path_lexicon.root_path(ChainKind.TESTNET, 7) == "<root>"
    assert path_lexicon.devfund_path(ChainKind.MAINNET, 2) == "<devfund>"
    assert calls == [("root", ChainKind.TESTNET, 7), ("devfund", ChainKind.MAINNET, 2)]


@pytest.mark.parametrize("bad", [True, -1, 2**32, 1.0, "7"])
def test_the_index_is_still_type_and_range_checked_before_the_ffi(bad):
    """ A ctypes u32 would silently wrap an out-of-range int; Python refuses first. """
    from seedsigner.models.sevenf.path_lexicon import root_path
    with pytest.raises((TypeError, ValueError)):
        root_path(ChainKind.TESTNET, bad)
