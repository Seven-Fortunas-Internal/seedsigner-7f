"""
    Tests seedsigner.models.sevenf.deputy_ca_export -- the Root-to-Deputy
    child-seed export flow (derive_purpose_seed + bootstrap_passphrase +
    encrypted_blob composed together). Backs
    7f-signing-support-deputy-ca-seed-export.

    Requires firmware/mldsa7f's compiled library (derive_purpose_seed goes
    through the real FFI boundary) -- skips cleanly if it's missing, same
    convention as test_sevenf_mldsa.py.
"""
import json

import pytest

from seedsigner.models.sevenf import encrypted_blob, mldsa
from seedsigner.models.sevenf.bootstrap_passphrase import passphrase_to_bytes
from seedsigner.models.sevenf.constants import ChainKind, MASTER_SEED_LEN
from seedsigner.models.sevenf.deputy_ca_export import build_export, deputy_ca_purpose_path


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


def test_deputy_ca_purpose_path_matches_the_real_7fchain_format():
    assert deputy_ca_purpose_path(ChainKind.TESTNET) == "m/deputy-ca/l1/testnet/0"
    assert deputy_ca_purpose_path(ChainKind.MAINNET) == "m/deputy-ca/l1/mainnet/0"
    assert deputy_ca_purpose_path(ChainKind.DEVNET) == "m/deputy-ca/l1/devnet/0"


def test_build_export_returns_8_words_and_a_decryptable_envelope():
    words, envelope = build_export(FIXED_SEED, ChainKind.TESTNET)
    assert len(words) == 8

    passphrase_bytes = passphrase_to_bytes(words)
    plaintext = encrypted_blob.decrypt(envelope, passphrase_bytes)
    database = json.loads(plaintext)

    assert database["version"] == 1
    assert len(database["entries"]) == 1
    entry = database["entries"][0]
    assert entry["path"] == "m/deputy-ca/l1/testnet/0"
    assert entry["status"] == "active"
    assert len(bytes.fromhex(entry["seed_hex"])) == MASTER_SEED_LEN


def test_build_export_seed_hex_matches_derive_purpose_seed_directly():
    words, envelope = build_export(FIXED_SEED, ChainKind.TESTNET)
    passphrase_bytes = passphrase_to_bytes(words)
    plaintext = encrypted_blob.decrypt(envelope, passphrase_bytes)
    entry = json.loads(plaintext)["entries"][0]

    expected = mldsa.derive_purpose_seed(FIXED_SEED, "m/deputy-ca/l1/testnet/0")
    assert bytes.fromhex(entry["seed_hex"]) == expected


def test_build_export_generates_a_fresh_passphrase_each_call():
    words1, _ = build_export(FIXED_SEED, ChainKind.TESTNET)
    words2, _ = build_export(FIXED_SEED, ChainKind.TESTNET)
    assert words1 != words2


def test_build_export_differs_per_chain_kind():
    words1, envelope1 = build_export(FIXED_SEED, ChainKind.TESTNET)
    words2, envelope2 = build_export(FIXED_SEED, ChainKind.MAINNET)

    entry1 = json.loads(encrypted_blob.decrypt(envelope1, passphrase_to_bytes(words1)))["entries"][0]
    entry2 = json.loads(encrypted_blob.decrypt(envelope2, passphrase_to_bytes(words2)))["entries"][0]
    assert entry1["seed_hex"] != entry2["seed_hex"]
    assert entry1["path"] != entry2["path"]


def test_build_export_wrong_master_seed_length_raises_value_error():
    with pytest.raises(ValueError):
        build_export(b"\x00" * 32, ChainKind.TESTNET)
