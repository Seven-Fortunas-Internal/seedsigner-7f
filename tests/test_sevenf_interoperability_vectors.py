"""
    Consolidated proof-at-a-glance index for the interoperability
    test-vector suite Patrick's requirements doc mandates
    (`~/dev/GDF/internal-docs/data-room/02.2 Product/l1/
    seedsigner-ceremony-requirements-and-design.md` §7.4). Backs
    7f-signing-support-interoperability-test-suite.

    §7.4's 6 vectors, verbatim:
      1. Phrase to master seed, for known phrases.
      2. Master seed to derived key, for every category and several
         indices, compared by public key.
      3. Canonical bytes, for several genesis and development fund
         configurations, compared byte for byte.
      4. A signature made on the device verifies in our verifier, and one
         made in our workspace verifies on the device.
      5. Multi-part encode and decode, including a deliberately corrupted
         frame, which must fail rather than truncate.
      6. Path validation: a path with uppercase, a trailing separator or a
         word outside the lexicon is rejected, not silently derived.

    This module is an INDEX, not a duplicate test suite: each vector's real
    pinned test lives in its natural home file, closest to the code it
    tests, and is imported here rather than re-implemented -- one source of
    truth per pinned value, no drift risk between two copies of the same
    magic constant. Running this file alone
    (`pytest tests/test_sevenf_interoperability_vectors.py -v`) confirms
    the FULL §7.4 set at a glance; the imported tests' own home files carry
    the fuller context/provenance for each pin.

    Vector 4 (cross-verification) is a genuine, separately tracked gap --
    7f-signing-support-no-cross-verification-tooling -- blocked on
    7fchain's own sf-wallet-side design, not attempted here.

    Vector 2 covers every reserved category (root-ca, deputy-ca including
    both its L1/L2 forms and a second index, centcom-ca, intermediate-ca,
    stablecoin, giftcard, utilitytoken, 7fchain/devfund) with a real
    Rust-cross-checked KAT, captured via `cargo test --release
    ffi_kat_capture_for_python -- --nocapture --ignored` (see
    test_sevenf_mldsa.py) -- closed 2026-09-29,
    7f-signing-support-interop-vector-2-category-coverage.

    Requires firmware/mldsa7f's compiled library (most of these vectors
    depend on it); skips cleanly if it's missing.
"""
import pytest

from seedsigner.models.sevenf import mldsa


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

from test_sevenf_bbqr import (
    test_corrupted_frame_fails_loudly_not_silently_wrong as _vector_5_corrupted_content,
    test_corrupted_header_total_count_raises_rather_than_truncating as _vector_5_corrupted_header,
    test_get_data_returns_none_before_complete as _vector_5_dropped_frames,
)
from test_sevenf_devfund_config import test_matches_the_real_reference_vector_address as _vector_3_devfund_config
from test_sevenf_genesis_config import test_build_matches_the_real_reference_vector as _vector_3_genesis_config
from test_sevenf_mldsa import (
    REMAINING_CATEGORY_KATS as _vector_2_remaining_category_kats,
    _assert_derive_pubkey_matches_kat as _vector_2_assert_kat,
    test_derive_pubkey_devfund_matches_rust_kat as _vector_2_devfund_category,
    test_derive_pubkey_root_ca_matches_rust_kat as _vector_2_root_ca_category,
)
from test_sevenf_path_lexicon import test_invalid_purpose_paths as _vector_6_rejects_bad_paths
from test_sevenf_root_ceremony import test_end_to_end_from_a_real_mnemonic as _vector_1_phrase_to_master_seed


def test_vector_1_phrase_to_master_seed():
    _vector_1_phrase_to_master_seed()


def test_vector_2_master_seed_to_derived_key_root_ca():
    _vector_2_root_ca_category()


def test_vector_2_master_seed_to_derived_key_devfund():
    _vector_2_devfund_category()


@pytest.mark.parametrize("purpose_path,expected_pk_sha256,expected_address", _vector_2_remaining_category_kats)
def test_vector_2_master_seed_to_derived_key_every_remaining_category(purpose_path, expected_pk_sha256, expected_address):
    _vector_2_assert_kat(purpose_path, expected_pk_sha256, expected_address)


def test_vector_3_canonical_bytes_genesis_config():
    _vector_3_genesis_config()


def test_vector_3_canonical_bytes_devfund_config():
    _vector_3_devfund_config()


def test_vector_5_multipart_corrupted_content_fails_loudly():
    _vector_5_corrupted_content()


def test_vector_5_multipart_corrupted_header_fails_loudly():
    _vector_5_corrupted_header()


def test_vector_5_multipart_dropped_frames_never_silently_complete():
    _vector_5_dropped_frames()


def test_vector_6_path_validation_rejects_uppercase_and_unknown_word():
    _vector_6_rejects_bad_paths()
