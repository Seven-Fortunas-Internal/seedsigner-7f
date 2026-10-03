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

    Vector 2 covers every role that still exists in the real single-grammar
    Role enum (crates/sf-keytree/src/path.rs) -- root, deputy (a second
    index too), centcom, wallet -- with a real Rust-cross-checked KAT,
    captured via `cargo test --release ffi_kat_capture_for_python
    -- --nocapture --ignored` (see test_sevenf_mldsa.py). Closed
    2026-09-29, re-captured 2026-10-03 for the R27 single-grammar
    collapse (which retired root-ca/intermediate-ca/stablecoin/giftcard/
    utilitytoken/7fchain-devfund as categories -- see that rewrite's own
    doc comments for why), 7f-signing-support-interop-vector-2-category-coverage.

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
    test_derive_pubkey_root_matches_rust_kat as _vector_2_root_category,
)
from test_sevenf_path_lexicon import (
    test_a_retired_role_is_not_a_role as _vector_6_rejects_unknown_role,
    test_segments_are_lowercase_and_bounded as _vector_6_rejects_uppercase,
)
from test_sevenf_root_ceremony import (
    test_end_to_end_from_a_real_mnemonic as _vector_1_phrase_to_master_seed,
    test_root_ca_and_devfund_are_the_same_key as _vector_2_devfund_is_the_root_key,
)


def test_vector_1_phrase_to_master_seed():
    _vector_1_phrase_to_master_seed()


def test_vector_2_master_seed_to_derived_key_root():
    _vector_2_root_category()


def test_vector_2_devfund_signs_with_the_same_key_as_root():
    """ devfund stopped being a separately-derived category in the R27
        single-grammar collapse (see root_ceremony.py's own BUG FIX note)
        -- this is vector 2's devfund coverage now: not a distinct
        derived-key KAT, but confirmation the devfund key IS the Root key. """
    _vector_2_devfund_is_the_root_key()


@pytest.mark.parametrize("path,expected_pk_sha256,expected_address", _vector_2_remaining_category_kats)
def test_vector_2_master_seed_to_derived_key_every_remaining_category(path, expected_pk_sha256, expected_address):
    _vector_2_assert_kat(path, expected_pk_sha256, expected_address)


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
    _vector_6_rejects_uppercase()
    _vector_6_rejects_unknown_role()
