"""
    Tests seedsigner.models.sevenf.genesis_config -- the ctypes bridge to
    firmware/mldsa7f's genesis-config canonical-bytes build/parse functions.
    Backs the re-scoped 7f-signing-support-root-ceremony-genesis-builder-and-signer
    (docs/7f-integration/root-key-ceremony-plan.md).

    Requires firmware/mldsa7f's compiled library (see test_sevenf_mldsa.py's
    own docstring for the search order); skips cleanly if it's missing.
"""
import pytest

from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.chains.base import ReviewField
from seedsigner.models.sevenf.genesis_config import (
    ConsensusParams,
    DERIVATION_SCHEME_V1,
    GenesisConfigError,
    _format_timestamp,
    build_canonical_bytes,
    build_root_sig_json,
    genesis_config_review_lines,
    parse_canonical_bytes,
    review_fields,
    root_id,
    root_sig_filename,
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


def _sample_consensus() -> ConsensusParams:
    return ConsensusParams(target_block_time_secs=420, difficulty_adjustment_interval_blocks=3500, blocks_per_decay_period=70_000)


def test_round_trip():
    consensus = _sample_consensus()
    bytes_ = build_canonical_bytes(ChainKind.TESTNET, 1_790_555_198, "cross-check fixture", consensus)
    fields = parse_canonical_bytes(bytes_)
    assert fields.chain_kind == ChainKind.TESTNET
    assert fields.timestamp == 1_790_555_198
    assert fields.message == "cross-check fixture"
    assert fields.consensus == consensus


@pytest.mark.parametrize("chain_kind", [ChainKind.MAINNET, ChainKind.TESTNET, ChainKind.DEVNET])
def test_round_trip_all_chain_kinds(chain_kind):
    consensus = _sample_consensus()
    bytes_ = build_canonical_bytes(chain_kind, 1, "x", consensus)
    fields = parse_canonical_bytes(bytes_)
    assert fields.chain_kind == chain_kind


def test_round_trip_empty_message():
    consensus = _sample_consensus()
    bytes_ = build_canonical_bytes(ChainKind.TESTNET, 1, "", consensus)
    fields = parse_canonical_bytes(bytes_)
    assert fields.message == ""


def test_round_trip_message_containing_lookalike_substrings():
    """ Mirrors firmware/mldsa7f/src/genesis_config.rs's own adversarial
        test at the Rust layer -- confirms the FFI round trip doesn't
        introduce a new failure mode the pure-Rust test wouldn't catch. """
    consensus = _sample_consensus()
    message = "testnet mainnet devnet 7fchain.ml-dsa-keygen.v1 lookalike text"
    bytes_ = build_canonical_bytes(ChainKind.TESTNET, 1, message, consensus)
    fields = parse_canonical_bytes(bytes_)
    assert fields.message == message


def test_build_produces_bytes_matching_real_cross_check_prefix():
    """ Cross-checks against this project's own real end-to-end sf-root
        cross-check (backlog story 7f-signing-support-root-ceremony-key-derivation):
        for devnet, timestamp=1790555198, message="cross-check fixture",
        consensus={30,50,200}, the canonical bytes must start with the
        domain tag + version, and the tail must carry the real
        derivation_scheme constant -- confirmed indirectly by round-tripping
        successfully (a wrong domain tag or version would make
        parse_canonical_bytes raise, per the dedicated rejection tests
        below and in the Rust-level test suite). """
    consensus = ConsensusParams(target_block_time_secs=30, difficulty_adjustment_interval_blocks=50, blocks_per_decay_period=200)
    bytes_ = build_canonical_bytes(ChainKind.DEVNET, 1_790_555_198, "cross-check fixture", consensus)
    fields = parse_canonical_bytes(bytes_)
    assert fields.chain_kind == ChainKind.DEVNET
    assert fields.timestamp == 1_790_555_198
    assert fields.message == "cross-check fixture"
    assert fields.consensus == consensus


def test_parse_rejects_garbage():
    with pytest.raises(GenesisConfigError):
        parse_canonical_bytes(b"not a genesis config at all")


def test_parse_rejects_empty_input():
    with pytest.raises(GenesisConfigError):
        parse_canonical_bytes(b"")


def test_parse_rejects_message_buffer_too_small():
    consensus = _sample_consensus()
    bytes_ = build_canonical_bytes(ChainKind.TESTNET, 1, "a message that is definitely longer than one byte", consensus)
    with pytest.raises(GenesisConfigError):
        parse_canonical_bytes(bytes_, max_message_len=1)


def test_genesis_config_fields_equality():
    """ Closes a coverage gap: GenesisConfigFields.__eq__ was otherwise
        never exercised (only its nested ConsensusParams.__eq__ was, via
        test_round_trip's `fields.consensus == consensus`). """
    consensus = _sample_consensus()
    bytes_ = build_canonical_bytes(ChainKind.TESTNET, 1, "same", consensus)
    fields_a = parse_canonical_bytes(bytes_)
    fields_b = parse_canonical_bytes(bytes_)
    assert fields_a == fields_b
    assert fields_a != "not a GenesisConfigFields"


def test_build_canonical_bytes_raises_on_nonzero_return(monkeypatch):
    """ Closes a coverage gap: build_canonical_bytes's own `if rc != 0:
        raise` branch was never triggered -- every legitimate Python-side
        input always sizes its output buffer correctly (overhead + message
        + margin), so no real call can reach it. Same documented-mock
        pattern as test_sevenf_mldsa.py's
        test_derive_and_sign_raises_mldsa_error_on_nonzero_return: inject a
        fake nonzero return at the ctypes-call boundary via a fake lib
        object, rather than a real FFI failure. """
    import seedsigner.models.sevenf.genesis_config as genesis_config_module

    class _FakeLib:
        def mldsa7f_genesis_build_canonical_bytes(self, *args):
            return -14  # ERR_OUTPUT_BUFFER_TOO_SMALL, ffi.rs

    monkeypatch.setattr(genesis_config_module, "_lib", lambda: _FakeLib())
    consensus = _sample_consensus()
    with pytest.raises(GenesisConfigError) as exc_info:
        build_canonical_bytes(ChainKind.TESTNET, 1, "x", consensus)
    assert exc_info.value.code == -14
    assert exc_info.value.operation == "build_canonical_bytes"


def test_genesis_config_review_lines_contains_all_fields():
    """ Regression test for a real bug: this function's own docstring claims
        to mirror firmware/mldsa7f/src/genesis_config.rs's render_lines(),
        but the original Python port silently dropped the "Derivation
        scheme" line (6 lines instead of Rust's 7) -- caught only while
        building review_fields() below and comparing against the real Rust
        function. Asserting len == 7 and the scheme string itself pins that
        this can't silently regress again. """
    consensus = _sample_consensus()
    bytes_ = build_canonical_bytes(ChainKind.TESTNET, 1_790_555_198, "cross-check fixture", consensus)
    fields = parse_canonical_bytes(bytes_)
    lines = genesis_config_review_lines(fields)
    joined = "\n".join(lines)
    assert "testnet" in joined
    assert "cross-check fixture" in joined
    assert DERIVATION_SCHEME_V1 in joined
    assert "420" in joined
    assert "3500" in joined
    assert "70000" in joined
    assert len(lines) == 7


def test_review_fields_matches_genesis_config_review_lines_content():
    """ review_fields() and genesis_config_review_lines() share the same
        _labeled_values() source, so their content must agree field-for-
        field -- confirms the shared-helper refactor didn't let the two
        functions drift again the way the pre-refactor version already had
        (see the regression test above). """
    consensus = _sample_consensus()
    bytes_ = build_canonical_bytes(ChainKind.TESTNET, 1_790_555_198, "cross-check fixture", consensus)
    fields = parse_canonical_bytes(bytes_)

    lines = genesis_config_review_lines(fields)
    review_field_list = review_fields(fields)

    assert len(review_field_list) == len(lines) == 7
    assert all(isinstance(f, ReviewField) for f in review_field_list)
    for line, field in zip(lines, review_field_list):
        assert line == f"{field.label}: {field.value}"
        assert field.is_warning is False


def test_review_fields_includes_derivation_scheme():
    consensus = _sample_consensus()
    bytes_ = build_canonical_bytes(ChainKind.TESTNET, 1, "x", consensus)
    fields = parse_canonical_bytes(bytes_)
    review_field_list = review_fields(fields)
    scheme_fields = [f for f in review_field_list if f.label == "Derivation scheme"]
    assert len(scheme_fields) == 1
    assert scheme_fields[0].value == DERIVATION_SCHEME_V1


def test_build_root_sig_json_matches_real_sf_core_root_sig_shape():
    """ Field names must match 7fchain's real
        crates/sf-core/src/genesis_config.rs::RootSig struct exactly, and the
        payload must NOT re-embed the config -- confirmed against
        crates/sf-keytree/src/bin/sf-root.rs::cmd_sign_genesis's real, current
        output (commit 3bb5da3), which is exactly `RootSig{signer_vk, sig}`
        and nothing else. `signer_vk` defaults to empty per D11 (the key is
        enrolled once and never resent), mirroring that command's own
        `--with-vk` flag defaulting to false. """
    signer_vk = bytes([0xAB, 0xCD] * 16)
    sig = bytes([0x12, 0x34] * 8)

    doc = build_root_sig_json(signer_vk, sig)

    assert doc == {
        "signer_vk": "",
        "sig": "1234" * 8,
    }
    # JSON-serializable -- this is the actual export payload's real shape.
    import json
    json.dumps(doc)


def test_build_root_sig_json_with_vk_includes_the_hex_key():
    signer_vk = bytes([0xAB, 0xCD] * 16)
    sig = bytes([0x12, 0x34] * 8)

    doc = build_root_sig_json(signer_vk, sig, with_vk=True)

    assert doc["signer_vk"] == "abcd" * 16
    assert doc["sig"] == "1234" * 8


def test_root_id_matches_real_sf_core_convention():
    """ Pinned against crates/sf-core/src/genesis_config.rs::root_id()'s own
        `vk_hex.chars().take(20).flat_map(|c| c.to_lowercase()).collect()`
        -- confirmed against that real, current source. """
    vk_hex = "AB" * 976  # ML_DSA_PK_LEN hex chars, uppercase to exercise lowercasing
    assert root_id(vk_hex) == "ab" * 10


def test_root_sig_filename_matches_real_sf_root_convention():
    """ Pinned against crates/sf-keytree/src/bin/sf-root.rs's own
        `cmd_sign_genesis` outbox naming: `{id}.genesis` where
        `id = root_id(vk_hex)` -- confirmed against that real, current
        source (commit 3bb5da3). """
    signer_vk = bytes.fromhex("ab" * 1952)  # ML_DSA_PK_LEN
    assert root_sig_filename(signer_vk) == "abababababababababab.genesis"


def test_root_sig_filename_uses_hex_not_raw_bytes():
    """ A signer_vk that would not survive a naive str() round-trip --
        confirms the filename is built from the hex encoding, not from
        bytes.decode() or similar, which would raise on arbitrary bytes. """
    signer_vk = bytes([0x00, 0xff, 0x10] * 20)
    filename = root_sig_filename(signer_vk)
    assert filename.endswith(".genesis")
    assert filename == f"{root_id(signer_vk.hex())}.genesis"


def test_format_timestamp_shows_both_raw_value_and_utc_interpretation():
    """ Regression test for real no-blind-signing feedback from the 7F
        hardware walkthrough: a bare Unix epoch integer isn't independently
        reviewable by a human -- the operator must see both the exact raw
        value (what's actually inside the signed bytes) and a human-readable
        UTC interpretation, not one instead of the other. """
    formatted = _format_timestamp(1_790_555_198)
    assert "1790555198" in formatted
    assert "2026" in formatted  # sanity: this epoch value is in 2026
    assert "UTC" in formatted


def test_format_timestamp_is_actually_correct_utc():
    """ Pins the exact conversion against Python's own stdlib, not just
        "contains a plausible-looking year". """
    formatted = _format_timestamp(1_790_555_198)
    from datetime import datetime, timezone
    expected = datetime.fromtimestamp(1_790_555_198, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    assert expected in formatted


def test_format_timestamp_handles_zero():
    formatted = _format_timestamp(0)
    assert "1970-01-01 00:00:00 UTC" in formatted


def test_format_timestamp_refuses_to_crash_on_an_out_of_range_value():
    """ `timestamp` is coordinator-supplied, unvalidated u64 data -- an
        absurdly large value must not crash the whole review screen with an
        uncaught OverflowError/OSError. The raw value must still be shown
        (never hidden), just without a UTC interpretation that can't be
        computed. """
    huge_timestamp = 2**63 - 1  # max signed 64-bit, far outside any real calendar date
    formatted = _format_timestamp(huge_timestamp)
    assert str(huge_timestamp) in formatted
    assert "not a valid calendar date" in formatted


def test_review_fields_timestamp_includes_utc():
    """ End-to-end: the actual review-screen field, not just the helper in
        isolation. """
    consensus = _sample_consensus()
    bytes_ = build_canonical_bytes(ChainKind.TESTNET, 1_790_555_198, "cross-check fixture", consensus)
    fields = parse_canonical_bytes(bytes_)
    review_field_list = review_fields(fields)
    timestamp_field = next(f for f in review_field_list if f.label == "Timestamp")
    assert "1790555198" in timestamp_field.value
    assert "UTC" in timestamp_field.value
