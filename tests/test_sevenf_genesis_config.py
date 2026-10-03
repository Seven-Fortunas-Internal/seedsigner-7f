"""
    Tests seedsigner.models.sevenf.genesis_config -- the ctypes bridge to
    firmware/mldsa7f's genesis-config canonical-bytes build/parse functions.
    Backs the re-scoped 7f-signing-support-root-ceremony-genesis-builder-and-signer
    (docs/7f-integration/root-key-ceremony-plan.md).

    Requires firmware/mldsa7f's compiled library (see test_sevenf_mldsa.py's
    own docstring for the search order); skips cleanly if it's missing.
"""
import json

import pytest

from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.chains.base import ReviewField
from seedsigner.models.sevenf.genesis_config import (
    ConsensusParams,
    DERIVATION_SCHEME_V1,
    SCHEMA_VERSION,
    GenesisConfigError,
    GenesisConfigJsonError,
    _format_timestamp,
    build_canonical_bytes,
    build_root_sig_json,
    genesis_config_review_lines,
    parse_canonical_bytes,
    parse_genesis_config_json,
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


def test_build_matches_the_real_reference_vector():
    """ Cross-checks this Python bridge against the exact same real
        reference vector firmware/mldsa7f/src/genesis_config.rs's own test
        module pins (extracted directly from sf-core's real
        genesis_config::canonical_bytes(), not guessed -- see that Rust
        test's own doc comment for the capture-and-revert provenance).
        Interoperability vector 3 of Patrick's requirements doc §7.4
        ("canonical bytes... compared byte for byte"). Confirms the ctypes
        marshalling itself, not just that Python and Rust agree with each
        other in isolation -- this test PREVIOUSLY only checked that
        decoding round-tripped, which a wrong domain tag or field order
        could still pass by accident if the same bug existed on both the
        build and parse side; a real byte-for-byte hex match can't. """
    consensus = ConsensusParams(target_block_time_secs=30, difficulty_adjustment_interval_blocks=50, blocks_per_decay_period=200)
    bytes_ = build_canonical_bytes(ChainKind.DEVNET, 1_790_555_198, "cross-check fixture", consensus)
    expected_hex = (
        "67656e657369732d636f6e666967016465766e6574000000006ab9b43e"
        "63726f73732d636865636b20666978747572653766636861696e2e6d6c"
        "2d6473612d6b657967656e2e7631000000000000001e0000000000000"
        "03200000000000000c8"
    )
    assert bytes_.hex() == expected_hex

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


def _sample_genesis_config_dict(chain_kind_str: str = "testnet", **overrides) -> dict:
    """ The REAL coordinator artifact shape (sf_core::genesis_config::
        GenesisConfig), confirmed field-for-field against that struct
        2026-10-03 -- not an independently invented test fixture shape. """
    doc = {
        "version": SCHEMA_VERSION,
        "chain_kind": chain_kind_str,
        "timestamp": 1_790_555_198,
        "message": "cross-check fixture",
        "derivation_scheme": DERIVATION_SCHEME_V1,
        "consensus": {
            "target_block_time_secs": 420,
            "difficulty_adjustment_interval_blocks": 3500,
            "blocks_per_decay_period": 70_000,
        },
        "signatures": [],
    }
    doc.update(overrides)
    return doc


def test_parse_genesis_config_json_matches_the_real_artifact_shape():
    """ The actual scan-time entry point as of the R27-adjacent
        genesis-wire-envelope fix: parses the REAL coordinator JSON file,
        not a hand-built canonical-bytes fixture. """
    doc = _sample_genesis_config_dict()
    fields = parse_genesis_config_json(json.dumps(doc).encode("utf-8"))
    assert fields.chain_kind == ChainKind.TESTNET
    assert fields.timestamp == 1_790_555_198
    assert fields.message == "cross-check fixture"
    assert fields.consensus == ConsensusParams(420, 3500, 70_000)


@pytest.mark.parametrize("chain_kind_str,expected", [
    ("mainnet", ChainKind.MAINNET), ("testnet", ChainKind.TESTNET), ("devnet", ChainKind.DEVNET),
])
def test_parse_genesis_config_json_all_chain_kinds(chain_kind_str, expected):
    doc = _sample_genesis_config_dict(chain_kind_str=chain_kind_str)
    fields = parse_genesis_config_json(json.dumps(doc).encode("utf-8"))
    assert fields.chain_kind == expected


def test_parse_genesis_config_json_produces_the_same_canonical_bytes_as_build_canonical_bytes():
    """ The actual point of this parser: building canonical_bytes from its
        output must match calling build_canonical_bytes() with the same
        values directly -- the exact bytes sf-root sign-genesis would sign
        for the same real JSON file. """
    doc = _sample_genesis_config_dict()
    fields = parse_genesis_config_json(json.dumps(doc).encode("utf-8"))
    bytes_from_json = build_canonical_bytes(fields.chain_kind, fields.timestamp, fields.message, fields.consensus)
    bytes_direct = build_canonical_bytes(ChainKind.TESTNET, 1_790_555_198, "cross-check fixture", ConsensusParams(420, 3500, 70_000))
    assert bytes_from_json == bytes_direct


def test_parse_genesis_config_json_ignores_present_signatures():
    """ A partly-assembled file (other Roots already signed) must parse
        identically to a bare one -- canonical_bytes never covers
        `signatures`, confirmed against sf-root.rs's own cmd_sign_genesis
        doc comment ("signing a partly assembled file gives the same
        signature as signing the bare one"). """
    bare = _sample_genesis_config_dict()
    partly_signed = _sample_genesis_config_dict(signatures=[{"signer_vk": "ab" * 976, "sig": "cd" * 1654}])
    fields_bare = parse_genesis_config_json(json.dumps(bare).encode("utf-8"))
    fields_signed = parse_genesis_config_json(json.dumps(partly_signed).encode("utf-8"))
    assert fields_bare == fields_signed


def test_parse_genesis_config_json_tolerates_missing_signatures_field():
    """ `signatures` is `#[serde(default)]` on the real struct -- optional,
        not required -- confirmed against that real field attribute. """
    doc = _sample_genesis_config_dict()
    del doc["signatures"]
    fields = parse_genesis_config_json(json.dumps(doc).encode("utf-8"))
    assert fields.chain_kind == ChainKind.TESTNET


def test_parse_genesis_config_json_rejects_invalid_utf8():
    with pytest.raises(GenesisConfigJsonError, match="UTF-8"):
        parse_genesis_config_json(b"\xff\xfe not utf-8")


def test_parse_genesis_config_json_rejects_malformed_json():
    with pytest.raises(GenesisConfigJsonError, match="JSON"):
        parse_genesis_config_json(b"{not valid json at all")


def test_parse_genesis_config_json_rejects_pathologically_deep_nesting():
    """ Regression test, adversarial review 2026-10-03: Python's json module
        is recursive-descent, so a deeply-nested payload raises
        RecursionError, not json.JSONDecodeError. Before this fix that
        propagated unhandled past SevenFScanGenesisConfigView's
        `except GenesisConfigJsonError` clause, surfacing a generic
        debug/traceback screen instead of the intended clean refusal --
        untrusted, coordinator-supplied, BBQr-scanned bytes must never do
        that. """
    pathological = b"[" * 100_000
    with pytest.raises(GenesisConfigJsonError, match="JSON"):
        parse_genesis_config_json(pathological)


@pytest.mark.parametrize("payload", [b"[]", b'"a string"', b"42", b"null", b"true"])
def test_parse_genesis_config_json_rejects_non_object_top_level(payload):
    with pytest.raises(GenesisConfigJsonError, match="object"):
        parse_genesis_config_json(payload)


def test_parse_genesis_config_json_rejects_float_version():
    """ Regression test, adversarial review 2026-10-03: `1.0 == 1` in
        Python, so a bare `version != SCHEMA_VERSION` check (missing the
        isinstance guard every other scalar field check here has) silently
        accepted a JSON float where the real sf-root's serde deserialization
        of a `u8` field would reject one outright. """
    doc = _sample_genesis_config_dict(version=1.0)
    with pytest.raises(GenesisConfigJsonError, match="version"):
        parse_genesis_config_json(json.dumps(doc).encode("utf-8"))


@pytest.mark.parametrize("bad_signatures", [
    "not a list", 42, None,
    [1, 2],  # entries not objects
    [{"signer_vk": "ab" * 976}],  # missing "sig"
    [{"sig": "cd" * 1654}],  # missing "signer_vk"
    [{"signer_vk": 123, "sig": "cd" * 1654}],  # wrong type
])
def test_parse_genesis_config_json_rejects_malformed_signatures(bad_signatures):
    """ Regression test, adversarial review 2026-10-03 (differential check
        against the real sf_core::genesis_config::GenesisConfig struct):
        the real struct fails to deserialize AT ALL if `signatures` is
        present but malformed-shaped -- confirmed by direct testing against
        that real struct. This parser never reads `signatures` content, but
        must still refuse a file the real tooling would never have
        produced, not silently accept it. """
    doc = _sample_genesis_config_dict(signatures=bad_signatures)
    with pytest.raises(GenesisConfigJsonError, match="signatures"):
        parse_genesis_config_json(json.dumps(doc).encode("utf-8"))


def test_parse_genesis_config_json_accepts_a_well_formed_signatures_entry():
    doc = _sample_genesis_config_dict(signatures=[{"signer_vk": "ab" * 976, "sig": "cd" * 1654}])
    fields = parse_genesis_config_json(json.dumps(doc).encode("utf-8"))
    assert fields.chain_kind == ChainKind.TESTNET


@pytest.mark.parametrize("bad_version", [2, 0, "1", True, None])
def test_parse_genesis_config_json_rejects_wrong_version(bad_version):
    doc = _sample_genesis_config_dict(version=bad_version)
    with pytest.raises(GenesisConfigJsonError, match="version"):
        parse_genesis_config_json(json.dumps(doc).encode("utf-8"))


def test_parse_genesis_config_json_rejects_missing_version():
    doc = _sample_genesis_config_dict()
    del doc["version"]
    with pytest.raises(GenesisConfigJsonError, match="version"):
        parse_genesis_config_json(json.dumps(doc).encode("utf-8"))


@pytest.mark.parametrize("bad_scheme", ["7fchain.ml-dsa-keygen.v2", "", None, 42])
def test_parse_genesis_config_json_rejects_wrong_derivation_scheme(bad_scheme):
    doc = _sample_genesis_config_dict(derivation_scheme=bad_scheme)
    with pytest.raises(GenesisConfigJsonError, match="derivation_scheme"):
        parse_genesis_config_json(json.dumps(doc).encode("utf-8"))


@pytest.mark.parametrize("bad_chain_kind", ["regtest", "Testnet", "TESTNET", "", None, 1])
def test_parse_genesis_config_json_rejects_unrecognized_chain_kind(bad_chain_kind):
    """ Includes wrong-case spellings ("Testnet"/"TESTNET") -- the real
        side's #[serde(rename_all = "lowercase")] is an exact, case-sensitive
        match, so this parser must be too, not more lenient than the real
        binary it stands in for. """
    doc = _sample_genesis_config_dict(chain_kind_str=bad_chain_kind)
    with pytest.raises(GenesisConfigJsonError, match="chain_kind"):
        parse_genesis_config_json(json.dumps(doc).encode("utf-8"))


@pytest.mark.parametrize("bad_timestamp", [-1, "1790555198", 1.5, True, None, 2**64])
def test_parse_genesis_config_json_rejects_bad_timestamp(bad_timestamp):
    doc = _sample_genesis_config_dict(timestamp=bad_timestamp)
    with pytest.raises(GenesisConfigJsonError, match="timestamp"):
        parse_genesis_config_json(json.dumps(doc).encode("utf-8"))


@pytest.mark.parametrize("bad_message", [42, None, ["a", "list"]])
def test_parse_genesis_config_json_rejects_bad_message_type(bad_message):
    doc = _sample_genesis_config_dict(message=bad_message)
    with pytest.raises(GenesisConfigJsonError, match="message"):
        parse_genesis_config_json(json.dumps(doc).encode("utf-8"))


@pytest.mark.parametrize("bad_consensus", [None, [], "not an object", 42])
def test_parse_genesis_config_json_rejects_bad_consensus_type(bad_consensus):
    doc = _sample_genesis_config_dict(consensus=bad_consensus)
    with pytest.raises(GenesisConfigJsonError, match="consensus"):
        parse_genesis_config_json(json.dumps(doc).encode("utf-8"))


@pytest.mark.parametrize("missing_key", [
    "target_block_time_secs", "difficulty_adjustment_interval_blocks", "blocks_per_decay_period",
])
def test_parse_genesis_config_json_rejects_missing_consensus_field(missing_key):
    doc = _sample_genesis_config_dict()
    del doc["consensus"][missing_key]
    with pytest.raises(GenesisConfigJsonError, match=missing_key):
        parse_genesis_config_json(json.dumps(doc).encode("utf-8"))


@pytest.mark.parametrize("bad_value", [-1, "420", 1.5, True, 2**64])
def test_parse_genesis_config_json_rejects_bad_consensus_field_value(bad_value):
    doc = _sample_genesis_config_dict()
    doc["consensus"]["target_block_time_secs"] = bad_value
    with pytest.raises(GenesisConfigJsonError, match="target_block_time_secs"):
        parse_genesis_config_json(json.dumps(doc).encode("utf-8"))


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
        `hex::encode(&Sha256::digest(&vk)[..10])` -- SHA-256 of the raw key,
        truncated to 10 bytes, hex-encoded. Re-confirmed directly against
        that real, current source 2026-09-30 after this test's PREVIOUS
        version pinned a plain-truncation value that had no relationship to
        the real function at all -- this module's own root_id() had the
        same bug, found via a 7fchain sync, not by this test (its old
        fixture value was self-consistently wrong). The expected value
        below is computed with Python's own hashlib directly against the
        input, not copied from the implementation under test. """
    vk_hex = "AB" * 976  # exercises uppercase-input handling
    import hashlib
    expected = hashlib.sha256(bytes.fromhex(vk_hex)).digest()[:10].hex()
    assert root_id(vk_hex) == expected
    assert root_id(vk_hex) == "0377200d0972f6389d22"  # pinned, not just self-referential


def test_root_sig_filename_matches_real_sf_root_convention():
    """ Pinned against crates/sf-keytree/src/bin/sf-root.rs's own
        `cmd_sign_genesis` outbox naming: `{id}.genesis` where
        `id = root_id(vk_hex)` -- confirmed against that real, current
        source (commit 3bb5da3). Expected id recomputed 2026-09-30 after
        root_id()'s own bug fix (see test_root_id_matches_real_sf_core_convention). """
    signer_vk = bytes.fromhex("ab" * 1952)  # ML_DSA_PK_LEN
    assert root_sig_filename(signer_vk) == "f818b47b772449955fed.genesis"


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
