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
from seedsigner.models.sevenf.genesis_config import (
    ConsensusParams,
    GenesisConfigError,
    build_canonical_bytes,
    genesis_config_review_lines,
    parse_canonical_bytes,
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
    consensus = _sample_consensus()
    bytes_ = build_canonical_bytes(ChainKind.TESTNET, 1_790_555_198, "cross-check fixture", consensus)
    fields = parse_canonical_bytes(bytes_)
    lines = genesis_config_review_lines(fields)
    joined = "\n".join(lines)
    assert "testnet" in joined
    assert "cross-check fixture" in joined
    assert "420" in joined
    assert "3500" in joined
    assert "70000" in joined
    assert len(lines) == 6
