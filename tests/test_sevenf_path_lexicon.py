"""
    Key paths are checked by 7fchain's own rules: crates/sf-keytree/src/path.rs,
    ported verbatim into firmware/mldsa7f (src/path.rs) and called through
    the FFI (mldsa7f_path_validate). 7fchain's lexicon requires this: "The
    device must apply the same rules, and must do so by calling this code
    over FFI rather than reimplementing it" (docs/derivation-path-lexicon.md).
    There is no Python copy of the rules; every case below runs the Rust
    validator, and 7fchain's own tests (role spellings, layers, chain-bound
    roles, leaves) run in firmware/mldsa7f with the ported code.
"""
import pytest

from seedsigner.models.sevenf import path_lexicon
from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.models.sevenf.path_lexicon import PathLexiconError, validate


def _ok(p):
    validate(p)


def _rejects(p):
    with pytest.raises(PathLexiconError):
        validate(p)


def test_the_rules_are_7fchains_not_a_python_copy():
    for name in ("Role", "Algorithm", "Leaf", "parse", "_validate_segment", "_parse_u32", "_parse_version", "MAX_SEGMENT_LEN"):
        assert not hasattr(path_lexicon, name), name


def test_the_refusal_message_is_7fchains():
    # sf-keytree path.rs parse(), the segment-count refusal, word for word.
    with pytest.raises(PathLexiconError) as e:
        validate("root/testnet/0/ml-dsa")
    assert str(e.value) == ("root path must be root/<chain-kind>/<index>/<algorithm>/v<N>, "
                            "got 'root/testnet/0/ml-dsa' (4 segments, expected 5 or 6)")


# ─── The settled paths ───────────────────────────────────────────────────

def test_the_settled_shapes_all_validate():
    for p in [
        "root/testnet/0/ml-dsa/v1",
        "root/mainnet/8/ml-dsa/v1",
        "miner/testnet/3/ml-dsa/v1/hot",
        "miner/testnet/3/ml-dsa/v1/block-reward",
        "wallet/testnet/0/ml-dsa/v1",
        "deputy/testnet/0/ml-dsa/v1",
        "deputy/mainnet/2/ml-dsa/v1",
        "centcom/testnet/0/ml-dsa/v1",
        "miner-registrar/testnet/0/ml-dsa/v1",
        "l2-verifier-registrar/testnet/0/ml-dsa/v1",
        "l2-sequencer-registrar/mainnet/3/ml-dsa/v1",
        "l2-wallet/testnet/1/0/ml-dsa/v1",
        "l2-wallet/mainnet/999/7/ml-dsa/v1",
        "sequencer/testnet/111/0/ml-dsa/v1",
        "master-minter/testnet/1/0/ml-dsa/v1",
        "master-minter/mainnet/1/2/ml-dsa/v1",
        "guardian/testnet/1/0/ml-dsa/v1",
        "verifier/testnet/0/ml-dsa/v1",
        "rechecker/mainnet/2/ml-dsa/v1",
        "federation/testnet/3/ml-dsa/v1",
    ]:
        _ok(p)


def test_the_m_prefix_is_refused():
    with pytest.raises(PathLexiconError, match="must not start with 'm/'"):
        validate("m/root/testnet/0/ml-dsa/v1")


def test_a_retired_role_is_not_a_role():
    for p in [
        "root-ca/testnet/0/ml-dsa/v1",
        "deputy-ca/testnet/0/ml-dsa/v1",
        "centcom-ca/testnet/0/ml-dsa/v1",
        "intermediate-ca/testnet/0/ml-dsa/v1",
        "treasury/testnet/0/ml-dsa/v1",
        # "devfund/..." dropped from this list, matching path.rs at 89d3d39:
        # the role was un-retired (see test_devfund_is_a_role_and_is_not_the_root_path).
        "value/testnet/1/0/ml-dsa/v1",
        "7fchain/testnet/0/ml-dsa/v1",
        "stablecoin/testnet/0/ml-dsa/v1",
        "minter/testnet/0/ml-dsa/v1",
        "bip32/testnet/0/ml-dsa/v1",
    ]:
        _rejects(p)


def test_l2_has_no_devnet():
    for p in [
        "l2-wallet/devnet/1/0/ml-dsa/v1",
        "sequencer/devnet/1/0/ml-dsa/v1",
        "verifier/devnet/0/ml-dsa/v1",
        "federation/devnet/0/ml-dsa/v1",
        "master-minter/devnet/1/0/ml-dsa/v1",
    ]:
        with pytest.raises(PathLexiconError, match="no devnet"):
            validate(p)
    # L1 roles are fine on devnet.
    _ok("root/devnet/0/ml-dsa/v1")
    _ok("miner/devnet/0/ml-dsa/v1/hot")
    _ok("wallet/devnet/0/ml-dsa/v1")


def test_a_leaf_outside_miner_is_refused():
    for p in [
        "root/testnet/0/ml-dsa/v1/hot",
        "wallet/testnet/0/ml-dsa/v1/hot",
        "verifier/testnet/0/ml-dsa/v1/hot",
        "federation/testnet/0/ml-dsa/v1/hot",
        "sequencer/testnet/1/0/ml-dsa/v1/hot",
    ]:
        with pytest.raises(PathLexiconError, match="only 'miner'"):
            validate(p)


def test_a_chain_id_appears_exactly_where_it_belongs():
    # Chain-bound without one: too short.
    _rejects("sequencer/testnet/0/ml-dsa/v1")
    # Not chain-bound but given one: too long.
    _rejects("verifier/testnet/1/0/ml-dsa/v1")
    _rejects("root/testnet/1/0/ml-dsa/v1")


def test_the_version_is_mandatory_and_shaped():
    _rejects("root/testnet/0/ml-dsa")
    _rejects("root/testnet/0/ml-dsa/1")
    _rejects("root/testnet/0/ml-dsa/v")
    _rejects("root/testnet/0/ml-dsa/vx")
    _ok("root/testnet/0/ml-dsa/v2")
    _ok("root/testnet/0/ml-dsa/v10")


def test_the_version_is_a_u32():
    """ Adversarial-review regression (2026-10-03): found by direct
        execution against the real path.rs::parse_version(), which calls
        digits.parse::<u32>() and errors on overflow -- an earlier version
        of _parse_version here checked the digit charset but not the u32
        bound, so "v4294967296" silently parsed instead of being rejected.
        Not reachable from any live flow today (see this module's own
        docstring), but a real condition mismatch against the reference. """
    _ok("root/testnet/0/ml-dsa/v4294967295")
    _rejects("root/testnet/0/ml-dsa/v4294967296")


def test_an_index_is_a_u32():
    _rejects("root/testnet/abc/ml-dsa/v1")
    _rejects("root/testnet/-1/ml-dsa/v1")
    _rejects("l2-wallet/testnet/abc/0/ml-dsa/v1")
    _ok("root/testnet/4294967295/ml-dsa/v1")


def test_segments_are_lowercase_and_bounded():
    _rejects("Root/testnet/0/ml-dsa/v1")
    _rejects("root/Testnet/0/ml-dsa/v1")
    _rejects("root/testnet/0/ml_dsa/v1")
    _rejects(f"root/testnet/0/{'a' * 33}/v1")


def test_an_unknown_algorithm_is_refused():
    _rejects("root/testnet/0/dilithium/v1")
    _rejects("root/testnet/0/ed25519/v1")
    # Falcon still parses: addresses must decode even though nothing
    # derives it any more.
    _ok("wallet/testnet/0/falcon/v1")


def test_builder_produces_a_path_that_validates():
    """ Not a 1:1 port of path.rs's builders_* tests (this device only has
        constants.root_path() as a builder, not a general path_for() for
        every role) -- see that module's own doc comment. """
    from seedsigner.models.sevenf.path_lexicon import root_path
    assert root_path(ChainKind.TESTNET) == "root/testnet/0/ml-dsa/v1"
    _ok(root_path(ChainKind.TESTNET))


# ─── Unicode strictness (not in the Rust reference's own test list) ──────

def test_segment_and_index_validation_are_strictly_ascii():
    """ Not in the Rust reference's own test list (Rust's char methods are
        ascii-only by construction, so this distinction doesn't exist
        there) -- but Python's str.islower()/isalpha()/isdigit() are NOT
        ascii-only, so a naive port would silently accept Unicode-lookalike
        segments/indices the real reference rejects. Found and fixed during
        the original port, 2026-09-29, by cross-checking against Rust's
        actual semantics rather than trusting a passing test suite alone;
        re-verified against the R27 single-grammar rewrite, 2026-10-03. """
    with pytest.raises(PathLexiconError):
        validate("root/testnet/0/ml-dsà/v1")  # non-ASCII lowercase letter
    with pytest.raises(PathLexiconError):
        validate("root/testnet/²/ml-dsa/v1")  # non-ASCII "digit" (superscript 2)
    with pytest.raises(PathLexiconError):
        validate("root/testnet/٣/ml-dsa/v1")  # Arabic-Indic digit 3


def test_segment_max_length():
    """ 32 characters is the most a segment may have (MAX_SEGMENT_LEN): an
        index of 32 zeros is a key upstream, 33 is refused (7fchain 06a47ba's
        keypair_at, 2026-10-08). """
    validate(f"root/testnet/{'0' * 32}/ml-dsa/v1")
    _rejects(f"root/testnet/{'0' * 33}/ml-dsa/v1")
    _rejects(f"root/testnet/0/ml-dsa/v1/{'a' * 33}")
    _rejects(f"root/testnet/0/{'a' * 33}/v1")


def test_devfund_is_a_role_and_is_not_the_root_path():
    """ Port of path.rs's devfund_is_a_role_again_and_is_not_the_root_path
        (7fchain 89d3d39, 2026-10-05): the dev fund is locked by nine
        devfund keys derived at their own path, not by the Root keys. L1,
        not chain-bound, no leaf. """
    from seedsigner.models.sevenf.path_lexicon import devfund_path, root_path
    _ok("devfund/testnet/0/ml-dsa/v1")
    _ok("devfund/devnet/1/ml-dsa/v1")
    _rejects("devfund/testnet/7/0/ml-dsa/v1")  # no chain-id segment
    assert devfund_path(ChainKind.TESTNET) == "devfund/testnet/0/ml-dsa/v1"
    assert devfund_path(ChainKind.TESTNET) != root_path(ChainKind.TESTNET)
    _ok(devfund_path(ChainKind.MAINNET))
