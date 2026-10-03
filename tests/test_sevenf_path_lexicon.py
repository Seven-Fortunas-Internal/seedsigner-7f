"""
    Tests for path_lexicon.py, translated directly from 7fchain's own
    crates/sf-keytree/src/path.rs test module -- the same test oracle as
    the real reference, not independently invented cases. If path.rs's
    test module ever changes, re-diff this file against it.

    RE-PORTED 2026-10-03 (R27): path.rs collapsed its two-level
    purpose-path/role-path grammar into one combined path; this file is a
    full re-port against that single grammar, not an incremental patch of
    the old two-level test file.
"""
import pytest

from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.models.sevenf.path_lexicon import (
    Algorithm,
    Leaf,
    PathLexiconError,
    Role,
    _validate_segment,
    parse,
    validate,
)


def _ok(path):
    validate(path)  # raises on failure; success is silent


def _rejects(path):
    with pytest.raises(PathLexiconError):
        validate(path)


# ─── R-L2: every lexicon value renders a legal segment ───────────────────

def test_every_role_renders_a_legal_segment():
    for r in Role:
        _validate_segment(r.value)


def test_every_algorithm_renders_a_legal_segment():
    for a in Algorithm:
        _validate_segment(a.value)


def test_every_leaf_renders_a_legal_segment():
    for leaf in Leaf:
        _validate_segment(leaf.value)


def test_role_spellings_are_pinned():
    """ The spellings are load-bearing: changing one changes every key
        under that role, so they are pinned rather than merely derived. """
    assert Role.ROOT.value == "root"
    assert Role.MINER.value == "miner"
    assert Role.WALLET.value == "wallet"
    assert Role.DEPUTY.value == "deputy"
    assert Role.CENTCOM.value == "centcom"
    assert Role.L2_WALLET.value == "l2-wallet"
    assert Role.SEQUENCER.value == "sequencer"
    assert Role.MASTER_MINTER.value == "master-minter"
    assert Role.GUARDIAN.value == "guardian"
    assert Role.VERIFIER.value == "verifier"
    assert Role.RECHECKER.value == "rechecker"
    assert Role.FEDERATION.value == "federation"
    assert Algorithm.ML_DSA.value == "ml-dsa"
    assert Algorithm.FALCON.value == "falcon"
    assert Leaf.HOT.value == "hot"
    assert Leaf.BLOCK_REWARD.value == "block-reward"


# ─── Structure ─────────────────────────────────────────────────────────

def test_no_role_spans_layers_so_the_layer_is_implied():
    for r in (Role.ROOT, Role.MINER, Role.WALLET, Role.DEPUTY, Role.CENTCOM):
        assert not r.is_l2, r
    for r in (
        Role.L2_WALLET, Role.SEQUENCER, Role.MASTER_MINTER,
        Role.GUARDIAN, Role.VERIFIER, Role.RECHECKER, Role.FEDERATION,
    ):
        assert r.is_l2, r


def test_chain_bound_roles_are_exactly_the_four():
    bound = [r.value for r in Role if r.is_chain_bound]
    assert bound == ["l2-wallet", "sequencer", "master-minter", "guardian"]


def test_only_miner_carries_a_leaf():
    """ R-L5, as a test rather than a comment. """
    for r in Role:
        assert r.allows_leaf == (r is Role.MINER), r


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
        "devfund/testnet/0/ml-dsa/v1",
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
    from seedsigner.models.sevenf.constants import root_path
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
        _validate_segment("à")  # non-ASCII lowercase letter
    with pytest.raises(PathLexiconError):
        validate("root/testnet/²/ml-dsa/v1")  # non-ASCII "digit" (superscript 2)
    with pytest.raises(PathLexiconError):
        validate("root/testnet/٣/ml-dsa/v1")  # Arabic-Indic digit 3


def test_segment_max_length():
    with pytest.raises(PathLexiconError):
        _validate_segment("a" * 33)
    _validate_segment("a" * 32)  # must not raise


def test_parse_returns_the_expected_fields():
    """ Not in the Rust reference's own test list (there, parse() returns
        a typed DerivationPath; here it returns a dict -- see
        path_lexicon.py's own docstring for why) -- pins this port's own
        return shape. """
    parsed = parse("l2-wallet/mainnet/999/7/ml-dsa/v1")
    assert parsed["role"] is Role.L2_WALLET
    assert parsed["chain_kind"] == ChainKind.MAINNET
    assert parsed["chain_id"] == 999
    assert parsed["index"] == 7
    assert parsed["algorithm"] is Algorithm.ML_DSA
    assert parsed["version"] == 1
    assert parsed["leaf"] is None

    parsed_leaf = parse("miner/testnet/3/ml-dsa/v1/block-reward")
    assert parsed_leaf["leaf"] is Leaf.BLOCK_REWARD
