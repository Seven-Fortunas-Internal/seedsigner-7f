"""
    Tests for path_lexicon.py, translated directly from 7fchain's own
    crates/sf-keytree/src/path.rs test module (2026-09-29) -- the same test
    oracle as the real reference, not independently invented cases. If
    path.rs's test module ever changes, re-diff this file against it.
"""
import pytest

from seedsigner.models.sevenf.path_lexicon import (
    KNOWN_TOKENS,
    PathLexiconError,
    validate_purpose_path,
    validate_role_path,
    _validate_segment,
)


def _ok(path):
    validate_purpose_path(path)  # raises on failure; success is silent


def _rejects(path):
    with pytest.raises(PathLexiconError):
        validate_purpose_path(path)


def test_valid_purpose_paths():
    # root-ca: L1-only but layer marker still required.
    _ok("m/root-ca/l1/devnet/0")
    _ok("m/root-ca/l1/testnet/0")
    _ok("m/root-ca/l1/mainnet/1")

    # deputy-ca: L1 + L2 forms.
    _ok("m/deputy-ca/l1/testnet/0")
    _ok("m/deputy-ca/l2/testnet/42/0")

    # centcom-ca: L1 + L2 forms.
    _ok("m/centcom-ca/l1/devnet/0")
    _ok("m/centcom-ca/l1/testnet/0")
    _ok("m/centcom-ca/l1/mainnet/0")
    _ok("m/centcom-ca/l2/mainnet/1/0")

    # intermediate-ca: L1 + L2 forms (legacy <tier> dropped).
    _ok("m/intermediate-ca/l1/testnet/0")
    _ok("m/intermediate-ca/l2/testnet/7/0")

    # 7fchain: L1-only treasury/devfund, layer marker required.
    _ok("m/7fchain/l1/testnet/treasury/0")
    _ok("m/7fchain/l1/testnet/devfund/0")

    # Tokens (off the per-network/L1-L2 structure for now).
    _ok("m/stablecoin/7fusd/0")
    _ok("m/giftcard/intercorp/0")
    _ok("m/utilitytoken/interbank/0")


def test_root_ca_requires_layer_marker_and_rejects_l2():
    _rejects("m/root-ca/0")
    _rejects("m/root-ca/testnet/0")
    _rejects("m/root-ca/l2/testnet/1/0")
    _rejects("m/root-ca/l1/regtest/0")


@pytest.mark.parametrize("cat", ["deputy-ca", "centcom-ca", "intermediate-ca"])
def test_l1_l2_categories_require_layer_and_chain_kind(cat):
    _rejects(f"m/{cat}/0")
    _rejects(f"m/{cat}/testnet/0")
    _rejects(f"m/{cat}/l3/testnet/0")
    _rejects(f"m/{cat}/l1/regtest/0")
    _rejects(f"m/{cat}/l1/testnet/42/0")
    _rejects(f"m/{cat}/l2/testnet/0")
    _rejects(f"m/{cat}/l2/testnet/abc/0")


def test_intermediate_ca_drops_tier_segment():
    _rejects("m/intermediate-ca/3/0")
    _rejects("m/intermediate-ca/5/0")


def test_7fchain_requires_layer_marker_and_chain_kind():
    _rejects("m/7fchain/treasury/0")
    _rejects("m/7fchain/testnet/treasury/0")
    _rejects("m/7fchain/l2/testnet/1/treasury/0")
    _rejects("m/7fchain/l1/regtest/treasury/0")
    _rejects("m/7fchain/l1/testnet/treasury")


def test_invalid_purpose_paths():
    _rejects("root-ca/l1/testnet/0")       # missing m/ prefix
    _rejects("m/unknown/0")                # unknown category
    _rejects("m/Root-CA/l1/testnet/0")     # uppercase
    _rejects("m/root ca/l1/testnet/0")     # spaces
    _rejects("m/stablecoin/my_coin/0")     # underscore
    _rejects("m/root-ca/l1/testnet/abc")   # non-numeric index


def test_valid_role_paths():
    for role in ("ml-dsa", "falcon", "bip32", "minter", "master-minter",
                 "pauser", "blacklister", "admin", "owner", "deployer"):
        validate_role_path(f"{role}/0")


def test_invalid_role_paths():
    with pytest.raises(PathLexiconError):
        validate_role_path("ml-dsa")
    with pytest.raises(PathLexiconError):
        validate_role_path("ml-dsa/0/extra")
    with pytest.raises(PathLexiconError):
        validate_role_path("minter/abc")


def test_segment_max_length():
    with pytest.raises(PathLexiconError):
        _validate_segment("a" * 33)
    _validate_segment("a" * 32)  # must not raise


def test_known_tokens():
    names = {name for name, _, _ in KNOWN_TOKENS}
    assert {"7fusd", "gtq", "intercorp", "interbank"} <= names


def test_7fchain_l2_operator_paths():
    # Chain-bound sequencer carries the l2_chain_id.
    _ok("m/7fchain/l2/testnet/sequencer/80000001/0")
    _ok("m/7fchain/l2/mainnet/sequencer/00000001/3")
    # Chain-agnostic verifier / rechecker carry no chain_id.
    _ok("m/7fchain/l2/testnet/verifier/0")
    _ok("m/7fchain/l2/testnet/rechecker/0")
    # L1 operator path (e.g. a chain_kind-scoped miner) still validates.
    _ok("m/7fchain/l1/testnet/miner/0")

    _rejects("m/7fchain/l2/testnet/sequencer/0")             # missing chain_id
    _rejects("m/7fchain/l2/testnet/verifier/80000001/0")      # stray chain_id
    _rejects("m/7fchain/l2/testnet/relayer/0")                # unknown L2 role
    _rejects("m/7fchain/l2/staging/verifier/0")               # bad chain_kind


def test_segment_and_index_validation_are_strictly_ascii():
    """ Not in the Rust reference's own test list (Rust's char methods are
        ascii-only by construction, so this distinction doesn't exist
        there) -- but Python's str.islower()/isalpha()/isdigit() are NOT
        ascii-only, so a naive port would silently accept Unicode-lookalike
        segments/indices the real reference rejects. Found and fixed during
        this port, 2026-09-29, by cross-checking against Rust's actual
        semantics rather than trusting a passing test suite alone. """
    with pytest.raises(PathLexiconError):
        _validate_segment("à")  # non-ASCII lowercase letter
    with pytest.raises(PathLexiconError):
        validate_purpose_path("m/root-ca/l1/testnet/²")  # non-ASCII "digit" (superscript 2)
    with pytest.raises(PathLexiconError):
        validate_purpose_path("m/root-ca/l1/testnet/٣")  # Arabic-Indic digit 3


def test_role_path_validation_reuses_the_same_segment_rules():
    """ Not in the Rust reference's own test list, but a real property of
        this port worth pinning: role-path segment validation is the same
        _validate_segment used for purpose-path segments, so the same
        character-set/length rules apply to both. """
    with pytest.raises(PathLexiconError):
        validate_role_path("Minter/0")  # uppercase
    with pytest.raises(PathLexiconError):
        validate_role_path((("a" * 33)) + "/0")  # over MAX_SEGMENT_LEN
