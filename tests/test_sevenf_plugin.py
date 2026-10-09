"""
    Tests seedsigner.chains.sevenf.plugin.SevenFPlugin -- the ChainPlugin
    adapter wrapping the already-tested models/sevenf/* ceremony logic.
    Backs the 7F-as-a-boot-time-chain integration (chains/sevenf/plugin.py's
    own docstring has the full rationale).

    Requires firmware/mldsa7f's compiled library (see test_sevenf_mldsa.py's
    own docstring for the search order); skips cleanly if it's missing.
"""
import json

import pytest

from seedsigner.chains import ChainRegistry
from seedsigner.chains.base import ParsedRequest, Signature
from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf.constants import ChainKind, root_path
from seedsigner.models.sevenf.genesis_config import GenesisConfigJsonError


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

FIXED_SEED = bytes([0x2A] * 64)


def _sample_genesis_config_json(chain_kind_str: str = "testnet", **overrides) -> bytes:
    """ The REAL coordinator artifact (sf-root-coordinator prepare-genesis's JSON file)
        -- see genesis_config.py's own "RESOLVED" docstring note. """
    doc = dict(
        version=1,
        chain_kind=chain_kind_str,
        timestamp=1_790_555_198,
        message="plugin cross-check",
        derivation_scheme="7fchain.ml-dsa-keygen.v1",
        consensus={
            "target_block_time_secs": 420,
            "difficulty_adjustment_interval_blocks": 3500,
            "blocks_per_decay_period": 70_000,
        },
        signatures=[],
    )
    doc.update(overrides)
    return json.dumps(doc).encode("utf-8")


def test_chain_registry_has_sevenf_plugin():
    plugin = ChainRegistry.get("sevenf")
    assert plugin.chain_id == "sevenf"
    assert plugin.display_name == "7F Chain"


def test_parse_sign_request_matches_real_genesis_config_fields():
    from seedsigner.chains.sevenf.plugin import SevenFPlugin
    plugin = SevenFPlugin()
    genesis_json = _sample_genesis_config_json()

    parsed = plugin.parse_sign_request(genesis_json)
    assert isinstance(parsed, ParsedRequest)
    assert parsed.operation == "Genesis Config"
    assert parsed.network_name == "testnet"
    assert parsed.derivation_path == root_path(ChainKind.TESTNET)
    labels = [f.label for f in parsed.review_fields]
    assert "Chain" in labels
    assert "Message" in labels
    assert len(parsed.review_fields) == 8  # 7 signed fields + the canonical digest


def test_parse_sign_request_rejects_a_malformed_payload():
    from seedsigner.chains.sevenf.plugin import SevenFPlugin
    plugin = SevenFPlugin()
    with pytest.raises(GenesisConfigJsonError):
        plugin.parse_sign_request(b"not a genesis config at all")


def test_review_fields_returns_the_parsed_fields_unchanged():
    from seedsigner.chains.sevenf.plugin import SevenFPlugin
    plugin = SevenFPlugin()
    genesis_json = _sample_genesis_config_json()
    parsed = plugin.parse_sign_request(genesis_json)
    assert plugin.review_fields(parsed) is parsed.review_fields


def test_encode_response_hex_encodes_the_signature_bytes():
    from seedsigner.chains.sevenf.plugin import SevenFPlugin
    plugin = SevenFPlugin()
    signature = Signature(signature_bytes=bytes([0xAB, 0xCD, 0xEF]))
    assert plugin.encode_response(signature) == b"abcdef"


# sign() and derive_address() refuse (story port-root-phrase-24-words, H-1):
# see tests/test_sevenf_seed_eligibility.py::test_the_plugin_does_not_sign_or_derive_outside_the_7f_views.
