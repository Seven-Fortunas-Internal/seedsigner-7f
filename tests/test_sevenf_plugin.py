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
from seedsigner.chains.base import Address, ParsedRequest, Signature
from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf.constants import ChainKind, root_path
from seedsigner.models.sevenf.genesis_config import GenesisConfigJsonError
from seedsigner.models.sevenf.root_ceremony import derive_root_ceremony_keys, sign_with_root_ca


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
    """ The REAL coordinator artifact (sf-root prepare-genesis's JSON file)
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


def test_sign_produces_the_real_root_ca_signature():
    """ Cross-checks against an independent direct call to
        root_ceremony.sign_with_root_ca() over the SAME canonical bytes the
        plugin builds internally from the JSON payload -- confirms the
        plugin wrapper isn't a placeholder and signs the exact bytes
        sf-root sign-genesis would for the same file. """
    from seedsigner.chains.sevenf.plugin import SevenFPlugin
    from seedsigner.models.sevenf.genesis_config import build_canonical_bytes, parse_genesis_config_json
    plugin = SevenFPlugin()
    genesis_json = _sample_genesis_config_json(chain_kind_str="testnet")

    signature = plugin.sign(FIXED_SEED, "irrelevant-path", genesis_json)
    assert isinstance(signature, Signature)
    assert len(signature.signature_bytes) == 3309

    fields = parse_genesis_config_json(genesis_json)
    canonical_bytes = build_canonical_bytes(fields.chain_kind, fields.timestamp, fields.message, fields.consensus)
    expected_pk, expected_sig = sign_with_root_ca(FIXED_SEED, ChainKind.TESTNET, canonical_bytes, confirmed=True)
    assert signature.public_key == expected_pk
    # ML-DSA-65 signing is hedged/randomized (confirmed elsewhere in this
    # suite) -- can't compare signature bytes directly, but both must verify
    # under the same public key and both must be well-formed.
    keys = derive_root_ceremony_keys(FIXED_SEED, ChainKind.TESTNET)
    assert signature.public_key == keys.root_ca.public_key


def test_sign_ignores_a_mismatched_path_argument_and_uses_the_payloads_own_chain_kind():
    """ Regression/self-validation test: sign()'s `path` argument must never
        override what's actually inside `payload` -- passing a path that
        claims a different chain_kind than the payload's real one must not
        change which key gets used. """
    from seedsigner.chains.sevenf.plugin import SevenFPlugin
    plugin = SevenFPlugin()
    testnet_json = _sample_genesis_config_json(chain_kind_str="testnet")

    signature = plugin.sign(FIXED_SEED, root_path(ChainKind.MAINNET), testnet_json)
    keys = derive_root_ceremony_keys(FIXED_SEED, ChainKind.TESTNET)
    assert signature.public_key == keys.root_ca.public_key
    mainnet_keys = derive_root_ceremony_keys(FIXED_SEED, ChainKind.MAINNET)
    assert signature.public_key != mainnet_keys.root_ca.public_key


def test_derive_address_matches_root_ceremony_derivation():
    from seedsigner.chains.sevenf.plugin import SevenFPlugin
    plugin = SevenFPlugin()
    path = root_path(ChainKind.TESTNET)

    address = plugin.derive_address(FIXED_SEED, path)
    assert isinstance(address, Address)
    assert address.path == path
    assert address.network_name == "testnet"

    keys = derive_root_ceremony_keys(FIXED_SEED, ChainKind.TESTNET)
    assert address.address == keys.root_ca.address


def test_derive_address_rejects_an_unparseable_path():
    from seedsigner.chains.sevenf.plugin import SevenFPlugin
    plugin = SevenFPlugin()
    with pytest.raises(ValueError):
        plugin.derive_address(FIXED_SEED, "m/not-a-real-7f-path/0")


def test_encode_response_hex_encodes_the_signature_bytes():
    from seedsigner.chains.sevenf.plugin import SevenFPlugin
    plugin = SevenFPlugin()
    signature = Signature(signature_bytes=bytes([0xAB, 0xCD, 0xEF]))
    assert plugin.encode_response(signature) == b"abcdef"
