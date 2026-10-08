"""
    Review screens show every signed field plus what sf-wallet-gov shows before
    signing (Jorge, 2026-10-07: the operator should be as informed as
    possible). Digests are pinned to what the real sign-genesis/sign-devfund
    printed for the same files (7fchain 416f576, 2026-10-07 end-to-end run).
"""
import json

import pytest

from seedsigner.models.sevenf import devfund_config, genesis_config
from seedsigner.models.sevenf.constants import ChainKind

from tools_helpers import REAL_GENESIS_JSON
from test_sevenf_devfund_config import REAL_DEVFUND_UNSIGNED_JSON

GENESIS_DIGEST = "7c3eda8efac08d6f887468885afa019f"
DEVFUND_DIGEST = "4216a1c800e3309b28b372c4fa3c290b"


def by_label(fields):
    return {f.label: f for f in fields}


def test_genesis_review_shows_sf_wallet_gov_canonical_digest():
    fields = by_label(genesis_config.review_fields(genesis_config.parse_genesis_config_json(REAL_GENESIS_JSON)))
    assert fields["Canonical digest"].value.replace(" ", "") == GENESIS_DIGEST


def test_devfund_review_shows_sf_wallet_gov_canonical_digest():
    fields = by_label(devfund_config.review_fields(devfund_config.parse_devfund_config_json(REAL_DEVFUND_UNSIGNED_JSON)))
    assert fields["Canonical digest"].value.replace(" ", "") == DEVFUND_DIGEST


def test_devfund_recipient_warns_it_receives_the_entire_genesis_reward():
    fields = by_label(devfund_config.review_fields(devfund_config.parse_devfund_config_json(REAL_DEVFUND_UNSIGNED_JSON)))
    assert fields["Recipient"].is_warning
    assert "ENTIRE genesis reward" in fields["Recipient"].warning_detail


def test_default_consensus_is_not_flagged():
    fields = genesis_config.review_fields(genesis_config.parse_genesis_config_json(REAL_GENESIS_JSON))
    assert not any(f.is_warning for f in fields)


@pytest.mark.parametrize("key, value, label", [
    ("target_block_time_secs", 1, "Target block time"),
    ("difficulty_adjustment_interval_blocks", 50, "Difficulty adjustment interval"),
    ("blocks_per_decay_period", 200, "Blocks per decay period"),
])
def test_non_default_consensus_is_flagged_on_its_own_field(key, value, label):
    """ sf-wallet-gov refuses non-default tempo without
        --accept-nondefault-consensus; the device makes the operator see it. """
    obj = json.loads(REAL_GENESIS_JSON)
    obj["consensus"][key] = value
    fields = by_label(genesis_config.review_fields(genesis_config.parse_genesis_config_json(json.dumps(obj).encode())))
    assert fields[label].is_warning and "default" in fields[label].warning_detail
    assert sum(f.is_warning for f in fields.values()) == 1


def test_genesis_timestamp_zero_is_refused():
    obj = json.loads(REAL_GENESIS_JSON)
    obj["timestamp"] = 0
    with pytest.raises(genesis_config.GenesisConfigJsonError, match="timestamp"):
        genesis_config.parse_genesis_config_json(json.dumps(obj).encode())


def test_consensus_defaults_match_sf_core():
    """ sf-core ConsensusParams::defaults_for (genesis_config.rs). """
    d = genesis_config.CONSENSUS_DEFAULTS
    assert d[ChainKind.DEVNET] == genesis_config.ConsensusParams(30, 50, 200)
    assert d[ChainKind.TESTNET] == d[ChainKind.MAINNET] == genesis_config.ConsensusParams(420, 1500, 70000)


def test_multisig_commitment_is_shown_grouped_so_it_wraps():
    """ 128 unbroken hex chars run off the 240px screen; groups of four wrap.
        Display only -- the signed payload is the ungrouped string. """
    f = devfund_config.parse_devfund_config_json(REAL_DEVFUND_UNSIGNED_JSON)
    shown = by_label(devfund_config.review_fields(f))["Recipient"].value
    assert shown.replace(" ", "") == f.recipient.payload
    assert all(len(group) == 4 for group in shown.split(" "))


def test_a_long_warning_field_is_split_so_its_warning_stays_on_screen():
    """ A grouped 128-hex commitment plus the "ENTIRE genesis reward" warning
        doesn't fit one 240px page (rendered 2026-10-08: the warning was hidden
        behind the Next button). Warning fields page in smaller chunks, each
        repeating the warning. """
    from seedsigner.views.sevenf_views._common import _MAX_CHARS_PER_WARNING_PAGE, _review_pages
    fields = devfund_config.review_fields(devfund_config.parse_devfund_config_json(REAL_DEVFUND_UNSIGNED_JSON))
    pages = [p for p in _review_pages(fields) if p.label == "Recipient"]
    assert len(pages) >= 2
    assert all(len(p.value) <= _MAX_CHARS_PER_WARNING_PAGE and p.is_warning for p in pages)
    assert " ".join(p.value for p in pages).replace(" ", "") == json.loads(REAL_DEVFUND_UNSIGNED_JSON)["recipient"]["commitment"]


@pytest.mark.parametrize("module, parse, signed", [
    ("genesis", lambda: genesis_config.parse_genesis_config_json(REAL_GENESIS_JSON), None),
    ("devfund", lambda: devfund_config.parse_devfund_config_json(REAL_DEVFUND_UNSIGNED_JSON), None),
])
def test_digest_is_taken_from_the_bytes_given_not_rebuilt(module, parse, signed):
    """ The digest must describe the exact bytes that get signed. """
    import hashlib
    mod = genesis_config if module == "genesis" else devfund_config
    bytes_to_sign = b"exactly these bytes"
    fields = by_label(mod.review_fields(parse(), canonical_bytes=bytes_to_sign))
    assert fields["Canonical digest"].value.replace(" ", "") == hashlib.sha256(bytes_to_sign).hexdigest()[:32]
