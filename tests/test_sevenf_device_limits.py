"""
    Story port-device-limits (H3, H4, M1, plan-stage L-2): the device accepts
    and refuses exactly what 7fchain's own types accept and refuse.

    Duplicate keys: the verdicts below were produced by 7fchain's own
    sf_core::genesis_config::{GenesisConfig, DevFundConfig} through
    serde_json at 06a47ba (a scratch program parsing each case, 2026-10-08):
    a repeated KNOWN field is refused at every level; a repeated UNKNOWN key
    is accepted at every level (no deny_unknown_fields).

    Sizes: sf-core puts no limit on the genesis message, and a dev-fund
    recipient payload is bounded only by its u16 length prefix.
"""
import json

import pytest

from seedsigner.models.sevenf import devfund_config, genesis_config
from seedsigner.models.sevenf.devfund_config import DevFundConfigJsonError
from seedsigner.models.sevenf.genesis_config import GenesisConfigJsonError

SIG = '{"signer_vk":"","sig":"00"}'
COMMIT = "ab" * 64


def _g(extra="", cons="", sigs=SIG):
    return ('{"version":1,"chain_kind":"testnet","timestamp":5,"message":"m","derivation_scheme":"7fchain.ml-dsa-keygen.v1",'
            '"consensus":{"target_block_time_secs":420,"difficulty_adjustment_interval_blocks":1500,"blocks_per_decay_period":70000'
            + cons + '},"signatures":[' + sigs + ']' + extra + '}').encode()


def _d(extra="", rec="", sigs=SIG):
    return ('{"version":2,"network":"testnet","recipient":{"kind":"multisig","commitment":"' + COMMIT + '"' + rec + '},'
            '"effective_block":0,"timestamp":5,"signatures":[' + sigs + ']' + extra + '}').encode()


# (name, document, accepted by 7fchain)
CASES = [
    ("genesis plain", _g(), True),
    ("genesis dup unknown top", _g(extra=',"x":1,"x":2'), True),
    ("genesis dup known top (timestamp)", _g(extra=',"timestamp":6'), False),
    ("genesis dup known consensus", _g(cons=',"blocks_per_decay_period":5'), False),
    ("genesis dup unknown consensus", _g(cons=',"y":1,"y":2'), True),
    ("genesis sig dup signer_vk", _g(sigs='{"signer_vk":"","signer_vk":"","sig":"00"}'), False),
    ("genesis sig dup unknown", _g(sigs='{"signer_vk":"","sig":"00","z":1,"z":2}'), True),
    ("devfund plain", _d(), True),
    ("devfund dup unknown top", _d(extra=',"x":1,"x":2'), True),
    ("devfund dup known top (network)", _d(extra=',"network":"testnet"'), False),
    ("devfund recipient dup commitment", _d(rec=',"commitment":"' + COMMIT + '"'), False),
    ("devfund recipient dup kind", _d(rec=',"kind":"multisig"'), False),
    ("devfund recipient dup unknown", _d(rec=',"w":1,"w":2'), True),
    ("devfund sig dup sig", _d(sigs='{"signer_vk":"","sig":"00","sig":"00"}'), False),
]


@pytest.mark.parametrize("name,doc,accepted", CASES, ids=[c[0] for c in CASES])
def test_duplicate_keys_as_7fchain(name, doc, accepted):
    parse, error = ((genesis_config.parse_genesis_config_json, GenesisConfigJsonError) if name.startswith("genesis")
                    else (devfund_config.parse_devfund_config_json, DevFundConfigJsonError))
    if accepted:
        parse(doc)
    else:
        with pytest.raises(error, match="duplicate"):
            parse(doc)


def test_a_long_genesis_message_is_accepted_and_round_trips():
    """ H3: no message limit in sf-core. """
    message = "7F " * 5000
    doc = json.loads(_g())
    doc["message"] = message
    fields = genesis_config.parse_genesis_config_json(json.dumps(doc).encode())
    canonical = genesis_config.build_canonical_bytes(fields.chain_kind, fields.timestamp, fields.message, fields.consensus)
    assert genesis_config.parse_canonical_bytes(canonical).message == message


def test_a_long_devfund_recipient_payload_round_trips():
    """ H4: the payload (address plus a trailing # comment, all signed) is
        bounded only by its u16 length prefix. """
    address = "t1lswdehurp3f3puwsuytdwcqjx6e9q0g6cktcyam8w2rhhvf"
    payload = address + "  # " + "c" * 10_000
    doc = json.loads(_d())
    doc["recipient"] = {"kind": "address", "address": payload}
    fields = devfund_config.parse_devfund_config_json(json.dumps(doc).encode())
    canonical = devfund_config.build_canonical_bytes(fields.network, fields.recipient, fields.effective_block, fields.timestamp)
    assert devfund_config.parse_canonical_bytes(canonical).recipient.payload == payload


def test_a_recipient_payload_past_u16_is_refused():
    doc = json.loads(_d())
    doc["recipient"] = {"kind": "address", "address": "t1lswdehurp3f3puwsuytdwcqjx6e9q0g6cktcyam8w2rhhvf # " + "c" * 70_000}
    with pytest.raises(DevFundConfigJsonError):
        devfund_config.parse_devfund_config_json(json.dumps(doc).encode())


# --- story port-web-page-pin-folders, device side (D-F2) ------------------------

@pytest.mark.parametrize("role, next_view", [("root", "SevenFVkPinView"), ("devfund", "SevenFExportRootVkQRView")])
def test_only_a_root_key_gets_a_pin_screen(role, next_view):
    """ sf-wallet-gov prints the root pin for a Root key (sign-root-cert) and
        no pin for a dev-fund key (derive-vk); the device does the same. """
    from base import FlowTest  # noqa: F401  (test base before the Controller)
    from seedsigner.views import sevenf_views
    view = sevenf_views.SevenFRootVkFingerprintView(public_key=b"\x0b" * 1952, title="t", key_index=0, role=role)
    with pytest.MonkeyPatch().context() as mp:
        mp.setattr(view, "run_screen", lambda screen_cls, **kw: 0)
        assert view.run().View_cls.__name__ == next_view


def test_the_pin_screen_names_it_the_root_pin():
    from base import FlowTest  # noqa: F401
    from seedsigner.views import sevenf_views
    view = sevenf_views.SevenFVkPinView(public_key=b"\x0b" * 1952, title="t", key_index=0, role="root")
    captured = {}
    with pytest.MonkeyPatch().context() as mp:
        mp.setattr(view, "run_screen", lambda screen_cls, **kw: captured.update(kw) or 0)
        view.run()
    assert "root pin" in captured["status_headline"]
