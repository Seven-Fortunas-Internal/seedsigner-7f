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


# --- execution-stage review 2026-10-08: more of serde's rules --------------------
# Verdicts from sf-core's own GenesisConfig / DevFundConfig through
# serde_json 1.0.151 (7fchain 06a47ba's Cargo.lock), a scratch crate, 2026-10-08.

def _g_with(old: str, new: str) -> bytes:
    doc = _g().decode()
    assert old in doc
    return doc.replace(old, new, 1).encode()


def _d_with(old: str, new: str) -> bytes:
    doc = _d().decode()
    assert old in doc
    return doc.replace(old, new, 1).encode()


SERDE_CASES = [
    # -0 is a float to serde_json: refused for an integer field, fine where ignored.
    ("genesis -0 consensus", _g_with('"target_block_time_secs":420', '"target_block_time_secs":-0'), False),
    ("genesis -0 unknown", _g(extra=',"z":[-0]'), True),
    ("devfund -0 effective_block", _d_with('"effective_block":0', '"effective_block":-0'), False),
    # A lone surrogate escape: refused in a field read or any key, fine in an ignored value.
    ("genesis surrogate message", _g_with('"message":"m"', '"message":"\\ud800"'), False),
    ("genesis surrogate signer_vk", _g(sigs='{"signer_vk":"\\ud800","sig":"00"}'), False),
    ("genesis surrogate sig", _g(sigs='{"signer_vk":"","sig":"\\udc00"}'), False),
    ("genesis surrogate unknown key", _g(extra=',"\\ud800":1'), False),
    ("genesis surrogate unknown value", _g(extra=',"z":"\\ud800"'), True),
    ("devfund surrogate commitment", _d_with('"commitment":"' + COMMIT, '"commitment":"\\ud800' + COMMIT[1:]), False),
    # An extra top-level devfund_address in a version-2 file is ignored, as any unknown key.
    ("devfund extra devfund_address", _d(extra=',"devfund_address":"t1abc"'), True),
    # Wrong types are refusals, not crashes.
    ("devfund network object", _d_with('"network":"testnet"', '"network":{"a":1}'), False),
    ("devfund kind list", _d_with('"kind":"multisig"', '"kind":["multisig"]'), False),
    ("genesis chain_kind list", _g_with('"chain_kind":"testnet"', '"chain_kind":["testnet"]'), False),
]


@pytest.mark.parametrize("name,doc,accepted", SERDE_CASES, ids=[c[0] for c in SERDE_CASES])
def test_serde_rules(name, doc, accepted):
    parse, error = ((genesis_config.parse_genesis_config_json, GenesisConfigJsonError) if name.startswith("genesis")
                    else (devfund_config.parse_devfund_config_json, DevFundConfigJsonError))
    if accepted:
        parse(doc)
    else:
        with pytest.raises(error):
            parse(doc)


def test_objects_without_a_repeated_key_are_plain_dicts():
    """ Security review 2026-10-08: a per-object subclass and attribute cost
        about 200x the payload in memory for many small objects. """
    from seedsigner.models.sevenf import config_json
    obj = config_json.load_object(b'{"x":[{},{"a":1}],"y":{"b":1,"b":2}}', ValueError, "test")
    assert type(obj) is dict and all(type(o) is dict for o in obj["x"])
    assert obj["y"].duplicates == frozenset({"b"})


def test_a_refused_value_is_shown_only_in_part():
    """ Security review 2026-10-08: the refusal reaches the screen, whose text
        layout is quadratic in its length. """
    long_scheme = "x" * 100_000
    with pytest.raises(GenesisConfigJsonError) as e:
        genesis_config.parse_genesis_config_json(_g_with('"7fchain.ml-dsa-keygen.v1"', json.dumps(long_scheme)))
    assert len(str(e.value)) < 200


@pytest.mark.parametrize("view_name", ["SevenFUnsupportedArtefactView", "SevenFNotA7FPhraseView"])
def test_a_refusal_screen_shows_a_bounded_reason(view_name):
    """ Whatever an error message carries, the refusal screen's text stays
        short enough to lay out (security review 2026-10-08). """
    from base import FlowTest  # noqa: F401
    from seedsigner.views import sevenf_views
    view = getattr(sevenf_views, view_name)(reason="r" * 100_000)
    assert len(view.reason) <= 301


def test_page_cuts_keep_every_character():
    """ Security review 2026-10-08: the pages of a value, joined, are the value;
        spaces at a cut were dropped, so runs of spaces in signed text could
        not be read. """
    from base import FlowTest  # noqa: F401
    from seedsigner.views.sevenf_views._common import _paginate_value
    value = ("word " * 30 + "     " + "x" * 400 + "  end") * 3
    pages = _paginate_value(value, 50)
    assert "".join(pages) == value
    assert all(len(p) <= 50 for p in pages)


def test_combining_marks_are_shown_escaped():
    """ A combining mark draws on top of the character before it, so what is
        signed could not be read off the screen; it is shown as an escape. """
    from seedsigner.models.sevenf.review_format import visible_text
    assert visible_text("é") == "e\\u0301"
    assert visible_text("café") == "café"          # a precomposed letter is a letter


def test_review_pages_are_computed_once_per_review():
    """ Security review 2026-10-08: every page press re-split the whole field
        list, quadratic in a long message. The same review's list is split once. """
    from base import FlowTest  # noqa: F401
    from seedsigner.models.review import ReviewField
    from seedsigner.views.sevenf_views._common import _review_pages
    fields = [ReviewField(label="Message", value="w " * 500)]
    first = _review_pages(fields)
    assert _review_pages(fields) is first
    assert _review_pages(list(fields)) == first and _review_pages(list(fields)) is not first
