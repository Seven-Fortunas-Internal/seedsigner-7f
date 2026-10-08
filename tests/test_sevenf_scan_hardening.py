"""
    Hostile-input hardening of the 7F scan path (security review 2026-10-08):
    a BBQr "zip bomb" must be refused, not decompressed into the Pi's 512 MB.
"""
import pytest

import base  # noqa: F401 -- mocks the Pi hardware modules the views import

from seedsigner.models.decode_qr import MAX_BBQR_DECODED_BYTES, DecodeQR, DecodeQRStatus
from seedsigner.models.encode_qr import BBQrEncoder


def _scan(payload: bytes, file_type="J") -> DecodeQR:
    encoder = BBQrEncoder(data=payload, file_type=file_type, bbqr_encoding="Z")
    d = DecodeQR()
    for _ in range(encoder.seq_len()):
        status = d.add_data(encoder.next_part())
    assert status == DecodeQRStatus.COMPLETE
    return d


def test_a_payload_over_the_cap_is_refused():
    d = _scan(b"\x00" * (MAX_BBQR_DECODED_BYTES + 1))
    with pytest.raises(ValueError, match="too large"):
        d.get_sevenf_bbqr_data()


def test_a_payload_at_the_cap_decodes():
    payload = b"\x00" * MAX_BBQR_DECODED_BYTES
    assert _scan(payload).get_sevenf_bbqr_data() == payload


def test_the_cap_is_far_above_any_ceremony_file():
    assert MAX_BBQR_DECODED_BYTES >= 512 * 1024


# ─── M1: what is signed is what is shown ──────────────────────────────────

def test_long_values_without_spaces_are_split():
    from seedsigner.views.sevenf_views._common import _paginate_value
    pages = _paginate_value("a" * 500, 180)
    assert all(len(p) <= 180 for p in pages) and "".join(pages) == "a" * 500


def test_long_values_with_newlines_are_split():
    from seedsigner.views.sevenf_views._common import _paginate_value
    pages = _paginate_value("line\n" * 200, 180)
    assert len(pages) > 1 and all(len(p) <= 180 for p in pages)


def test_control_and_bidi_characters_are_shown_visibly():
    """ A genesis message is coordinator text that gets signed: newlines,
        bidi overrides and other invisible characters are displayed as
        escapes so nothing signed is hidden from the operator. """
    from seedsigner.models.sevenf.review_format import visible_text
    assert visible_text("a\nb") == "a\\nb"
    assert visible_text("x‮y") == "x\\u202ey"
    assert visible_text("tab\there") == "tab\\there"
    assert visible_text("plain ascii, ünïcode ok") == "plain ascii, ünïcode ok"


def test_genesis_message_review_shows_escapes():
    import json
    from seedsigner.models.sevenf import genesis_config
    from tools_helpers import REAL_GENESIS_JSON
    obj = json.loads(REAL_GENESIS_JSON)
    obj["message"] = "hello\nhidden‮"
    fields = {f.label: f.value for f in genesis_config.review_fields(
        genesis_config.parse_genesis_config_json(json.dumps(obj).encode()))}
    assert fields["Message"] == "hello\\nhidden\\u202e"


# ─── M5 / L1: hostile genesis JSON is refused cleanly ─────────────────────

@pytest.mark.parametrize("raw", [
    b'{"version": 1, "chain_kind": "testnet", "timestamp": ' + b"9" * 5000 + b'}',
    b'{"version": 1, "version": 1}',
    b'{"version": NaN}',
])
def test_genesis_parser_refuses_hostile_json_cleanly(raw):
    from seedsigner.models.sevenf.genesis_config import GenesisConfigJsonError, parse_genesis_config_json
    with pytest.raises(GenesisConfigJsonError):
        parse_genesis_config_json(raw)


@pytest.mark.parametrize("message", ["\ud800", "x" * 4097])
def test_genesis_parser_refuses_unencodable_or_oversized_messages(message):
    import json
    from seedsigner.models.sevenf.genesis_config import GenesisConfigJsonError, parse_genesis_config_json
    from tools_helpers import REAL_GENESIS_JSON
    obj = json.loads(REAL_GENESIS_JSON)
    obj["message"] = message
    with pytest.raises(GenesisConfigJsonError):
        parse_genesis_config_json(json.dumps(obj).encode())


# ─── M5: any failure at a scan boundary shows the refusal screen ─────────

@pytest.mark.parametrize("view_name, extra", [
    ("SevenFScanGenesisConfigView", {}),
    ("SevenFScanDevFundConfigView", {}),
    ("SevenFScanRootCertificateView", {"chain_kind": "TESTNET"}),
])
def test_unexpected_errors_at_scan_boundaries_become_a_refusal(monkeypatch, view_name, extra):
    from seedsigner.models.seed import Seed
    from seedsigner.models.sevenf.constants import ChainKind
    from seedsigner.views import sevenf_views
    seed = Seed(mnemonic=["abandon"] * 11 + ["about"])
    args = {"seed": seed, **{k: getattr(ChainKind, v) for k, v in extra.items()}}
    view = getattr(sevenf_views, view_name).__new__(getattr(sevenf_views, view_name))
    view.__dict__.update(args)

    class Boom:
        def get_sevenf_bbqr_data(self):
            raise IndexError("segment index out of range")

    view.decoder = Boom()
    destination = view._handle_complete_scan()
    assert destination.View_cls is sevenf_views.SevenFUnsupportedArtefactView
