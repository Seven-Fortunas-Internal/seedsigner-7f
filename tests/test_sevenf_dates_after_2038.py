"""
    The device is 32-bit ARM: datetime.fromtimestamp() there cannot go past
    2038-01-19 (time_t), so a 20-year Root certificate's "Valid until" showed
    "(not a valid calendar date)" on the dev unit (Jorge, 2026-10-08), and the
    review let it be signed anyway. Dates are computed without the platform's
    time_t; a certificate date the device cannot show is refused.
"""
from datetime import datetime as _real_datetime

import pytest

from seedsigner.models.sevenf import ceremony_clock, cert_request, devfund_config, genesis_config, review_format
from seedsigner.models.sevenf.constants import ChainKind
from sevenf_helpers import requires_mldsa7f

Y2038 = 2**31 - 1
NOT_BEFORE = 1_791_504_000                       # 2026-10-09 00:00:00 UTC
NOT_AFTER = NOT_BEFORE + cert_request.ROOT_DAYS * 86_400


class _Datetime32(_real_datetime):
    """ datetime as on a 32-bit time_t platform. """
    @classmethod
    def fromtimestamp(cls, t, tz=None):
        if t > Y2038:
            raise OverflowError("timestamp out of range for platform time_t")
        return super().fromtimestamp(t, tz)


@pytest.fixture
def thirty_two_bit(monkeypatch):
    for module in (review_format, ceremony_clock):
        monkeypatch.setattr(module, "datetime", _Datetime32)


def test_a_date_after_2038_is_shown_on_a_32_bit_device(thirty_two_bit):
    assert review_format.format_timestamp(NOT_AFTER) == f"{NOT_AFTER}\n(2046-10-04 00:00:00 UTC)"


def test_the_root_certificate_review_shows_its_end_date(thirty_two_bit):
    fields = {f.label: f.value for f in cert_request.root_self_cert_review_fields(
        b"\x01" * 1952, ChainKind.TESTNET, NOT_BEFORE, NOT_AFTER, b"\x40" * 16)}
    assert "2046-10-04" in fields["Valid until"] and "2026-10-09" in fields["Valid from"]


def test_a_certificate_date_the_device_cannot_show_is_refused():
    with pytest.raises(cert_request.CertRequestError, match="calendar date"):
        cert_request.root_self_cert_review_fields(b"\x01" * 1952, ChainKind.TESTNET, NOT_BEFORE, 2**63, b"\x40" * 16)


def test_the_date_editor_works_past_2038(thirty_two_bit):
    d = ceremony_clock.DateTimeFields.from_timestamp(NOT_AFTER)
    assert (d.year, d.month, d.day) == (2046, 10, 4)
    assert d.to_timestamp() == NOT_AFTER


def test_a_coordinator_timestamp_that_is_no_calendar_date_is_a_warning():
    """ sf-wallet-gov refuses only a zero timestamp (sign_ops.rs
        validate_genesis/validate_devfund), so the device signs any other u64
        too, but the review must not show it as an ordinary value. """
    import json
    doc = {"version": 2, "network": "testnet", "recipient": {"kind": "multisig", "commitment": "ab" * 64},
           "effective_block": 0, "timestamp": 2**63, "signatures": []}
    fields = devfund_config.parse_devfund_config_json(json.dumps(doc).encode())
    shown = {f.label: f for f in devfund_config.review_fields(fields)}
    assert shown["Timestamp"].is_warning and "calendar" in shown["Timestamp"].warning_detail
    gdoc = {"version": 1, "chain_kind": "testnet", "timestamp": 2**63, "message": "m",
            "derivation_scheme": "7fchain.ml-dsa-keygen.v1",
            "consensus": {"target_block_time_secs": 420, "difficulty_adjustment_interval_blocks": 1500,
                          "blocks_per_decay_period": 70000}}
    gfields = genesis_config.parse_genesis_config_json(json.dumps(gdoc).encode())
    gshown = {f.label: f for f in genesis_config.review_fields(gfields)}
    assert gshown["Timestamp"].is_warning


@requires_mldsa7f
def test_the_root_certificate_view_refuses_a_date_it_cannot_show(monkeypatch):
    from base import FlowTest  # noqa: F401
    from seedsigner.models.seed import Seed
    from seedsigner.views import sevenf_views
    from seedsigner.views.sevenf_views import _root_cert
    monkeypatch.setattr(_root_cert, "ceremony_now", lambda controller: NOT_BEFORE)
    monkeypatch.setattr(cert_request, "ROOT_DAYS", 10**15)          # an end date past year 9999
    monkeypatch.setattr(cert_request, "build_root_tbs", lambda *a, **kw: b"tbs")
    view = sevenf_views.SevenFBuildRootSelfCertView(seed=Seed(["abandon"] * 23 + ["art"]),
                                                    chain_kind=ChainKind.TESTNET, key_index=0)
    destination = view.run()
    assert destination.View_cls is sevenf_views.SevenFUnsupportedArtefactView
    assert "calendar date" in destination.view_args["reason"]
