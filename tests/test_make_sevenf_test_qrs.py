"""
    Round-trips tools/make_sevenf_test_qrs.py's generated artifacts through the
    app's own real scan-side decode path (BBQrEncoder -> DecodeQR ->
    get_sevenf_bbqr_data()) and real parsers (genesis_config, devfund_config,
    cert_request), so a change to either side of the encode/decode pair -- or a
    mistake in the tool's own payload construction -- fails a test instead of
    silently producing an artifact that only looks right.

    Requires firmware/mldsa7f's compiled library (same as tests/test_sevenf_mldsa.py
    and friends) -- skips cleanly if it's missing rather than failing the suite.
"""
import importlib.util
import os

import pytest

from seedsigner.models.sevenf import mldsa

TOOLS_DIR = os.path.join(os.path.dirname(__file__), "..", "tools")


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


def _load_tool_module():
    spec = importlib.util.spec_from_file_location(
        "make_sevenf_test_qrs", os.path.join(TOOLS_DIR, "make_sevenf_test_qrs.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tool = _load_tool_module()

from seedsigner.models.encode_qr import BBQrEncoder
from seedsigner.models.decode_qr import DecodeQR
from seedsigner.models.sevenf import cert_request, genesis_config, devfund_config


def _round_trip(payload: bytes) -> bytes:
    encoder = BBQrEncoder(data=payload, file_type="B", bbqr_encoding="Z")
    decoder = DecodeQR()
    for _ in range(encoder.seq_len()):
        assert decoder.add_data(encoder.next_part()) is not False
    assert decoder.is_complete
    assert decoder.is_sevenf_bbqr
    got = decoder.get_sevenf_bbqr_data()
    assert got == payload
    return got


def test_genesis_config_round_trips_and_parses():
    got = _round_trip(tool.build_genesis_config())
    genesis_config.parse_canonical_bytes(got)


def test_devfund_config_round_trips_and_parses():
    got = _round_trip(tool.build_devfund_config())
    devfund_config.parse_canonical_bytes(got)


def test_root_cert_request_round_trips_and_subject_matches_the_test_seed():
    root_keys = tool.root_ceremony.derive_root_ceremony_keys(tool.root_seed().seed_bytes, tool.CHAIN_KIND)
    got = _round_trip(tool.build_root_cert_request(root_keys.root_ca.public_key))
    req = cert_request.parse_cert_request_json(got)
    assert req.role == cert_request.ROLE_ROOT
    assert cert_request.subject_matches(req, root_keys.root_ca.public_key)


def test_deputy_cert_request_round_trips_and_parses():
    deputy_keys = tool.root_ceremony.derive_root_ceremony_keys(tool.deputy_seed().seed_bytes, tool.CHAIN_KIND)
    got = _round_trip(tool.build_deputy_cert_request(deputy_keys.root_ca.public_key))
    req = cert_request.parse_cert_request_json(got)
    assert req.role == cert_request.ROLE_DEPUTY
    assert req.subject_vk == deputy_keys.root_ca.public_key


def test_root_and_deputy_test_seeds_are_actually_different():
    # The whole point of the passphrase variant is a distinct key -- catch a
    # regression that accidentally makes both identities derive identically.
    root_keys = tool.root_ceremony.derive_root_ceremony_keys(tool.root_seed().seed_bytes, tool.CHAIN_KIND)
    deputy_keys = tool.root_ceremony.derive_root_ceremony_keys(tool.deputy_seed().seed_bytes, tool.CHAIN_KIND)
    assert root_keys.root_ca.public_key != deputy_keys.root_ca.public_key
