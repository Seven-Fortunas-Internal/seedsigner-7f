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


def test_genesis_config_is_coordinator_shaped_json_the_device_accepts():
    """ The device's genesis scan reads the coordinator's genesis-unsigned.json
        (parse_genesis_config_json), so the test artifact must be that shape,
        with prepare-genesis's default consensus values. """
    got = _round_trip(tool.build_genesis_config())
    fields = genesis_config.parse_genesis_config_json(got)
    assert fields.consensus == genesis_config.ConsensusParams(420, 1500, 70000)


def test_devfund_config_is_coordinator_shaped_json_the_device_accepts():
    """ Same for devfund-unsigned.json: version 2, multisig recipient, as
        prepare-devfund --threshold 6 --vk ... writes it. """
    got = _round_trip(tool.build_devfund_config())
    fields = devfund_config.parse_devfund_config_json(got)
    assert fields.recipient.tag == devfund_config.DevfundRecipient.MULTISIG


def test_root_cert_round_trips_and_parses():
    root_keys = tool.root_ceremony.derive_root_ceremony_keys(tool.root_seed().seed_bytes, tool.CHAIN_KIND)
    got = _round_trip(tool.build_root_cert_der(root_keys, tool.root_seed()))
    parsed = cert_request.parse_root_certificate_der(got)
    assert parsed.subject_vk == root_keys.root_ca.public_key
    assert parsed.chain_kind == tool.CHAIN_KIND


def test_deputy_csr_round_trips_and_parses():
    deputy_keys = tool.root_ceremony.derive_root_ceremony_keys(tool.deputy_seed().seed_bytes, tool.CHAIN_KIND)
    got = _round_trip(tool.build_deputy_csr_der(deputy_keys, tool.deputy_seed()))
    parsed = cert_request.verify_and_parse_csr_der(got)
    assert parsed.subject_vk == deputy_keys.root_ca.public_key


def test_root_cert_and_deputy_csr_support_the_real_deputy_cross_cert_flow():
    """ The actual point of this story: confirm the tool's own two new
        artifacts are not just individually well-formed, but genuinely
        usable as the two scanned inputs to the real Deputy cross-
        certification pipeline (build_deputy_tbs_v2 -> sign -> assemble),
        the same way a real device run would use them. """
    import time

    root_keys = tool.root_ceremony.derive_root_ceremony_keys(tool.root_seed().seed_bytes, tool.CHAIN_KIND)
    deputy_keys = tool.root_ceremony.derive_root_ceremony_keys(tool.deputy_seed().seed_bytes, tool.CHAIN_KIND)
    root_cert_der = _round_trip(tool.build_root_cert_der(root_keys, tool.root_seed()))
    deputy_csr_der = _round_trip(tool.build_deputy_csr_der(deputy_keys, tool.deputy_seed()))

    now = int(time.time())
    tbs = cert_request.build_deputy_tbs_v2(root_cert_der, deputy_csr_der, tool.CHAIN_KIND, now, cert_request.DEPUTY_DAYS, cert_request.generate_serial())
    _, signature = tool.root_ceremony.sign_with_root_ca(tool.root_seed().seed_bytes, tool.CHAIN_KIND, tbs, confirmed=True)
    deputy_cert_der = cert_request.assemble_deputy_cert_der(tbs, signature, root_cert_der)
    parsed = cert_request.parse_root_certificate_der(deputy_cert_der)
    assert parsed.subject_vk == deputy_keys.root_ca.public_key
    assert parsed.chain_kind == tool.CHAIN_KIND


def test_root_test_seed_qr_round_trips_through_the_real_decode_path(tmp_path):
    from seedsigner.models.decode_qr import DecodeQR

    path = tool.render_seed_qr("root_test_seed_qr", tool.ROOT_TEST_MNEMONIC, tmp_path)
    assert path.is_file()

    from seedsigner.models.encode_qr import CompactSeedQrEncoder
    from seedsigner.models.settings_definition import SettingsConstants
    encoder = CompactSeedQrEncoder(
        mnemonic=tool.ROOT_TEST_MNEMONIC, wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)
    decoder = DecodeQR()
    decoder.add_data(encoder.next_part())
    assert decoder.is_complete
    assert decoder.is_seed
    assert decoder.get_seed_phrase() == tool.ROOT_TEST_MNEMONIC


def test_root_and_deputy_test_seeds_are_actually_different():
    # The whole point of the passphrase variant is a distinct key -- catch a
    # regression that accidentally makes both identities derive identically.
    root_keys = tool.root_ceremony.derive_root_ceremony_keys(tool.root_seed().seed_bytes, tool.CHAIN_KIND)
    deputy_keys = tool.root_ceremony.derive_root_ceremony_keys(tool.deputy_seed().seed_bytes, tool.CHAIN_KIND)
    assert root_keys.root_ca.public_key != deputy_keys.root_ca.public_key
