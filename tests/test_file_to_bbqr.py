"""
    tools/file_to_bbqr.py: turns a ceremony file on the host into the QR
    slideshow the device scans (the host-to-device half of the transfer
    tooling). Each real 7fchain artifact must round-trip through the device's
    own BBQr decoder and parser.
"""
import importlib.util
import json
from pathlib import Path

import pytest

from seedsigner.models.decode_qr import DecodeQR, DecodeQRStatus
from seedsigner.models.encode_qr import BBQrEncoder

FIXTURES = Path(__file__).parent / "fixtures"
spec = importlib.util.spec_from_file_location("file_to_bbqr", Path(__file__).parent.parent / "tools" / "file_to_bbqr.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


def _round_trip(payload: bytes, file_type: str) -> bytes:
    encoder = BBQrEncoder(data=payload, file_type=file_type, bbqr_encoding="Z")
    d = DecodeQR()
    for _ in range(encoder.seq_len()):
        status = d.add_data(encoder.next_part())
    assert status == DecodeQRStatus.COMPLETE and d.is_sevenf_bbqr
    return d.get_sevenf_bbqr_data()


def test_genesis_json_goes_as_json(tmp_path):
    from seedsigner.models.sevenf.genesis_config import parse_genesis_config_json
    from tools_helpers import REAL_GENESIS_JSON
    f = tmp_path / "genesis-unsigned.json"
    f.write_bytes(REAL_GENESIS_JSON)
    payload, file_type = tool.payload_for(f)
    assert file_type == "J"
    parse_genesis_config_json(_round_trip(payload, file_type))


def test_devfund_json_goes_as_json(tmp_path):
    from seedsigner.models.sevenf.devfund_config import parse_devfund_config_json
    from test_sevenf_devfund_config import REAL_DEVFUND_UNSIGNED_JSON
    f = tmp_path / "devfund-unsigned.json"
    f.write_bytes(REAL_DEVFUND_UNSIGNED_JSON)
    payload, file_type = tool.payload_for(f)
    assert file_type == "J"
    parse_devfund_config_json(_round_trip(payload, file_type))


def test_root_cert_pem_goes_as_der():
    from seedsigner.models.sevenf.cert_request import parse_root_certificate_der
    payload, file_type = tool.payload_for(FIXTURES / "sf_wallet_gov_root_cert_abandon_art_testnet.pem")
    assert file_type == "B"
    parse_root_certificate_der(_round_trip(payload, file_type))


def test_deputy_csr_pem_goes_as_der():
    from seedsigner.models.sevenf.cert_request import verify_and_parse_csr_der
    payload, file_type = tool.payload_for(FIXTURES / "sf_wallet_gov_deputy_csr.pem")
    assert file_type == "B"
    verify_and_parse_csr_der(_round_trip(payload, file_type))


@pytest.mark.parametrize("content", [b"not json, not pem", b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"])
def test_refuses_anything_else(tmp_path, content):
    f = tmp_path / "x.bin"
    f.write_bytes(content)
    with pytest.raises(ValueError):
        tool.payload_for(f)


def test_writes_a_slideshow(tmp_path):
    out = tool.write_bbqr_slideshow(FIXTURES / "sf_wallet_gov_root_cert_abandon_art_testnet.pem", tmp_path)
    assert out.name.endswith("_slideshow.html") and out.exists()
    assert len(list(out.parent.glob("*.png"))) > 1


def test_slideshow_escapes_the_file_name(tmp_path):
    """ The page is built from the file name: a hostile name must not inject markup. """
    evil = tmp_path / 'x<img src=x onerror=alert(1)><\\script>.json'
    evil.write_text('{"version": 1}')
    page = tool.write_bbqr_slideshow(evil, tmp_path).read_text()
    head, _, script = page.partition("<script>")
    assert "<img src=x" not in head and "&lt;img src=x" in head  # markup context escaped
    assert page.count("<script>") == 1 and script.count("</script>") == 1  # no breaking out of the script
