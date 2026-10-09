"""
    tools/bbqr_web_scanner/bbqr-encode.js: the web page's "To device" half.
    Every ceremony file must produce exactly the BBQr parts tools/file_to_bbqr.py
    sends, the device's own decoder and parser must accept them, and each
    drawn QR must scan back to its part. Requires Node (skips if absent).
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from PIL import Image
from pyzbar import pyzbar

from seedsigner.models.decode_qr import DecodeQR, DecodeQRStatus
from seedsigner.models.encode_qr import BBQrEncoder
from seedsigner.models.sevenf import cert_request, review_format
from seedsigner.models.sevenf.devfund_config import parse_devfund_config_json
from seedsigner.models.sevenf.genesis_config import parse_genesis_config_json
from test_file_to_bbqr import tool as file_to_bbqr
from test_sevenf_devfund_config import REAL_DEVFUND_UNSIGNED_JSON
from tools_helpers import REAL_GENESIS_JSON
from sevenf_helpers import requires_mldsa7f

TOOL_DIR = Path("tools/bbqr_web_scanner")
FIXTURES = Path(__file__).parent / "fixtures"
ROOT_CERT = FIXTURES / "sf_wallet_gov_root_cert_abandon_art_testnet.pem"
DEPUTY_CSR = FIXTURES / "sf_wallet_gov_deputy_csr.pem"
DEPUTY_CERT = FIXTURES / "sf_wallet_gov_deputy_cert_issuer_255ef46a.pem"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="requires node")


def _encode(path: Path, *flags: str) -> dict:
    result = subprocess.run(
        ["node", "encode_cli.js", str(path.resolve()), *flags],
        cwd=TOOL_DIR, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _python_parts(path: Path) -> list[str]:
    payload, file_type = file_to_bbqr.payload_for(path)
    encoder = BBQrEncoder(data=payload, file_type=file_type, bbqr_encoding="Z")
    return [encoder.next_part() for _ in range(encoder.seq_len())]


def _device_decode(parts: list[str]) -> bytes:
    d = DecodeQR()
    for part in reversed(parts):  # any order, as the camera sees them
        status = d.add_data(part)
    assert status == DecodeQRStatus.COMPLETE and d.is_sevenf_bbqr
    return d.get_sevenf_bbqr_data()


@pytest.fixture
def genesis_file(tmp_path):
    f = tmp_path / "genesis-unsigned.json"
    f.write_bytes(REAL_GENESIS_JSON)
    return f


@pytest.fixture
def devfund_file(tmp_path):
    f = tmp_path / "devfund-unsigned.json"
    f.write_bytes(REAL_DEVFUND_UNSIGNED_JSON)
    return f


def test_genesis_config_matches_the_python_tool_and_the_device_parses_it(genesis_file):
    out = _encode(genesis_file)
    assert out["kind"] == "genesis-config" and out["fileType"] == "J"
    assert out["parts"] == _python_parts(genesis_file)
    parse_genesis_config_json(_device_decode(out["parts"]))


def test_devfund_config_matches_the_python_tool_and_the_device_parses_it(devfund_file):
    out = _encode(devfund_file)
    assert out["kind"] == "devfund-config" and out["fileType"] == "J"
    assert out["parts"] == _python_parts(devfund_file)
    parsed = parse_devfund_config_json(_device_decode(out["parts"]))
    fields = dict(out["fields"])
    assert fields["Recipient (receives the ENTIRE genesis reward)"].replace(" ", "") == parsed.recipient.payload


@requires_mldsa7f
def test_root_cert_goes_as_der_and_shows_its_ski():
    out = _encode(ROOT_CERT)
    assert out["kind"] == "root-cert" and out["fileType"] == "B"
    assert out["parts"] == _python_parts(ROOT_CERT)
    parsed = cert_request.parse_root_certificate_der(_device_decode(out["parts"]))
    shown = dict(out["fields"])["Root subject key id"].replace(" ", "")
    assert shown == review_format.ski(parsed.subject_vk.hex())


@requires_mldsa7f
def test_deputy_csr_goes_as_der_and_shows_the_deputy_ski():
    out = _encode(DEPUTY_CSR)
    assert out["kind"] == "deputy-csr" and out["fileType"] == "B"
    assert out["parts"] == _python_parts(DEPUTY_CSR)
    parsed = cert_request.verify_and_parse_csr_der(_device_decode(out["parts"]))
    shown = dict(out["fields"])["Deputy subject key id (confirm by voice)"].replace(" ", "")
    assert shown == review_format.ski(parsed.subject_vk.hex())


def test_each_drawn_qr_scans_back_to_its_part(devfund_file):
    out = _encode(devfund_file, "--matrix")
    for part, rows in zip(out["parts"], out["matrices"], strict=True):
        scale, border = 4, 4
        side = (len(rows) + 2 * border) * scale
        img = Image.new("L", (side, side), 255)
        for r, row in enumerate(rows):
            for c, bit in enumerate(row):
                if bit == "1":
                    x, y = (c + border) * scale, (r + border) * scale
                    img.paste(0, (x, y, x + scale, y + scale))
        decoded = pyzbar.decode(img)
        assert [d.data.decode() for d in decoded] == [part]


@pytest.mark.parametrize("content, reason", [
    (b"not json, not pem", "not a genesis or dev-fund config"),
    (b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", "not a genesis or dev-fund config"),
    (b'{"version": 1}', "not a genesis or dev-fund config"),
    (b"{not json", "not valid JSON"),
    (b"", "empty"),
    ("{\"message\": \"café\"}".encode(), "not plain text"),
    (b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n", "not valid base64"),
    (b"-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n", "not an ML-DSA-65 certificate request"),
])
def test_refuses_anything_the_device_does_not_scan(tmp_path, content, reason):
    f = tmp_path / "x.txt"
    f.write_bytes(content)
    assert reason in _encode(f)["error"]


@pytest.mark.parametrize("content", [
    b'{"version": 2, "network": "testnet", "recipient": {"kind": "multisig", "commitment": "ab"}, "effective_block": 9007199254740993, "timestamp": 1}',
    b'{"version": 2, "network": "testnet", "recipient": {"kind": "multisig", "commitment": "ab"}, "effective_block": 1.0, "timestamp": 1}',
    b'{"version": 2, "network": "testnet", "recipient": {"kind": "multisig", "commitment": "ab"}, "effective_block": 1e3, "timestamp": 1}',
    b'{"version": 2, "network": {"x": 1}, "recipient": {"kind": "multisig", "commitment": "ab"}, "effective_block": 0, "timestamp": 1}',
    b'{"version": 1, "chain_kind": "testnet", "timestamp": 1, "message": "m", "derivation_scheme": "s", "consensus": {"target_block_time_secs": 4.2e2}}',
])
def test_refuses_a_config_it_could_not_show_exactly(tmp_path, content):
    """ The summary must read exactly as the bytes sent: no rounding, no [object Object]. """
    f = tmp_path / "x.json"
    f.write_bytes(content)
    assert "not sent as shown" in _encode(f)["error"]


def test_refuses_an_oversized_file(tmp_path):
    f = tmp_path / "big.json"
    f.write_bytes(b'{"consensus": {}, "pad": "' + b"a" * 70000 + b'"}')
    assert "ceremony files are under" in _encode(f)["error"]


def test_refuses_a_deputy_certificate_in_place_of_a_root_certificate():
    """ Cross-Certify Deputy's first scan is the issuing Root's own certificate. """
    assert "not a Root self-certificate" in _encode(DEPUTY_CERT)["error"]


def test_page_writes_file_content_as_text_only():
    """ Names and fields come from the chosen file: never parsed as markup. """
    for name in ("app-send.js", "app.js", "bbqr-encode.js"):
        assert ".innerHTML" not in (TOOL_DIR / name).read_text()


def test_page_loads_only_its_own_scripts():
    html = (TOOL_DIR / "index.html").read_text()
    assert "script-src 'self'" in html and "<script>" not in html and "style=" not in html
