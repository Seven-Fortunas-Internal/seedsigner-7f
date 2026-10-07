"""
    Verifies tools/bbqr_web_scanner/bbqr-decode.js (the browser/Node BBQr
    assembly logic) against this app's own real BBQrEncoder output --
    catching drift between the JS port and the real Python implementation
    it was manually ported from. Requires Node (skips cleanly if absent,
    same convention as the mldsa7f-dependent tests).
"""
import json
import shutil
import subprocess

import pytest

from seedsigner.models.encode_qr import BBQrEncoder
from seedsigner.models.sevenf import genesis_config, mldsa, root_ceremony
from seedsigner.models.sevenf.constants import ChainKind

TOOL_DIR = "tools/bbqr_web_scanner"


def _lib_available() -> bool:
    try:
        mldsa._lib_handle()
        return True
    except FileNotFoundError:
        return False


pytestmark = pytest.mark.skipif(
    shutil.which("node") is None or not _lib_available(),
    reason="requires both node and a built firmware/mldsa7f (`cargo build --release`)",
)


def _decode_via_node(segments: list[str], tmp_path) -> bytes:
    segments_path = tmp_path / "segments.json"
    segments_path.write_text(json.dumps(segments))
    result = subprocess.run(
        ["node", "decode_cli.js", str(segments_path)],
        cwd=TOOL_DIR, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    return bytes.fromhex(result.stdout)


def test_decodes_a_real_single_part_bbqr_payload(tmp_path):
    payload = b'{"hello": "world"}'
    encoder = BBQrEncoder(data=payload, file_type="J", bbqr_encoding="Z")
    segments = [encoder.next_part() for _ in range(encoder.seq_len())]
    assert _decode_via_node(segments, tmp_path) == payload


def test_decodes_a_real_multi_part_bbqr_payload_out_of_order(tmp_path):
    # A real genesis-config signature export -- large enough to span
    # multiple BBQr parts, exactly the case that matters for the scanner.
    root_keys = root_ceremony.derive_root_ceremony_keys(b"\x2a" * 64, ChainKind.TESTNET)
    payload = json.dumps(genesis_config.build_root_sig_json(
        root_keys.root_ca.public_key, b"\x11" * 3309, with_vk=True,
    )).encode("utf-8")
    encoder = BBQrEncoder(data=payload, file_type="J", bbqr_encoding="Z")
    segments = [encoder.next_part() for _ in range(encoder.seq_len())]
    assert len(segments) > 1, "test payload should need multiple BBQr parts"

    shuffled = list(reversed(segments))  # part order must not matter
    assert _decode_via_node(shuffled, tmp_path) == payload


def test_root_id_matches_the_real_python_port():
    """ Found live 2026-10-07 during a real testnet Root VK enrollment:
        Jorge asked for root_id() in the scanner page so he and Patrick can
        independently cross-check a scanned vk against the device's own
        "Subject key id" screen. This locks the JS port (bbqr-decode.js's
        rootId(), Web Crypto SHA-256) against the real Python implementation
        (review_format.root_id(), already verified against 7fchain's real
        sf-core::genesis_config::root_id()) for an actual derived key, not a
        synthetic fixture. """
    import subprocess

    from seedsigner.models.sevenf.review_format import root_id

    root_keys = root_ceremony.derive_root_ceremony_keys(b"\x2a" * 64, ChainKind.TESTNET)
    vk_hex = root_keys.root_ca.public_key.hex()
    expected = root_id(vk_hex)

    result = subprocess.run(
        ["node", "-e", f"""
const {{ rootId }} = require('./bbqr-decode.js');
rootId('{vk_hex}').then(r => process.stdout.write(r));
"""],
        cwd=TOOL_DIR, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected


def test_rejects_an_inconsistent_sequence(tmp_path):
    payload_a = BBQrEncoder(data=b"AAAA" * 200, file_type="J", bbqr_encoding="Z")
    payload_b = BBQrEncoder(data=b"BBBB" * 200, file_type="B", bbqr_encoding="Z")
    mixed = [payload_a.next_part(), payload_b.next_part()]
    segments_path = tmp_path / "segments.json"
    segments_path.write_text(json.dumps(mixed))
    result = subprocess.run(
        ["node", "decode_cli.js", str(segments_path)],
        cwd=TOOL_DIR, capture_output=True, text=True,
    )
    assert result.returncode != 0
