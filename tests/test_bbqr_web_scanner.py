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


def test_ski_matches_the_real_python_port():
    """ Locks the scanner's JS ski() (Web Crypto SHA-256, first 20 bytes)
        against review_format.ski() for an actual derived key, so a vk scanned
        on a phone shows the same subject key id the device screen and
        sf-wallet-gov print (7fchain ce04ae9/416f576). """
    import subprocess

    from seedsigner.models.sevenf.review_format import ski

    root_keys = root_ceremony.derive_root_ceremony_keys(b"\x2a" * 64, ChainKind.TESTNET)
    vk_hex = root_keys.root_ca.public_key.hex()
    expected = ski(vk_hex)

    result = subprocess.run(
        ["node", "-e", f"""
const {{ ski }} = require('./bbqr-decode.js');
ski('{vk_hex}').then(r => process.stdout.write(r));
"""],
        cwd=TOOL_DIR, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected
    assert len(result.stdout) == 40


def test_scanner_page_labels_the_id_as_subject_key_id_only():
    """ The old "(root_id)" suffix named the retired 20-hex id. """
    from pathlib import Path
    html = (Path(TOOL_DIR) / "index.html").read_text()
    assert "root_id" not in html
    assert "rootId" not in html
    assert "Subject key id:" in html


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


def _node(js: str) -> str:
    result = subprocess.run(["node", "-e", js], cwd=TOOL_DIR, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return result.stdout


def test_pin_is_the_full_sha256_of_the_raw_vk():
    """ 7fchain's x509::vk_pin() -- Sha256::digest(vk), 64 hex -- is the "root
        pin" a federation member reports over a second channel (ceremony-
        federation-member.md Step 4). Expected computed with hashlib, not the
        code under test. """
    import hashlib

    vk = root_ceremony.derive_root_ceremony_keys(b"\x2a" * 64, ChainKind.TESTNET).root_ca.public_key
    out = _node(f"require('./bbqr-decode.js').pin('{vk.hex()}').then(r => process.stdout.write(r));")
    assert out == hashlib.sha256(vk).hexdigest()


def test_pin_and_ski_match_real_sf_wallet_gov_for_the_canonical_phrase():
    """ `sf-wallet-gov sign-root-cert --index 0` at 7fchain 416f576 on
        "abandon x23 art" (testnet, empty passphrase) printed exactly these;
        the ski is the pin's first 40 hex. """
    from embit.bip39 import mnemonic_to_seed

    seed = mnemonic_to_seed(" ".join(["abandon"] * 23 + ["art"]), password="")
    vk_hex = root_ceremony.derive_root_ceremony_keys(seed, ChainKind.TESTNET).root_ca.public_key.hex()
    out = _node(f"""
const d = require('./bbqr-decode.js');
Promise.all([d.ski('{vk_hex}'), d.pin('{vk_hex}')]).then(([s, p]) => process.stdout.write(s + ' ' + p));
""")
    assert out == ("591c511984a2d73c6bee1f4dc149d48f7f97fc55 "
                   "591c511984a2d73c6bee1f4dc149d48f7f97fc55ad607b821b91eca949f0641a")


def test_vk_bundle_carries_ski_pin_and_vk_with_sf_wallet_gov_labels():
    """ "Copy all" puts everything a member hands the coordinator for one key
        in one paste: the ski (file name / voice check), the pin (second-
        channel check) and the vk itself. Labels match what sf-wallet-gov
        prints, so the two can be compared line by line. """
    vk = root_ceremony.derive_root_ceremony_keys(b"\x2a" * 64, ChainKind.TESTNET).root_ca.public_key
    import hashlib
    digest = hashlib.sha256(vk).hexdigest()
    out = _node(f"require('./bbqr-decode.js').vkBundle('{vk.hex().upper()}').then(r => process.stdout.write(r));")
    assert out == (
        f"subject key id: {digest[:40]}\n"
        f"pin: {digest}\n"
        f"file: {digest[:40]}.vk\n"
        f"vk: {vk.hex()}\n"
    )


def test_vk_bundle_rejects_non_hex():
    out = _node("require('./bbqr-decode.js').vkBundle('not hex').then(r => process.stdout.write(String(r)));")
    assert out == "null"


def test_scanner_page_offers_copy_all_and_shows_the_pin():
    from pathlib import Path
    html = (Path(TOOL_DIR) / "index.html").read_text()
    assert 'id="copyAll"' in html
    assert "BBQrDecode.vkBundle(" in html
    assert "BBQrDecode.pin(" in html
