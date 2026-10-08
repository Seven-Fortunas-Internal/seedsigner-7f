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


def test_scanner_page_explains_how_ski_and_pin_are_derived():
    """ Jorge asked (2026-10-07) for a very brief on-page note on how both
        values come from the vk, so a reader can recompute them. """
    from pathlib import Path
    html = (Path(TOOL_DIR) / "index.html").read_text()
    assert 'id="vkNote"' in html
    note = html.split('id="vkNote"', 1)[1].split("</p>", 1)[0]
    assert "SHA-256" in note
    assert "first 20 bytes" in note
    assert "RFC 7093" in note


@pytest.mark.parametrize("env, expected", [
    ("{hasSavePicker: true, canShareFiles: true}", "picker"),    # desktop Chrome/Edge: choose the folder
    ("{hasSavePicker: false, canShareFiles: true}", "share"),    # iPhone Safari: share sheet -> Save to Files / AirDrop
    ("{hasSavePicker: false, canShareFiles: false}", "download"),
])
def test_save_method_prefers_folder_picker_then_share_sheet_then_download(env, expected):
    out = _node(f"process.stdout.write(require('./bbqr-decode.js').saveMethod({env}));")
    assert out == expected


def test_scanner_page_offers_save_for_vk_results():
    from pathlib import Path
    html = (Path(TOOL_DIR) / "index.html").read_text()
    assert 'id="saveVk"' in html
    assert "BBQrDecode.saveMethod(" in html
    assert "application/octet-stream" in html  # iOS Safari appends .txt to text/plain downloads


def test_summary_file_is_the_bundle_with_a_phone_check_reminder():
    """ "Save summary" writes <ski>.txt next to the .vk: a record for the
        holder, never a substitute for confirming the pin by phone. """
    import hashlib
    vk = root_ceremony.derive_root_ceremony_keys(b"\x2a" * 64, ChainKind.TESTNET).root_ca.public_key
    digest = hashlib.sha256(vk).hexdigest()
    out = _node(f"require('./bbqr-decode.js').vkSummary('{vk.hex()}').then(r => process.stdout.write(JSON.stringify(r)));")
    import json
    summary = json.loads(out)
    assert summary["name"] == f"{digest[:40]}.txt"
    text = summary["text"]
    assert text.startswith("# ")
    assert "phone" in text.splitlines()[0]
    assert f"subject key id: {digest[:40]}\npin: {digest}\nfile: {digest[:40]}.vk\nvk: {vk.hex()}\n" in text


def test_scanner_page_offers_save_summary():
    from pathlib import Path
    html = (Path(TOOL_DIR) / "index.html").read_text()
    assert 'id="saveSummary"' in html
    assert "BBQrDecode.vkSummary(" in html


def _root_cert_envelope() -> str:
    from pathlib import Path
    from seedsigner.models.sevenf.export_envelope import pem_to_der, root_cert_export
    from embit.bip39 import mnemonic_to_seed
    pem = (Path("tests/fixtures/sf_wallet_gov_root_cert_abandon_art_testnet.pem")).read_text()
    vk = root_ceremony.derive_root_ceremony_keys(
        mnemonic_to_seed(" ".join(["abandon"] * 23 + ["art"]), password=""), ChainKind.TESTNET).root_ca.public_key
    return root_cert_export(pem_to_der(pem), vk).decode()


def _inspect(envelope_text: str) -> dict:
    import json
    js = f"require('./bbqr-decode.js').inspectExport({json.dumps(envelope_text)}).then(r => process.stdout.write(JSON.stringify(r)));"
    return json.loads(_node(js))


def test_inspect_export_accepts_a_device_root_cert_and_checks_its_name():
    from pathlib import Path
    r = _inspect(_root_cert_envelope())
    assert r["error"] is None
    assert r["kind"] == "root-cert"
    assert r["file"] == "root-591c511984a2d73c6bee1f4dc149d48f7f97fc55.pem"
    assert r["ski"] == "591c511984a2d73c6bee1f4dc149d48f7f97fc55"
    assert r["pin"] == "591c511984a2d73c6bee1f4dc149d48f7f97fc55ad607b821b91eca949f0641a"
    assert r["body"] == Path("tests/fixtures/sf_wallet_gov_root_cert_abandon_art_testnet.pem").read_text()


@pytest.mark.parametrize("change, needle", [
    (lambda e: {**e, "file": "root-" + "0" * 40 + ".pem"}, "does not match"),
    (lambda e: {**e, "file": "../root-591c511984a2d73c6bee1f4dc149d48f7f97fc55.pem"}, "file name"),
    (lambda e: {**e, "file": "x/y.pem"}, "file name"),
    (lambda e: {**e, "kind": "mystery"}, "kind"),
    (lambda e: {**e, "sf7_export": 2}, "version"),
    (lambda e: {**e, "body": "not a certificate"}, "certificate"),
])
def test_inspect_export_refuses_bad_envelopes(change, needle):
    import json
    bad = json.dumps(change(json.loads(_root_cert_envelope())))
    r = _inspect(bad)
    assert r["error"] and needle in r["error"]


def test_inspect_export_ignores_non_envelope_json():
    r = _inspect('{"signer_vk": "", "sig": "00"}')
    assert r is None


def test_scanner_page_handles_export_envelopes():
    from pathlib import Path
    html = (Path(TOOL_DIR) / "index.html").read_text()
    assert "BBQrDecode.inspectExport(" in html
    assert 'id="saveExport"' in html


def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + length + content


def _cert_with_decoy_key(real_vk: bytes, decoy_vk: bytes) -> bytes:
    """ A certificate-shaped DER whose issuer name hides a decoy
        "03 82 07 a1 00 + 1952 bytes" before the real SubjectPublicKeyInfo. """
    oid_ml_dsa_65 = bytes.fromhex("0609608648016503040312")
    alg = _der(0x30, oid_ml_dsa_65)
    spki = _der(0x30, alg + _der(0x03, b"\x00" + real_vk))
    issuer = _der(0x30, _der(0x04, _der(0x03, b"\x00" + decoy_vk)))
    tbs = _der(0x30,
               _der(0xA0, _der(0x02, b"\x02"))       # version v3
               + _der(0x02, b"\x40" + b"\x11" * 15)  # serial
               + alg + issuer
               + _der(0x30, b"")                     # validity (shape only)
               + _der(0x30, b"")                     # subject
               + spki)
    return _der(0x30, tbs + alg + _der(0x03, b"\x00" + b"\x55" * 10))


def test_cert_subject_vk_walks_the_der_and_ignores_a_decoy_key():
    import json
    real, decoy = b"\x01" * 1952, b"\x02" * 1952
    der = _cert_with_decoy_key(real, decoy)
    out = _node(f"""
const d = require('./bbqr-decode.js');
const der = Uint8Array.from(Buffer.from('{der.hex()}', 'hex'));
const vk = d.certSubjectVk(der);
process.stdout.write(vk ? Buffer.from(vk).toString('hex') : 'null');
""")
    assert out == real.hex()


def test_cert_subject_vk_refuses_a_non_ml_dsa_key():
    der = _cert_with_decoy_key(b"\x01" * 1952, b"\x02" * 1952).replace(
        bytes.fromhex("0609608648016503040312"), bytes.fromhex("0609608648016503040311"))
    out = _node(f"""
const d = require('./bbqr-decode.js');
process.stdout.write(String(d.certSubjectVk(Uint8Array.from(Buffer.from('{der.hex()}', 'hex')))));
""")
    assert out == "null"


@pytest.mark.parametrize("change, needle", [
    (lambda e: {**e, "body": "-----BEGIN CERTIFICATE-----\nA=A=\n-----END CERTIFICATE-----\n"}, "certificate"),
    (lambda e: {**e, "body": e["body"].replace("\n", "", 1).replace("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n", 1)[:0] + e["body"].replace("\n", "\n\n", 2)}, "canonical"),
    (lambda e: {**e, "file": "a" * 90 + ".pem"}, "file name"),
    (lambda e: {**e, "file": "root-..pem"}, "file name"),
])
def test_inspect_export_refuses_malformed_bodies_and_names(change, needle):
    import json
    r = _inspect(json.dumps(change(json.loads(_root_cert_envelope()))))
    assert r["error"] and needle in r["error"]
    assert isinstance(r["body"], str)  # the page can still show what it refused


def _sig_envelope(kind: str) -> str:
    from seedsigner.models.sevenf.export_envelope import signature_export
    return signature_export(kind, b"\x07" * 1952, bytes(range(256)) * 12 + bytes(3309 - 3072)).decode()


@pytest.mark.parametrize("kind", ["genesis", "devfund"])
def test_inspect_export_accepts_device_signatures(kind):
    import hashlib, json
    env = json.loads(_sig_envelope(kind))
    r = _inspect(json.dumps(env))
    assert r["error"] is None
    assert r["kind"] == f"{kind}-sig"
    assert r["file"] == f"{hashlib.sha256(b'\x07' * 1952).hexdigest()[:40]}.{kind}"
    assert r["ski"] == r["file"].split(".")[0]
    assert r["body"] == env["body"]


@pytest.mark.parametrize("change, needle", [
    (lambda e: {**e, "file": e["file"].replace(".genesis", ".devfund")}, "file name"),   # extension must match kind
    (lambda e: {**e, "file": "ABC.genesis"}, "file name"),
    (lambda e: {**e, "body": e["body"].replace('"sig": "', '"sig": "zz')}, "signature"),
    (lambda e: {**e, "body": e["body"].rstrip("\n")}, "canonical"),
    (lambda e: {**e, "body": '{\n  "signer_vk": "' + "11" * 1952 + '",\n  "sig": "' + "22" * 3309 + '"\n}\n'}, "does not match"),
])
def test_inspect_export_refuses_bad_signature_envelopes(change, needle):
    import json
    r = _inspect(json.dumps(change(json.loads(_sig_envelope("genesis")))))
    assert r["error"] and needle in r["error"]


def test_inspect_export_accepts_an_embedded_key_that_matches_the_name():
    import hashlib, json
    vk = b"\x07" * 1952
    env = json.loads(_sig_envelope("genesis"))
    env["body"] = json.dumps({"signer_vk": vk.hex(), "sig": "22" * 3309}, indent=2) + "\n"
    r = _inspect(json.dumps(env))
    assert r["error"] is None and r["file"].startswith(hashlib.sha256(vk).hexdigest()[:40])


@pytest.mark.parametrize("body", [
    '{\n  "signer_vk": "",\n  "sig": [\n    "' + "22" * 3309 + '"\n  ]\n}\n',  # RegExp.test would coerce the array
    '{\n  "signer_vk": [],\n  "sig": "' + "22" * 3309 + '"\n}\n',
])
def test_inspect_export_refuses_non_string_signature_fields(body):
    import json
    env = {**json.loads(_sig_envelope("genesis")), "body": body}
    r = _inspect(json.dumps(env))
    assert r["error"]


@pytest.mark.parametrize("kind", ["constructor", "toString", "__proto__"])
def test_inspect_export_refuses_inherited_property_names_as_kinds(kind):
    import json
    env = {**json.loads(_sig_envelope("genesis")), "kind": kind}
    r = _inspect(json.dumps(env))
    assert r["error"] and "unsupported export kind" in r["error"]


# A real `sf-wallet-gov sign-deputy-cert` output, issued by Root ski 255ef46a...
DEPUTY_ISSUER = "255ef46a87fe6a5607e1ce58f0cf5cce0bee3bae"


def _deputy_envelope(file=None) -> str:
    import json
    from pathlib import Path
    pem = Path("tests/fixtures/sf_wallet_gov_deputy_cert_issuer_255ef46a.pem").read_text()
    return json.dumps({"sf7_export": 1, "kind": "deputy-cert",
                       "file": file or f"deputy-{DEPUTY_ISSUER}.pem", "body": pem})


def test_inspect_export_accepts_a_deputy_cert_named_for_its_issuer():
    r = _inspect(_deputy_envelope())
    assert r["error"] is None
    assert r["issuer_ski"] == DEPUTY_ISSUER
    assert r["ski"] == "720573f1e72fed7c3c7f9aeaec504d3976287ea5"  # the Deputy's own key (e2e run)


def test_inspect_export_refuses_a_deputy_cert_named_for_another_root():
    r = _inspect(_deputy_envelope(file="deputy-" + "0" * 40 + ".pem"))
    assert r["error"] and "does not match" in r["error"]


@pytest.mark.parametrize("role, folder", [("root", "governance/root/outbox"), ("devfund", "governance/devfund/outbox")])
def test_inspect_export_accepts_role_tagged_vks_and_names_the_folder(role, folder):
    import hashlib, json
    from seedsigner.models.sevenf.export_envelope import vk_export
    vk = b"\x0b" * 1952
    r = _inspect(vk_export(role, vk).decode())
    assert r["error"] is None
    assert r["kind"] == f"{role}-vk"
    assert r["ski"] == hashlib.sha256(vk).hexdigest()[:40]
    assert r["pin"] == hashlib.sha256(vk).hexdigest()
    assert r["folder"] == folder


@pytest.mark.parametrize("change, needle", [
    (lambda e: {**e, "file": "0" * 40 + ".vk"}, "does not match"),
    (lambda e: {**e, "body": e["body"].rstrip("\n")}, "verification key"),
    (lambda e: {**e, "body": e["body"].upper()}, "verification key"),
])
def test_inspect_export_refuses_bad_vk_envelopes(change, needle):
    import json
    from seedsigner.models.sevenf.export_envelope import vk_export
    env = json.loads(vk_export("root", b"\x0b" * 1952))
    r = _inspect(json.dumps(change(env)))
    assert r["error"] and needle in r["error"]


def test_summary_records_the_role_when_known():
    import json
    vk = (b"\x0b" * 1952).hex()
    out = _node(f"require('./bbqr-decode.js').vkSummary('{vk}', 'devfund').then(r => process.stdout.write(JSON.stringify(r)));")
    assert "role: devfund" in json.loads(out)["text"]
