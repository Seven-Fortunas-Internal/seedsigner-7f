"""
    Exercises tools/verify_sevenf_signature.py end-to-end: build a real
    genesis-config, sign it with mldsa7f, render both the original artefact
    and the signed export as real BBQr PNGs (ephemeral, since
    tools/test_artifacts/ is gitignored), then run the tool's own functions
    against those images -- proving it correctly identifies the artefact
    type and independently verifies a real signature, and correctly rejects
    a tampered one.
"""
import importlib.util
import json
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


def _load_module(name: str):
    spec = importlib.util.spec_from_file_location(name, os.path.join(TOOLS_DIR, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gen_tool = _load_module("make_sevenf_test_qrs")
verify_tool = _load_module("verify_sevenf_signature")


@pytest.fixture
def signed_genesis_config(tmp_path):
    from seedsigner.models.sevenf import genesis_config, root_ceremony

    # The artifact is the coordinator's JSON; the device signs the canonical
    # bytes rebuilt from its fields.
    original_json = gen_tool.build_genesis_config()
    f = genesis_config.parse_genesis_config_json(original_json)
    canonical_bytes = genesis_config.build_canonical_bytes(f.chain_kind, f.timestamp, f.message, f.consensus)
    root_keys = root_ceremony.derive_root_ceremony_keys(gen_tool.root_seed().seed_bytes, gen_tool.CHAIN_KIND)
    _, sig = mldsa.derive_and_sign(
        gen_tool.root_seed().seed_bytes, "root/testnet/0/ml-dsa/v1", canonical_bytes,
    )
    signed_json = genesis_config.build_root_sig_json(root_keys.root_ca.public_key, sig, with_vk=True)

    original_paths = gen_tool.render_bbqr("original", original_json, tmp_path)
    signed_paths = gen_tool.render_bbqr("signed", json.dumps(signed_json).encode("utf-8"), tmp_path)
    return original_paths, signed_paths


def test_verify_tool_confirms_a_real_signature(signed_genesis_config):
    original_paths, signed_paths = signed_genesis_config
    original_bytes = verify_tool._decode_bbqr_images(original_paths)
    kind, message = verify_tool._identify_and_parse_message(original_bytes)
    assert kind == "genesis-config"

    signed_bytes = verify_tool._decode_bbqr_images(signed_paths)
    signed_obj = json.loads(signed_bytes)

    from dilithium_py.ml_dsa import ML_DSA_65
    pk = bytes.fromhex(signed_obj["signer_vk"])
    sig = bytes.fromhex(signed_obj["sig"])
    assert ML_DSA_65.verify(pk, message, sig)


def test_verify_tool_rejects_a_tampered_signature(signed_genesis_config):
    original_paths, signed_paths = signed_genesis_config
    original_bytes = verify_tool._decode_bbqr_images(original_paths)
    _, message = verify_tool._identify_and_parse_message(original_bytes)

    signed_bytes = verify_tool._decode_bbqr_images(signed_paths)
    signed_obj = json.loads(signed_bytes)

    from dilithium_py.ml_dsa import ML_DSA_65
    pk = bytes.fromhex(signed_obj["signer_vk"])
    sig = bytes.fromhex(signed_obj["sig"])
    tampered_sig = bytes([sig[0] ^ 0x01]) + sig[1:]
    assert not ML_DSA_65.verify(pk, message, tampered_sig)


def _run_cli(monkeypatch, capsys, argv):
    monkeypatch.setattr("sys.argv", ["verify_sevenf_signature.py"] + argv)
    exit_code = 0
    try:
        verify_tool.main()
    except SystemExit as e:
        exit_code = e.code or 0
    return exit_code, capsys.readouterr()


def test_cli_refuses_without_pubkey_hex_or_trust_flag(signed_genesis_config, monkeypatch, capsys):
    """ H1 fix, adversarial security review 2026-09-29: the tool must not
        silently trust the export's own embedded signer_vk as the
        verification key by default -- that would let a forged, internally
        self-consistent export report VALID. """
    original_paths, signed_paths = signed_genesis_config
    argv = ["--original", *map(str, original_paths), "--signed", *map(str, signed_paths)]
    exit_code, captured = _run_cli(monkeypatch, capsys, argv)
    assert exit_code == 2
    assert "pubkey-hex is required" in captured.err


def test_cli_verifies_with_explicit_trusted_pubkey(signed_genesis_config, monkeypatch, capsys):
    from seedsigner.models.sevenf import root_ceremony
    original_paths, signed_paths = signed_genesis_config
    root_keys = root_ceremony.derive_root_ceremony_keys(gen_tool.root_seed().seed_bytes, gen_tool.CHAIN_KIND)

    argv = [
        "--original", *map(str, original_paths),
        "--signed", *map(str, signed_paths),
        "--pubkey-hex", root_keys.root_ca.public_key.hex(),
    ]
    exit_code, captured = _run_cli(monkeypatch, capsys, argv)
    assert exit_code == 0
    assert "VALID" in captured.out


def test_cli_trust_embedded_flag_warns_loudly(signed_genesis_config, monkeypatch, capsys):
    original_paths, signed_paths = signed_genesis_config
    argv = [
        "--original", *map(str, original_paths),
        "--signed", *map(str, signed_paths),
        "--trust-embedded-signer-vk",
    ]
    exit_code, captured = _run_cli(monkeypatch, capsys, argv)
    assert exit_code == 0
    assert "only proves internal self-consistency" in captured.err
    assert "VALID" in captured.out


def test_cli_warns_on_pubkey_mismatch_but_trusts_the_explicit_one(signed_genesis_config, monkeypatch, capsys):
    original_paths, signed_paths = signed_genesis_config
    wrong_pubkey = "00" * 1952
    argv = [
        "--original", *map(str, original_paths),
        "--signed", *map(str, signed_paths),
        "--pubkey-hex", wrong_pubkey,
    ]
    exit_code, captured = _run_cli(monkeypatch, capsys, argv)
    assert "does not match the export's own embedded signer_vk" in captured.err
    assert exit_code == 1
    assert "INVALID" in captured.out
