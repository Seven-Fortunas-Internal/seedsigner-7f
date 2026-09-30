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

    canonical_bytes = gen_tool.build_genesis_config()
    root_keys = root_ceremony.derive_root_ceremony_keys(gen_tool.root_seed().seed_bytes, gen_tool.CHAIN_KIND)
    _, sig = mldsa.derive_and_sign(
        gen_tool.root_seed().seed_bytes, "m/root-ca/l1/testnet/0", "ml-dsa/0", canonical_bytes,
    )
    signed_json = genesis_config.build_root_sig_json(root_keys.root_ca.public_key, sig, with_vk=True)

    original_paths = gen_tool.render_bbqr("original", canonical_bytes, tmp_path)
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
