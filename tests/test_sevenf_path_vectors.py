"""
    7fchain's own path-to-key vectors (crates/sf-keytree/tests/path_vectors.rs,
    7fchain 06a47ba), checked through the whole device stack: SeedSigner's
    BIP-39 seed for the canonical "abandon x23 art" phrase, then the device's
    FFI derivation. The file says the device "checks itself against" these.
    Pins are the first 64 hex characters of each 3,904-hex key, as upstream.
"""
import pytest

from seedsigner.models.seed import Seed
from seedsigner.models.sevenf import mldsa

PHRASE = ["abandon"] * 23 + ["art"]

# Copied from path_vectors.rs:146-152 at 06a47ba.
VECTORS = {
    "root/testnet/0/ml-dsa/v1": "cf7586cee76af9b1447b0fb77432c06e71fcf9a43d3a232bf9a496e94ac807a6",
    "miner/testnet/0/ml-dsa/v1/hot": "a1b10faf25fb88945344e60dd257a9cbbea38dd4bc8f23f99a6c25a8868a9413",
    "miner/testnet/0/ml-dsa/v1/block-reward": "6ff173512475a800f3e266600c41e62866854473d1440a75bfda5d67179f8962",
    "wallet/testnet/0/ml-dsa/v1": "2bc5bd20444cb832e24542f745b6986d183a1e9ff218c59663e66e71b58b278b",
    "l2-wallet/testnet/1/0/ml-dsa/v1": "51c81e15aaab952500808d9312f660fcbe649fb6833a5a725efbd719df481b32",
    "deputy/testnet/0/ml-dsa/v1": "3cbd07f029fc5cf2af10e9e4410769b0845d51afcefbec9ceb54dbfb2b4090ab",
    "centcom/testnet/0/ml-dsa/v1": "a9fe4c4d56df5546d52bf978cd13347c7a394b89922504feda834c8a963cb389",
}


@pytest.mark.parametrize("path,pin", sorted(VECTORS.items()))
def test_7fchain_path_vector(path, pin):
    vk, _address = mldsa.derive_pubkey(Seed(PHRASE).seed_bytes, path)
    assert vk.hex()[:64] == pin
