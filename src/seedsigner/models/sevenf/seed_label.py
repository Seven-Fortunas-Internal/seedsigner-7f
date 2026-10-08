"""
    The short label a seed is shown by in 7F mode: the first 8 hex of its
    testnet Root subject key id (Jorge, 2026-10-07). Stock SeedSigner shows the
    BIP-32 fingerprint instead -- the first 4 bytes of HASH160 of the
    secp256k1 master public key -- which has no relationship to any 7F key.
    The testnet Root ski is what holders and the coordinator compare in the
    current ceremony; a mainnet setting could switch it later.

    Deriving an ML-DSA-65 key takes a moment on a Pi Zero, so each label is
    cached in memory (keyed by a hash of the seed bytes, never the bytes
    themselves) for the life of the process.
"""
import hashlib

from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.models.sevenf.review_format import ski
from seedsigner.models.sevenf.root_ceremony import derive_root_ceremony_keys

LABEL_CHARS = 8
_cache: dict[bytes, str] = {}


def sevenf_seed_label(seed_bytes: bytes) -> str:
    key = hashlib.sha256(seed_bytes).digest()
    label = _cache.get(key)
    if label is None:
        vk = derive_root_ceremony_keys(seed_bytes, ChainKind.TESTNET, index=0).root_ca.public_key
        label = ski(vk.hex())[:LABEL_CHARS]
        _cache[key] = label
    return label
