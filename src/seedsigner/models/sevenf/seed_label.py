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
from seedsigner.models.sevenf.root_ceremony import NotA7FPhraseError, derive_root_ceremony_keys, seed_for_7f

LABEL_CHARS = 8
NOT_7F = "not 7F"   # a seed 7fchain would not derive from (not 24 English BIP-39 words)
_cache: dict[bytes, str] = {}


def sevenf_seed_label(seed) -> str:
    """ The label of a SeedSigner Seed in 7F mode, or NOT_7F. A device
        convention, not a 7fchain identifier: the device names a phrase by its
        testnet Root key at index 0, whatever network a flow later uses. """
    try:
        sevenf_seed = seed_for_7f(seed)
    except NotA7FPhraseError:
        return NOT_7F
    key = hashlib.sha256(sevenf_seed.seed_bytes).digest()
    label = _cache.get(key)
    if label is None:
        vk = derive_root_ceremony_keys(sevenf_seed, ChainKind.TESTNET, index=0).root_ca.public_key
        label = ski(vk.hex())[:LABEL_CHARS]
        _cache[key] = label
    return label
