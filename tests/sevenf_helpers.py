"""
    Test-only helpers for the 7F model. `root_ceremony.SevenFSeed` exists only
    for a 24-word English BIP-39 phrase (seed_for_7f); tests that pin key
    derivation from a fixed 64-byte seed vector use sevenf_seed_from_bytes,
    which skips the phrase check. Never used outside tests/.
"""
from seedsigner.models.sevenf import root_ceremony


def sevenf_seed_from_bytes(seed_bytes: bytes) -> root_ceremony.SevenFSeed:
    return root_ceremony.SevenFSeed._from_checked(root_ceremony._TOKEN, seed_bytes)
