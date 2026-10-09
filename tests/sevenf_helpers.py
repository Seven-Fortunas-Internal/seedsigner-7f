"""
    Test-only helpers for the 7F model. `root_ceremony.SevenFSeed` exists only
    for a 24-word English BIP-39 phrase (seed_for_7f); tests that pin key
    derivation from a fixed 64-byte seed vector use sevenf_seed_from_bytes,
    which skips the phrase check. Never used outside tests/.
"""
from seedsigner.models.sevenf import root_ceremony


def sevenf_seed_from_bytes(seed_bytes: bytes) -> root_ceremony.SevenFSeed:
    return root_ceremony.SevenFSeed._from_checked(root_ceremony._TOKEN, seed_bytes)


def _mldsa7f_available() -> bool:
    from seedsigner.models.sevenf import mldsa
    try:
        mldsa._lib_handle()
        return True
    except FileNotFoundError:
        return False


# For a test that calls the Rust library: in this repo's own CI the library
# (built in the parent repo, firmware/mldsa7f) is absent, so it is skipped.
import os  # noqa: E402

import pytest  # noqa: E402

requires_mldsa7f = pytest.mark.skipif(
    os.environ.get("SEVENF_REQUIRE_MLDSA7F") != "1" and not _mldsa7f_available(),
    reason="firmware/mldsa7f not built -- run `cargo build --release` in firmware/mldsa7f/ first",
)
