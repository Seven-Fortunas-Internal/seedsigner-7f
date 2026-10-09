"""
    Constants for the 7fchain Root ceremony (docs/7f-integration/root-key-ceremony-plan.md).

    Values here mirror firmware/mldsa7f's own constants and the real 7fchain
    code they were ported from (sf-crypto/src/ml_dsa.rs, sf-crypto/src/address.rs,
    sf-keytree/src/path.rs) -- kept in sync manually, not generated. Paths are
    built by 7fchain's own code over the FFI (path_lexicon.py).
"""
from dataclasses import dataclass
from enum import IntEnum


class ChainKind(IntEnum):
    """ Matches sf-crypto/src/address.rs's ChainKind (re-exported by
        sf-core's genesis_config) and the chain-kind byte
        firmware/mldsa7f/src/ffi.rs's decode_chain_kind() expects. """
    MAINNET = 0
    TESTNET = 1
    DEVNET = 2

    @property
    def path_segment(self) -> str:
        """ The literal string used inside a 7fchain derivation path, e.g.
            "root/testnet/0/ml-dsa/v1" -- confirmed against
            crates/sf-keytree/src/path.rs's `ChainKind::as_str()`. """
        return self.name.lower()


# ML-DSA-65 sizes, confirmed against firmware/mldsa7f/src/ml_dsa.rs's own
# constants (which mirror fips204::ml_dsa_65::{PK_LEN,SK_LEN,SIG_LEN}).
ML_DSA_PK_LEN = 1952
ML_DSA_SIG_LEN = 3309

# Every 7fchain address is exactly this many ASCII characters.
ADDRESS_LEN = 49

# SeedSigner's Seed.seed_bytes is always this long: standard BIP-39,
# bip39.mnemonic_to_seed()'s PBKDF2-HMAC-SHA512 output (models/seed.py).
MASTER_SEED_LEN = 64

# A key index is a u32 in 7fchain (sf-keytree path.rs: `pub index: u32`);
# sf-wallet-gov accepts 0..=4294967295 and refuses anything else. No value is
# reserved for any operation (docs/7f-integration/root-key-index-selector-plan.md).
MAX_KEY_INDEX = 2**32 - 1


def key_index_segment(index: int) -> str:
    """ The index as it appears in a path: canonical decimal, as 7fchain's
        `path_for` writes it (`u32::to_string`). The path string is what gets
        hashed, so "007" and "7" would be two different keys; only an int in
        range is accepted, never a string or a bool. """
    if isinstance(index, bool) or not isinstance(index, int):
        raise TypeError(f"key index must be an int, got {type(index).__name__}")
    if not 0 <= index <= MAX_KEY_INDEX:
        raise ValueError(f"key index must be 0 to {MAX_KEY_INDEX}, got {index}")
    return str(index)


def parse_key_index_entry(text: str) -> int:
    """ An index typed on the device's digits keypad: a strict subset of
        what sf-wallet-gov accepts for `--index` (Rust `str::parse::<u32>`,
        which also takes a leading "+"): ASCII digits only, leading zeros
        allowed ("007" is 7), 0 to MAX_KEY_INDEX. Raises
        ValueError otherwise. Python's int() and str.isdigit() also accept
        non-ASCII digits, spaces and signs, so they are not used on their own. """
    if not isinstance(text, str):
        raise TypeError(f"key index entry must be text, got {type(text).__name__}")
    if not text or any(c not in "0123456789" for c in text):
        raise ValueError(f"key index must be digits 0-9, got {text!r}")
    index = int(text)
    key_index_segment(index)  # range check
    return index


@dataclass(frozen=True)
class DerivedKey:
    """ One derived ML-DSA-65 key. A CA key has no address (sf-wallet-gov
        prints none for one), so none is carried. """
    public_key: bytes
