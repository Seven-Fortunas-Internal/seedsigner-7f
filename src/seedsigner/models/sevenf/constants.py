"""
    Constants for the 7fchain Root ceremony (docs/7f-integration/root-key-ceremony-plan.md).

    Values here mirror firmware/mldsa7f's own constants and the real 7fchain
    code they were ported from (sf-crypto/src/ml_dsa.rs, sf-crypto/src/address.rs,
    sf-keytree/src/bin/sf-root.rs) -- kept in sync manually, not generated.
"""
from dataclasses import dataclass
from enum import IntEnum


class ChainKind(IntEnum):
    """ Matches sf-core::genesis_config::ChainKind and the `network` byte
        firmware/mldsa7f/src/ffi.rs's decode_network() expects. """
    MAINNET = 0
    TESTNET = 1
    DEVNET = 2

    @property
    def path_segment(self) -> str:
        """ The literal string used inside a 7fchain derivation path, e.g.
            "root/testnet/0/ml-dsa/v1" -- confirmed against
            crates/sf-keytree/src/path.rs's `ChainKind::as_str()`. """
        return self.name.lower()


class Layer(IntEnum):
    """ Matches the `layer` byte firmware/mldsa7f/src/ffi.rs's decode_layer()
        expects. The Root ceremony only ever uses L1. """
    L1 = 0
    L2 = 1


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


def root_path(chain_kind: ChainKind, index: int = 0) -> str:
    """ e.g. "root/testnet/0/ml-dsa/v1", built by 7fchain's own
        `path::path_for(Role::Root, chain_kind, index)` over the FFI (the
        verbatim port in firmware/mldsa7f), never written by hand here.

        RE-PORTED 2026-10-03 (R27): 7fchain collapsed its two-level
        `purpose_path`/`role_path` grammar into this single combined path
        -- see firmware/mldsa7f/src/derive.rs's doc comment for why. This
        single function replaces the old `root_ca_purpose_path()`,
        `devfund_purpose_path()`, and the separate `ML_DSA_LEAF_ROLE`
        constant: `sf-root.rs`'s own `cmd_sign_genesis` and
        `cmd_sign_devfund` both call the byte-identical
        `root_key_from_file(...)` at the same index -- genesis-config and
        devfund-config are signed by the SAME Root key, not two -- so the
        devfund-config SIGNING key is this path. The per-holder dev-fund key
        a member enrolls is a different key at devfund_path() below (7fchain
        89d3d39, 2026-10-05). `index` is sf-wallet-gov's `--index`, default 0
        (7f-signing-support-key-index-selector); our practice is one phrase per
        Root key at index 0. """
    key_index_segment(index)  # type and range: a ctypes u32 would wrap
    from seedsigner.models.sevenf import mldsa  # mldsa imports this module
    return mldsa.path_for("root", chain_kind, index)


def devfund_path(chain_kind: ChainKind, index: int = 0) -> str:
    """ e.g. "devfund/testnet/0/ml-dsa/v1", built by 7fchain's own
        `path_for(Role::Devfund, chain_kind, index)` over the FFI (89d3d39): the
        dev fund is locked by nine devfund keys, one per federation holder,
        derived from the same phrase as that holder's Root at this different
        path, so a dev-fund signature isn't attributable to a known Root.
        This is the key a member enrolls (sf-wallet-gov `derive-vk --role
        devfund`). It does NOT sign the devfund-config -- the Roots still
        declare the recipient with the Root key (root_path above). `index` is
        sf-wallet-gov's `--index`, default 0; 7fchain calls a later index a
        rotation (open question on 7fchain#7). """
    key_index_segment(index)  # type and range: a ctypes u32 would wrap
    from seedsigner.models.sevenf import mldsa  # mldsa imports this module
    return mldsa.path_for("devfund", chain_kind, index)


@dataclass(frozen=True)
class DerivedKey:
    """ One derived ML-DSA-65 key. A CA key has no address (sf-wallet-gov
        prints none for one), so none is carried. """
    public_key: bytes
