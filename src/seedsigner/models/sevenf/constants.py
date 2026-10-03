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


def root_path(chain_kind: ChainKind) -> str:
    """ e.g. "root/testnet/0/ml-dsa/v1" -- confirmed against 7fchain's real
        `crates/sf-keytree/src/path.rs::path_for(Role::Root, chain_kind, 0)`
        and `phrase_file.rs::root_path()`.

        RE-PORTED 2026-10-03 (R27): 7fchain collapsed its two-level
        `purpose_path`/`role_path` grammar into this single combined path
        -- see firmware/mldsa7f/src/derive.rs's doc comment for why. This
        single function replaces the old `root_ca_purpose_path()`,
        `devfund_purpose_path()`, and the separate `ML_DSA_LEAF_ROLE`
        constant: `sf-root.rs`'s own `cmd_sign_genesis` and
        `cmd_sign_devfund` both call the byte-identical
        `root_key_from_file(..., index 0)` -- genesis-config and
        devfund-config are signed by the SAME Root key, not two. There is
        no separate "devfund path" any more; root_ceremony.py's devfund
        key is this same path (see that module's own doc comment for the
        bug this fixed). Always index 0: the Root ceremony derives exactly
        one Root key per chain_kind, never a family of indexed keys. """
    return f"root/{chain_kind.path_segment}/0/ml-dsa/v1"


@dataclass(frozen=True)
class DerivedKey:
    """ One derived ML-DSA-65 key: its public key bytes and its 7fchain address. """
    public_key: bytes
    address: str
