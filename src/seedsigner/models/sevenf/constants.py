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
            "m/root-ca/l1/testnet/0" -- confirmed against sf-root.rs:368-370. """
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


def root_ca_purpose_path(chain_kind: ChainKind) -> str:
    """ e.g. "m/root-ca/l1/testnet/0" -- confirmed against sf-root.rs:368. """
    return f"m/root-ca/l1/{chain_kind.path_segment}/0"


def devfund_purpose_path(chain_kind: ChainKind) -> str:
    """ e.g. "m/7fchain/l1/testnet/devfund/0" -- confirmed against sf-root.rs:370. """
    return f"m/7fchain/l1/{chain_kind.path_segment}/devfund/0"


# The leaf role under either purpose path -- confirmed against
# sf-root.rs:860,1273-1276,1800,2003 (`derive_leaf_seed(&root_seed, "ml-dsa/v1/0")`).
# RE-CONFIRMED 2026-10-01: the version segment became mandatory
# (docs/derivation-path-lexicon.md, path.rs's validate_role_path) as part of
# regenerating the nine Root keys for the 6-of-9 testnet relaunch -- this
# constant was still "ml-dsa/0" (pre-dates that change) until this fix.
# Always index 0: the Root ceremony derives exactly one Root CA key and one
# devfund key per chain_kind, never a family of indexed keys.
ML_DSA_LEAF_ROLE = "ml-dsa/v1/0"


@dataclass(frozen=True)
class DerivedKey:
    """ One derived ML-DSA-65 key: its public key bytes and its 7fchain address. """
    public_key: bytes
    address: str
