"""
    Derivation paths, by 7fchain's own rules: crates/sf-keytree/src/path.rs,
    ported verbatim into firmware/mldsa7f (src/path.rs) and called through the
    FFI. 7fchain's lexicon requires exactly this: "The device must apply the same
    rules, and must do so by calling this code over FFI rather than
    reimplementing it" (docs/derivation-path-lexicon.md). This module keeps no
    copy of the rules; the Rust derivation also validates every path itself
    (derive.rs), so validate() is where a caller gets 7fchain's message, not a
    second gate.

        <role>/<chain-kind>/[<chain-id>/]<index>/<algorithm>/v<N>[/<leaf>]
"""
from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.models.sevenf.mldsa import PathLexiconError

__all__ = ["PathLexiconError", "devfund_path", "root_path", "validate"]


def validate(path: str) -> None:
    """ Raise PathLexiconError, with 7fchain's message, unless `path` is valid. """
    refusal = mldsa.path_refusal(path)
    if refusal is not None:
        raise PathLexiconError(refusal)


def root_path(chain_kind: ChainKind, index: int = 0) -> str:
    """ e.g. "root/testnet/0/ml-dsa/v1": 7fchain's `path_for(Role::Root,
        chain_kind, index)`. The Root key signs the genesis- and
        devfund-configs and the certificates (sf-wallet-gov sign_ops.rs: both
        configs `load_signer(Role::Root, ...)`). `index` is sf-wallet-gov's
        `--index`, default 0; our practice is one phrase per Root key at
        index 0. """
    return mldsa.path_for("root", chain_kind, index)


def devfund_path(chain_kind: ChainKind, index: int = 0) -> str:
    """ e.g. "devfund/testnet/0/ml-dsa/v1": 7fchain's `path_for(Role::Devfund,
        chain_kind, index)` (89d3d39). The holder's dev-fund key, one of the
        nine that lock the dev fund (sf-wallet-gov `derive-vk --role
        devfund`); it does NOT sign the devfund-config, the Root key does.
        7fchain calls a later index a rotation (open question on 7fchain#7). """
    return mldsa.path_for("devfund", chain_kind, index)
