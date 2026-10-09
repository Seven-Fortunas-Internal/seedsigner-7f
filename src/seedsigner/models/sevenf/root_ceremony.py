"""
    The Root and dev-fund keys of a 7F federation holder, derived from the
    holder's phrase exactly as 7fchain's sf-wallet-gov derives them.

    7fchain is the source of truth (CLAUDE.md):
    - A governance phrase is 24 English BIP-39 words, with an optional BIP-39
      passphrase (sf-keytree phrase_file.rs ROOT_WORD_COUNT, mnemonic.rs
      master_seed). Only `seed_for_7f()` makes a `SevenFSeed`, and every
      function here takes one, so no other seed can reach a 7F key.
    - The Root key is at root/<chain_kind>/<index>/ml-dsa/v1. sf-wallet-gov
      signs genesis-config AND devfund-config with it (sign_ops.rs: both
      `load_signer(Role::Root, ...)`), so `RootCeremonyKeys.devfund` is the same
      key as `root_ca`.
    - Each holder's dev-fund key is a different key, at
      devfund/<chain_kind>/<index>/ml-dsa/v1 (7fchain 89d3d39): it locks the
      dev fund's multisig; the Roots declare the recipient with the Root key.
    - CA keys have no address: sf-wallet-gov prints none for them ("would
      invite someone to pay it", main.rs derive-vk).

    Signing is gated: `confirmed=True` may be passed only by the confirm view
    shown after the operator has approved every review field (or by offline
    test-fixture tooling that has no operator session). It is the
    no-blind-signing gate, not a formality.
"""
from dataclasses import dataclass

from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf.constants import ChainKind, DerivedKey, devfund_path, root_path

ROOT_WORD_COUNT = 24                 # sf-keytree phrase_file.rs
_ENGLISH = "en"                      # bip39 2.2.2 default features: English only


class NotA7FPhraseError(ValueError):
    """ The seed is not a 7F governance phrase: 24 English BIP-39 words. """


_TOKEN = object()


class SevenFSeed:
    """ The BIP-39 seed of a 7F governance phrase. Made only by seed_for_7f(). """
    __slots__ = ("_seed_bytes",)

    def __init__(self, *args, **kwargs):
        raise TypeError("a SevenFSeed is made only by seed_for_7f(seed)")

    @classmethod
    def _from_checked(cls, token, seed_bytes: bytes) -> "SevenFSeed":
        if token is not _TOKEN:
            raise TypeError("a SevenFSeed is made only by seed_for_7f(seed)")
        obj = object.__new__(cls)
        object.__setattr__(obj, "_seed_bytes", bytes(seed_bytes))
        return obj

    @property
    def seed_bytes(self) -> bytes:
        return self._seed_bytes


def seed_for_7f(seed) -> SevenFSeed:
    """ The SevenFSeed of `seed`, or NotA7FPhraseError if 7fchain would not
        derive from it: not a plain BIP-39 Seed (an ElectrumSeed is a subclass
        whose seed bytes are not BIP-39), not 24 words, or not English. """
    from seedsigner.models.seed import Seed
    if type(seed) is not Seed:
        raise NotA7FPhraseError("7F keys come from a BIP-39 phrase; this seed is not one")
    if len(seed.mnemonic_list) != ROOT_WORD_COUNT:
        raise NotA7FPhraseError(f"a 7F governance phrase is {ROOT_WORD_COUNT} words, this seed has {len(seed.mnemonic_list)}")
    if seed.wordlist_language_code != _ENGLISH:
        raise NotA7FPhraseError("a 7F governance phrase uses the English BIP-39 wordlist")
    return SevenFSeed._from_checked(_TOKEN, seed.seed_bytes)


def _bytes_of(seed: SevenFSeed) -> bytes:
    if not isinstance(seed, SevenFSeed):
        raise TypeError(f"7F keys are derived only from a SevenFSeed (seed_for_7f), not {type(seed).__name__}")
    return seed.seed_bytes


@dataclass(frozen=True)
class RootCeremonyKeys:
    """ The Root key for one chain_kind at one key index. `devfund` is the same
        key as `root_ca`: the key that signs the devfund-config (sf-wallet-gov
        sign-devfund signs as Role::Root), not the holder's dev-fund key. """
    chain_kind: ChainKind
    root_ca: DerivedKey
    devfund: DerivedKey
    index: int = 0


def derive_root_ceremony_keys(seed: SevenFSeed, chain_kind: ChainKind, *, index: int) -> RootCeremonyKeys:
    """ The Root key at sf-wallet-gov's `--index` (required, so a caller can
        never silently get index 0). """
    public_key, _ca_address_unused = mldsa.derive_pubkey(_bytes_of(seed), root_path(chain_kind, index))
    root_key = DerivedKey(public_key=public_key)
    return RootCeremonyKeys(chain_kind=chain_kind, root_ca=root_key, devfund=root_key, index=index)


def derive_devfund_key(seed: SevenFSeed, chain_kind: ChainKind, *, index: int) -> DerivedKey:
    """ The holder's dev-fund key (sf-wallet-gov `derive-vk --role devfund
        --index`), a different key from the Root key. Exported only. """
    public_key, _ca_address_unused = mldsa.derive_pubkey(_bytes_of(seed), devfund_path(chain_kind, index))
    return DerivedKey(public_key=public_key)


class SigningNotConfirmedError(Exception):
    """ A sign call without confirmed=True: see this module's docstring. """


def _sign_with_root_key(seed: SevenFSeed, chain_kind: ChainKind, message: bytes, confirmed: bool, index: int, what: str) -> tuple[bytes, bytes]:
    seed_bytes = _bytes_of(seed)
    if not confirmed:
        raise SigningNotConfirmedError(
            f"{what} refuses to sign without confirmed=True -- only the confirm view may set it, "
            "after the operator has approved every displayed field.")
    return mldsa.derive_and_sign(seed_bytes, root_path(chain_kind, index), message)


def sign_with_root_ca(seed: SevenFSeed, chain_kind: ChainKind, message: bytes, *, confirmed: bool, index: int) -> tuple[bytes, bytes]:
    """ Sign with the Root key at `index`, as sf-wallet-gov sign-genesis,
        sign-root-cert and sign-deputy-cert do. Returns (public_key, signature);
        the library verifies the signature before returning it. """
    return _sign_with_root_key(seed, chain_kind, message, confirmed, index, "sign_with_root_ca")


def sign_with_devfund(seed: SevenFSeed, chain_kind: ChainKind, message: bytes, *, confirmed: bool, index: int) -> tuple[bytes, bytes]:
    """ Sign a devfund-config with the Root key at `index`, as sf-wallet-gov
        sign-devfund does (Role::Root). A separate name only so the devfund
        confirm view reads as what it signs. """
    return _sign_with_root_key(seed, chain_kind, message, confirmed, index, "sign_with_devfund")
