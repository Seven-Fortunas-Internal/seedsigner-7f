"""
    Derive the two Root-ceremony keys -- Root CA and devfund -- from a
    24-word BIP-39 mnemonic's seed bytes. Backs
    7f-signing-support-root-ceremony-key-derivation
    (docs/7f-integration/root-key-ceremony-plan.md).

    Deliberately narrow: no treasury key (dropped, see that plan doc's
    "Correction" section -- sf-core/src/genesis_config.rs has no
    treasury/premine field, B8/D20), and no mnemonic-generation logic here
    -- that's stock SeedSigner's existing Seed/mnemonic UI, reused as-is
    per docs/7f-integration/README.md's "What's reusable from stock
    SeedSigner" section.
"""
from dataclasses import dataclass

from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf.constants import (
    ChainKind,
    DerivedKey,
    Layer,
    ML_DSA_LEAF_ROLE,
    devfund_purpose_path,
    root_ca_purpose_path,
)


@dataclass(frozen=True)
class RootCeremonyKeys:
    """ The two keys `sf-root init` derives for one chain_kind (no treasury
        -- see this module's own docstring). """
    chain_kind: ChainKind
    root_ca: DerivedKey
    devfund: DerivedKey


def derive_root_ceremony_keys(seed_bytes: bytes, chain_kind: ChainKind) -> RootCeremonyKeys:
    """ Derive the Root CA and devfund ML-DSA-65 keys for `chain_kind` from
        `seed_bytes` (SeedSigner's Seed.seed_bytes -- standard BIP-39,
        empty passphrase, 64 bytes).

        Both keys use layer=L1 and leaf role "ml-dsa/0" -- confirmed
        against sf-root.rs:368-370,658-660,783-785. Raises
        seedsigner.models.sevenf.mldsa.MlDsaError on any derivation
        failure, ValueError if seed_bytes is the wrong length.
    """
    root_ca_pk, root_ca_address = mldsa.derive_pubkey(
        seed_bytes,
        root_ca_purpose_path(chain_kind),
        ML_DSA_LEAF_ROLE,
        int(chain_kind),
        int(Layer.L1),
    )
    devfund_pk, devfund_address = mldsa.derive_pubkey(
        seed_bytes,
        devfund_purpose_path(chain_kind),
        ML_DSA_LEAF_ROLE,
        int(chain_kind),
        int(Layer.L1),
    )

    return RootCeremonyKeys(
        chain_kind=chain_kind,
        root_ca=DerivedKey(public_key=root_ca_pk, address=root_ca_address),
        devfund=DerivedKey(public_key=devfund_pk, address=devfund_address),
    )


class SigningNotConfirmedError(Exception):
    """ Raised when sign_with_root_ca is called without confirmed=True.
        See that function's own docstring for why this exists as an
        enforced architectural gate, not a caller convention. """
    pass


def sign_with_root_ca(seed_bytes: bytes, chain_kind: ChainKind, message: bytes, *, confirmed: bool) -> tuple[bytes, bytes]:
    """ Sign `message` with the Root CA key for `chain_kind` -- the
        operation `sf-root sign-genesis` performs over a genesis-config's
        canonical bytes. Returns (public_key, signature).

        `confirmed` is REQUIRED (keyword-only, no default) and must be
        `True` -- there is no way to call this function without explicitly
        deciding that value. This is the architectural review-before-sign
        gate an adversarial review found missing (see
        7f-signing-support-root-ceremony-genesis-builder-and-signer's own
        notes in _delivery/backlog.yaml): a single callable that builds
        bytes and signs them, with review bolted on as a UI step in front
        of it, is not the same guarantee as this project's "no-blind-signing,
        non-negotiable" principle requires. views.sevenf_views.SevenFConfirmSignView
        is the only intended caller allowed to pass confirmed=True, and only
        after the operator has explicitly approved every displayed field
        (see genesis_config.review_fields(), paged one field per screen by
        views.sevenf_views.SevenFGenesisReviewFieldView). Passing
        confirmed=True from anywhere else defeats the whole point of this
        parameter existing -- it is not a formality to satisfy a type
        checker, it is the gate.
    """
    if not confirmed:
        raise SigningNotConfirmedError(
            "sign_with_root_ca refuses to sign without confirmed=True -- "
            "only the review screen may set this, after the operator has "
            "approved every displayed field."
        )
    return mldsa.derive_and_sign(
        seed_bytes,
        root_ca_purpose_path(chain_kind),
        ML_DSA_LEAF_ROLE,
        message,
    )
