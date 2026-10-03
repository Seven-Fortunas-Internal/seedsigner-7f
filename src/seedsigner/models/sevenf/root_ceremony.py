"""
    Derive the Root-ceremony key from a 24-word BIP-39 mnemonic's seed
    bytes. Backs 7f-signing-support-root-ceremony-key-derivation
    (docs/7f-integration/root-key-ceremony-plan.md).

    Deliberately narrow: no treasury key (dropped, see that plan doc's
    "Correction" section -- sf-core/src/genesis_config.rs has no
    treasury/premine field, B8/D20), and no mnemonic-generation logic here
    -- that's stock SeedSigner's existing Seed/mnemonic UI, reused as-is
    per docs/7f-integration/README.md's "What's reusable from stock
    SeedSigner" section.

    BUG FIX, 2026-10-03 (R27 re-port): this module used to derive
    `devfund` from a *separate* path from `root_ca`
    (`m/7fchain/l1/<chain_kind>/devfund/0` vs. `m/root-ca/l1/<chain_kind>/0`)
    -- two different keys. Direct reading of 7fchain's real `sf-root.rs`
    confirmed `cmd_sign_genesis` and `cmd_sign_devfund` both call the
    byte-for-byte identical `root_key_from_file(chain_kind, 0, ...)`:
    genesis-config and devfund-config are signed by the SAME Root key,
    not two. `RootCeremonyKeys.devfund` is now the same `DerivedKey` as
    `root_ca`, and `sign_with_devfund()` signs with that same key --
    see that function's own doc comment.
"""
from dataclasses import dataclass

from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf.constants import ChainKind, DerivedKey, Layer, root_path


@dataclass(frozen=True)
class RootCeremonyKeys:
    """ The Root-ceremony key for one chain_kind (no treasury -- see this
        module's own docstring). `devfund` is the SAME key as `root_ca`
        (see the BUG FIX note above), kept as its own field so callers that
        read `.devfund` don't need to know that -- not a second derivation. """
    chain_kind: ChainKind
    root_ca: DerivedKey
    devfund: DerivedKey


def derive_root_ceremony_keys(seed_bytes: bytes, chain_kind: ChainKind) -> RootCeremonyKeys:
    """ Derive the Root ML-DSA-65 key for `chain_kind` from `seed_bytes`
        (SeedSigner's Seed.seed_bytes -- standard BIP-39, empty passphrase,
        64 bytes). `root_ca` and `devfund` are the same derived key (see
        this module's own BUG FIX note) -- confirmed against 7fchain's real
        `sf-root.rs`'s `root_key_from_file()`. Raises
        seedsigner.models.sevenf.mldsa.MlDsaError on any derivation
        failure, ValueError if seed_bytes is the wrong length.
    """
    root_pk, root_address = mldsa.derive_pubkey(
        seed_bytes,
        root_path(chain_kind),
        int(chain_kind),
        int(Layer.L1),
    )
    root_key = DerivedKey(public_key=root_pk, address=root_address)

    return RootCeremonyKeys(
        chain_kind=chain_kind,
        root_ca=root_key,
        devfund=root_key,
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
        non-negotiable" principle requires. On the DEVICE, the only intended
        callers are views.sevenf_views.SevenFConfirmSignView (genesis-config,
        after the operator has approved every field via
        genesis_config.review_fields()/SevenFGenesisReviewFieldView) and
        SevenFConfirmSignRootCertView (Root self-cert and Deputy cross-cert,
        after the operator has approved every field via
        root_self_cert_review_fields()/deputy_cross_cert_v2_review_fields()).
        Passing confirmed=True from anywhere else on the device defeats the
        whole point of this parameter existing -- it is not a formality to
        satisfy a type checker, it is the gate.

        The one exception is OFFLINE, host-side test-fixture-generation
        tooling (tools/make_sevenf_test_qrs.py's build_root_cert_der/
        build_deputy_csr_der) -- never shipped to the device, never reads a
        real ceremony seed, and signs only the hardcoded test-only BIP-39
        fixtures already used throughout that tool. There is no review
        screen to gate there because there is no operator session at all;
        the gate this parameter protects is "did a human see the fields
        before this device signed them," which doesn't apply to a script
        generating its own test input.
    """
    if not confirmed:
        raise SigningNotConfirmedError(
            "sign_with_root_ca refuses to sign without confirmed=True -- "
            "only the review screen may set this, after the operator has "
            "approved every displayed field."
        )
    return mldsa.derive_and_sign(
        seed_bytes,
        root_path(chain_kind),
        message,
    )


def sign_with_devfund(seed_bytes: bytes, chain_kind: ChainKind, message: bytes, *, confirmed: bool) -> tuple[bytes, bytes]:
    """ Sign `message` with the Root key for `chain_kind` -- the
        devfund-config twin of sign_with_root_ca() above, same enforced
        review-before-sign gate and same rationale (see that function's own
        docstring; not repeated here).

        BUG FIX, 2026-10-03 (R27 re-port): this used to sign with a
        separately-derived "devfund" key. Direct reading of 7fchain's real
        `sf-root.rs` confirmed `cmd_sign_genesis` and `cmd_sign_devfund`
        call the byte-for-byte identical `root_key_from_file(chain_kind, 0,
        ...)` -- genesis-config and devfund-config are signed by the SAME
        Root key. This function now derives and signs with `root_path()`,
        exactly like sign_with_root_ca() -- kept as a separate function
        (rather than deleted in favor of calling sign_with_root_ca()
        directly) only so devfund-config's own confirmed-sign call site
        reads as what it is, not as a disguised genesis-config signature.

        `confirmed` is REQUIRED (keyword-only, no default) and must be
        `True`. views.sevenf_views.SevenFConfirmSignDevFundView is the only
        intended caller allowed to pass confirmed=True, after the operator
        has approved every field in devfund_config.review_fields(), paged
        by the same SevenFCertRequestReviewFieldView this codebase already
        reuses for every other artefact type. """
    if not confirmed:
        raise SigningNotConfirmedError(
            "sign_with_devfund refuses to sign without confirmed=True -- "
            "only the review screen may set this, after the operator has "
            "approved every displayed field."
        )
    return mldsa.derive_and_sign(
        seed_bytes,
        root_path(chain_kind),
        message,
    )
