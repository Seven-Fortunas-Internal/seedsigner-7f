"""
    Devfund-config signing flow: scan the devfund-config sent by the
    coordinator, the no-blind-signing review flow (via _common.py's shared
    SevenFCertRequestReviewFieldView), the gated sign call, and export of
    the signed result. R11's "development-fund configuration" artefact.
"""
from dataclasses import dataclass
from gettext import gettext as _

from seedsigner.helpers.l10n import mark_for_translation as _mft
from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
from seedsigner.models.seed import Seed
from seedsigner.models.sevenf import devfund_config, root_ceremony
from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.models.sevenf.devfund_config import DevFundConfigError, DevFundConfigJsonError
from seedsigner.views.scan_views import ScanView
from seedsigner.views.view import BackStackView, Destination, MainMenuView, View, guard_active_chain

from seedsigner.models.review import ReviewField

from ._common import (
    refuse_on_unexpected_error, SevenFCertRequestReviewFieldView, SevenFUnsupportedArtefactView,
    key_index_review_field, refuse_unless_signed_by_shown_key, subject_key_id_with_index,
)
from ._key_index import SevenFSelectKeyIndexView


@dataclass(frozen=True)
class SevenFSignedArtifact:
    """ Devfund-config signing's own signed result -- threaded through
        view_args from SevenFConfirmSignDevFundView to
        SevenFDevFundConfigSignedView to SevenFExportSignedDevFundConfigQRView,
        replacing this flow's former write/read of
        controller.sevenf_ceremony_data (7f-review-ceremony-data-untyped-
        shared-dict). """
    public_key: bytes
    signature: bytes


class SevenFScanDevFundConfigView(ScanView):
    """ Scans the BBQr-encoded devfund-config the coordinator (sf-root)
        sends to this signer -- R11's "development-fund configuration"
        artefact, the third of the three signable artefacts that section
        requires (genesis config and Deputy certificates are the other
        two, both already built). Mirrors _genesis.SevenFScanGenesisConfigView
        exactly (same guard_active_chain check, same "file_type on the wire
        is not authoritative, try to parse it" self-validation doctrine):
        a genesis-config or CertRequest accidentally scanned here fails to
        parse as a devfund-config (different domain tag) and is refused
        the same way, not specially detected. """
    instructions_text = _mft("Scan devfund config")
    invalid_qr_type_message = _mft("Expected a devfund-config QR (BBQr, from the coordinator)")


    def __init__(self, seed: Seed):
        super().__init__()
        self.seed = seed

        if guard_active_chain(self, "sevenf"):
            return


    @property
    def is_valid_qr_type(self):
        return self.decoder.is_sevenf_bbqr


    @refuse_on_unexpected_error
    def _handle_complete_scan(self):
        # The coordinator's real artifact is devfund-unsigned.json
        # (sf-root-coordinator prepare-devfund); the bytes signed are rebuilt
        # from its parsed fields, exactly as sf-wallet-gov sign-devfund does.
        payload = self.decoder.get_sevenf_bbqr_data()

        try:
            json_fields = devfund_config.parse_devfund_config_json(payload)
            canonical_bytes = devfund_config.build_canonical_bytes(
                json_fields.network, json_fields.recipient, json_fields.effective_block, json_fields.timestamp)
            # Review what the Rust parser reads back out of the exact bytes to
            # be signed, and refuse if that disagrees with the JSON (same as
            # the genesis path, plugin._canonical_bytes_from_json).
            fields = devfund_config.parse_canonical_bytes(canonical_bytes)
        except (DevFundConfigJsonError, DevFundConfigError) as e:
            return Destination(SevenFUnsupportedArtefactView, view_args=dict(
                reason=_("Couldn't parse this as a devfund-config: {}").format(e)))
        if fields != json_fields:
            return Destination(SevenFUnsupportedArtefactView, view_args=dict(
                reason=_("Couldn't parse this as a devfund-config: the bytes to sign don't match the file")))

        # Signed with the ROOT key (sf-wallet-gov sign-devfund --index N signs
        # as Role::Root), so this asks for the Root index, not a dev-fund one.
        return Destination(
            SevenFSelectKeyIndexView,
            view_args=dict(
                role="root",
                next_destination=SevenFDevFundReviewStartView,
                next_view_args=dict(
                    seed=self.seed,
                    chain_kind=fields.network,
                    canonical_bytes=canonical_bytes,
                    review_fields=devfund_config.review_fields(fields, canonical_bytes=canonical_bytes),
                ),
            ),
            skip_current_view=True,
        )



class SevenFDevFundReviewStartView(View):
    """ After the Root key index: the review pages, with the signing key
        first (7f-signing-support-key-index-selector). """
    def __init__(self, seed: Seed, chain_kind: ChainKind, canonical_bytes: bytes,
                 review_fields: list[ReviewField], key_index: int):
        super().__init__()
        self.seed = seed
        self.chain_kind = chain_kind
        self.canonical_bytes = canonical_bytes
        self.review_fields = review_fields
        self.key_index = key_index


    def run(self):
        return Destination(
            SevenFCertRequestReviewFieldView,
            view_args=dict(
                review_fields=[key_index_review_field(self.chain_kind, self.key_index), *self.review_fields],
                page_title=_("Review Devfund Config"),
                confirmed_destination=SevenFConfirmSignDevFundView,
                confirmed_view_args=dict(
                    seed=self.seed,
                    chain_kind=self.chain_kind,
                    tbs_bytes=self.canonical_bytes,
                    key_index=self.key_index,
                ),
            ),
            skip_current_view=True,
        )



class SevenFConfirmSignDevFundView(View):
    """ Final review step for devfund-config signing: confirms which chain
        and which address the signature will be attributed to -- the
        signing-identity check, distinct from the per-field content review
        that already happened on the preceding pages. Labelled "Root key":
        the devfund-config is Root-signed (sf-wallet-gov sign-devfund), and
        since 7fchain 89d3d39 a separate dev-fund key exists that this is not.

        CORRECTED 2026-10-03 (R27 re-port, adversarial review): this
        docstring used to claim the devfund address differs from the Root
        CA address shown by _common.SevenFConfirmSignRootCertView's own
        confirm screen, "different derived keys off the same seed." That
        was the exact bug root_ceremony.py's own BUG FIX note fixed --
        devfund and Root CA are now the SAME key (confirmed against
        7fchain's real sf-root.rs: cmd_sign_genesis/cmd_sign_devfund both
        call the byte-identical root_key_from_file()). This screen still
        shows `keys.devfund.address` (now always equal to
        `keys.root_ca.address`) -- kept as a separate View/confirm screen
        from SevenFConfirmSignRootCertView for artefact-type clarity
        (genesis vs. devfund-config is still a real distinction the
        operator should see named), not because it disambiguates two
        different signing identities any more. Do not "restore" a separate
        devfund derivation here -- that would reintroduce the fixed bug.

        Reuses root_ceremony.sign_with_devfund() unmodified. This is the
        ONLY caller permitted to pass confirmed=True for this flow, same
        contract as _common.SevenFConfirmSignRootCertView. """
    def __init__(self, seed: Seed, chain_kind: ChainKind, tbs_bytes: bytes, key_index: int):
        super().__init__()
        self.seed = seed
        self.chain_kind = chain_kind
        self.tbs_bytes = tbs_bytes
        self.key_index = key_index

        keys = root_ceremony.derive_root_ceremony_keys(self.seed.seed_bytes, self.chain_kind, key_index)
        self.public_key = keys.devfund.public_key
        self.devfund_address = keys.devfund.address
        self.subject_key_id = subject_key_id_with_index(keys.devfund.public_key, key_index)


    def run(self):
        from seedsigner.gui.screens.sevenf_screens import SevenFConfirmSignScreen
        selected_menu_num = self.run_screen(
            SevenFConfirmSignScreen,
            chain_kind_name=self.chain_kind.name.lower(),
            address=self.devfund_address,
            subject_key_id=self.subject_key_id,
            signing_role_label=_("Root key"),
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # Operator clicked "Sign" -- the one and only call site allowed to pass
        # confirmed=True for this flow (root_ceremony.sign_with_devfund's own docstring).
        public_key, signature = root_ceremony.sign_with_devfund(
            self.seed.seed_bytes,
            self.chain_kind,
            self.tbs_bytes,
            confirmed=True,
            index=self.key_index,
        )
        refused = refuse_unless_signed_by_shown_key(public_key, self.public_key)
        if refused:
            return refused
        artifact = SevenFSignedArtifact(public_key=public_key, signature=signature)
        return Destination(SevenFDevFundConfigSignedView, view_args=dict(artifact=artifact))



class SevenFDevFundConfigSignedView(View):
    """ Success confirmation, then straight to export -- unlike genesis's
        two-artifact _genesis.SevenFExportView menu, devfund signing only
        ever produces one exportable artifact (the signature), so there's
        no menu to show.

        `artifact` (added 2026-10-04, 7f-review-ceremony-data-untyped-
        shared-dict) replaces the former write/read of
        controller.sevenf_ceremony_data. """
    def __init__(self, artifact: SevenFSignedArtifact):
        super().__init__()
        self.artifact = artifact


    def run(self):
        from seedsigner.gui.screens.screen import ButtonOption, LargeIconStatusScreen
        self.run_screen(
            LargeIconStatusScreen,
            title=_("Devfund Config Signed"),
            show_back_button=False,
            status_headline=_("Success!"),
            text=_("The devfund config has been signed with your Root key."),
            button_data=[ButtonOption("OK")],
        )
        return Destination(SevenFExportSignedDevFundConfigQRView, view_args=dict(artifact=self.artifact))



class SevenFExportSignedDevFundConfigQRView(View):
    """ Exports the devfund-config signature as BBQr-encoded JSON. Matches
        sf-core::genesis_config::RootSig's real, current on-wire shape --
        the exact same shape genesis-config signatures use
        (devfund_config.build_root_sig_json()'s own docstring has the
        confirmation: "Same shape and same rules as GenesisConfig::signatures"
        per sf-core's own DevFundConfig.signatures doc comment). Only the
        signature leaves the device per ceremony (D11), matching every
        other export in this package. """
    def __init__(self, artifact: SevenFSignedArtifact):
        super().__init__()
        self.artifact = artifact


    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
        from seedsigner.models.encode_qr import BBQrEncoder
        from seedsigner.models.sevenf.export_envelope import signature_export

        # <ski>.devfund exactly as sf-wallet-gov sign-devfund writes it, in an
        # envelope that tells the host page the file name (export_envelope.py).
        self.run_screen(
            QRDisplayScreen,
            qr_encoder=BBQrEncoder(
                data=signature_export("devfund", self.artifact.public_key, self.artifact.signature), file_type="J"),
        )
        return Destination(MainMenuView, skip_current_view=True)
