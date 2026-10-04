"""
    Devfund-config signing flow: scan the devfund-config sent by the
    coordinator, the no-blind-signing review flow (via _common.py's shared
    SevenFCertRequestReviewFieldView), the gated sign call, and export of
    the signed result. R11's "development-fund configuration" artefact.
"""
from gettext import gettext as _

from seedsigner.helpers.l10n import mark_for_translation as _mft
from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
from seedsigner.models.seed import Seed
from seedsigner.models.sevenf import devfund_config, root_ceremony
from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.models.sevenf.devfund_config import DevFundConfigError
from seedsigner.views.scan_views import ScanView
from seedsigner.views.view import BackStackView, Destination, MainMenuView, View, guard_active_chain

from ._common import SevenFCertRequestReviewFieldView, SevenFUnsupportedArtefactView


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


    def _handle_complete_scan(self):
        canonical_bytes = self.decoder.get_sevenf_bbqr_data()

        try:
            fields = devfund_config.parse_canonical_bytes(canonical_bytes)
        except DevFundConfigError as e:
            return Destination(SevenFUnsupportedArtefactView, view_args=dict(
                reason=_("Couldn't parse this as a devfund-config: {}").format(e)))

        return Destination(
            SevenFCertRequestReviewFieldView,
            view_args=dict(
                review_fields=devfund_config.review_fields(fields),
                page_title=_("Review Devfund Config"),
                confirmed_destination=SevenFConfirmSignDevFundView,
                confirmed_view_args=dict(
                    seed=self.seed,
                    chain_kind=fields.network,
                    tbs_bytes=canonical_bytes,
                ),
            ),
            skip_current_view=True,
        )



class SevenFConfirmSignDevFundView(View):
    """ Final review step for devfund-config signing: confirms which chain
        and which address the signature will be attributed to -- the
        signing-identity check, distinct from the per-field content review
        that already happened on the preceding pages.

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
    def __init__(self, seed: Seed, chain_kind: ChainKind, tbs_bytes: bytes):
        super().__init__()
        self.seed = seed
        self.chain_kind = chain_kind
        self.tbs_bytes = tbs_bytes

        keys = root_ceremony.derive_root_ceremony_keys(self.seed.seed_bytes, self.chain_kind)
        self.devfund_address = keys.devfund.address


    def run(self):
        from seedsigner.gui.screens.sevenf_screens import SevenFConfirmSignScreen
        selected_menu_num = self.run_screen(
            SevenFConfirmSignScreen,
            chain_kind_name=self.chain_kind.name.lower(),
            address=self.devfund_address,
            signing_role_label=_("devfund key"),
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
        )
        self.controller.sevenf_ceremony_data = dict(public_key=public_key, signature=signature)
        return Destination(SevenFDevFundConfigSignedView)



class SevenFDevFundConfigSignedView(View):
    """ Success confirmation, then straight to export -- unlike genesis's
        two-artifact _genesis.SevenFExportView menu, devfund signing only
        ever produces one exportable artifact (the signature), so there's
        no menu to show. """
    def run(self):
        from seedsigner.gui.screens.screen import ButtonOption, LargeIconStatusScreen
        self.run_screen(
            LargeIconStatusScreen,
            title=_("Devfund Config Signed"),
            show_back_button=False,
            status_headline=_("Success!"),
            text=_("The devfund config has been signed with the devfund key."),
            button_data=[ButtonOption("OK")],
        )
        return Destination(SevenFExportSignedDevFundConfigQRView)



class SevenFExportSignedDevFundConfigQRView(View):
    """ Exports the devfund-config signature as BBQr-encoded JSON. Matches
        sf-core::genesis_config::RootSig's real, current on-wire shape --
        the exact same shape genesis-config signatures use
        (devfund_config.build_root_sig_json()'s own docstring has the
        confirmation: "Same shape and same rules as GenesisConfig::signatures"
        per sf-core's own DevFundConfig.signatures doc comment). Only the
        signature leaves the device per ceremony (D11), matching every
        other export in this package. """
    def run(self):
        import json

        from seedsigner.gui.screens.screen import QRDisplayScreen
        from seedsigner.models.encode_qr import BBQrEncoder
        data = self.controller.sevenf_ceremony_data
        signed_json = devfund_config.build_root_sig_json(
            data["public_key"], data["signature"],
        )
        json_bytes = json.dumps(signed_json).encode("utf-8")

        self.run_screen(
            QRDisplayScreen,
            qr_encoder=BBQrEncoder(data=json_bytes, file_type="J"),  # 'J': BBQr JSON
        )
        return Destination(MainMenuView, skip_current_view=True)
