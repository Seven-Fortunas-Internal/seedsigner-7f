"""
    7fchain root-key ceremony UI: scan the genesis-config sent by the
    coordinator, the no-blind-signing review flow, the gated sign call, and
    export of the signed result. See docs/7f-integration/root-key-ceremony-plan.md.

    Follows the same file-pairing convention as the rest of this codebase
    (seed_views.py <-> seed_screens.py, evm_views.py <-> evm_screens.py); see
    gui/screens/sevenf_screens.py for the paired Screen classes.

    Backs 7f-signing-support-root-ceremony-ui-wizard (_delivery/backlog.yaml):
    scan -> parse -> page through every signed field -> confirm identity ->
    sign -> export. Reached from SeedOptionsView's "7F: Sign Genesis Config"
    button (seed_views.py) -- a per-seed submenu item, so the seed is always
    already known by the time SevenFScanGenesisConfigView runs, the same way
    evm_views.EvmScanSignRequestView never needs a separate seed-selection
    step either. This is deliberately narrower than the wizard story's
    original phrasing ("mnemonic generation with optional entropy injection,
    chain_kind selection, key derivation") -- that phrasing predates this
    project's own architecture correction that the device PARSES a received
    genesis-config rather than building one from local operator input (see
    root-key-ceremony-plan.md's "Superseding authority" section, §5.3/5.4):
    there is no chain_kind to select (it comes only from the parsed bytes)
    and no on-device genesis-config construction step at all. Mnemonic
    generation/entropy injection is just SeedSigner's existing seed-creation
    flow, already reachable before ever reaching SeedOptionsView -- nothing
    7F-specific to add there.
"""
from gettext import gettext as _

from seedsigner.helpers.l10n import mark_for_translation as _mft
from seedsigner.chains.base import ReviewField
from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
from seedsigner.gui.screens.screen import ButtonOption
from seedsigner.models.seed import Seed
from seedsigner.models.sevenf import genesis_config, root_ceremony
from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.models.sevenf.genesis_config import GenesisConfigError
from seedsigner.views.scan_views import ScanView
from seedsigner.views.view import BackStackView, Destination, MainMenuView, View


class SevenFScanGenesisConfigView(ScanView):
    """ Scans the BBQr-encoded genesis-config the coordinator (sf-root)
        sends to this signer -- the real entry point into the ceremony.
        Overrides _handle_complete_scan() rather than duplicating ScanView's
        shared scan-screen scaffolding (same pattern as EvmScanSignRequestView,
        evm_views.py). Not wired into ScanView's own top-level catch-all
        dispatch (scan_views.py's _handle_complete_scan): unlike EVM's
        eth_sign_request (reachable from Home's generic Scan button before
        any seed is known, hence that flow's double-scan design), this view
        is only ever reached with a seed already selected -- no separate
        seed-selection sub-flow is needed at all. """
    instructions_text = _mft("Scan genesis config")
    invalid_qr_type_message = _mft("Expected a genesis-config QR (BBQr, from the coordinator)")


    def __init__(self, seed: Seed):
        super().__init__()
        self.seed = seed


    @property
    def is_valid_qr_type(self):
        return self.decoder.is_sevenf_bbqr


    def _handle_complete_scan(self):
        canonical_bytes = self.decoder.get_sevenf_bbqr_data()

        # Self-validation: file_type on the wire is not authoritative (any
        # BBQr file-type byte could be attached to any bytes) -- the real
        # check is whether parse_canonical_bytes() itself accepts them, the
        # same "refuse rather than guess" doctrine every other scan-dispatch
        # branch in this codebase already applies (see e.g.
        # EvmScanSignRequestView's own is_real_transaction_payload() check).
        try:
            genesis_config.parse_canonical_bytes(canonical_bytes)
        except GenesisConfigError as e:
            return Destination(SevenFUnsupportedArtefactView, view_args=dict(
                reason=_("Couldn't parse this as a genesis-config: {}").format(e)))

        return Destination(
            SevenFGenesisReviewStartView,
            view_args=dict(seed=self.seed, canonical_bytes=canonical_bytes),
            skip_current_view=True,
        )



class SevenFUnsupportedArtefactView(View):
    """ Same role as evm_views.EvmUnsupportedSignRequestView -- a scanned
        artefact that claims to be a 7F ceremony payload but doesn't
        actually parse as one. """
    def __init__(self, reason: str):
        super().__init__()
        self.reason = reason


    def run(self):
        from seedsigner.gui.screens import DireWarningScreen
        from seedsigner.gui.components import SeedSignerIconConstants
        self.run_screen(
            DireWarningScreen,
            title=_("Unsupported Artefact"),
            show_back_button=False,
            status_icon_name=SeedSignerIconConstants.ERROR,
            status_headline=_("Can't Parse This"),
            text=self.reason,
            button_data=[ButtonOption("OK")],
        )
        return Destination(MainMenuView, skip_current_view=True)



class SevenFGenesisReviewStartView(View):
    """ Entry point: parses the received canonical bytes (never trusts a
        separately-supplied "friendly" description of what they contain --
        same self-validation principle as chains/base.py's ChainPlugin
        contract) and stashes the resulting review fields for paging.

        chain_kind is deliberately NOT a constructor parameter: it comes
        only from the parsed bytes (fields.chain_kind), never from a
        separately-supplied value that could diverge from what's actually
        signed -- the same self-validation principle this class's own
        docstring already states. An earlier version of this view took
        chain_kind as an independent argument; caught and fixed while
        wiring the real scan/export flow, before any scan entry point ever
        shipped a caller that could have supplied a mismatched value. """
    def __init__(self, seed: Seed, canonical_bytes: bytes):
        super().__init__()
        self.seed = seed

        fields = genesis_config.parse_canonical_bytes(canonical_bytes)
        self.controller.sevenf_ceremony_data = dict(
            seed=seed,
            chain_kind=fields.chain_kind,
            canonical_bytes=canonical_bytes,
            fields=fields,
            review_fields=genesis_config.review_fields(fields),
        )


    def run(self):
        return Destination(SevenFGenesisReviewFieldView, view_args=dict(page_num=0), skip_current_view=True)



class SevenFGenesisReviewFieldView(View):
    """ Pages through the genesis-config's review fields one concern per
        screen -- the concrete no-blind-signing mechanism. See
        gui/screens/sevenf_screens.py's SevenFReviewFieldScreen. """
    def __init__(self, page_num: int = 0):
        super().__init__()
        self.page_num = page_num
        data = self.controller.sevenf_ceremony_data
        self.fields: list[ReviewField] = data["review_fields"]

        if self.page_num >= len(self.fields):
            raise Exception("Bug in 7F genesis-config review field paging")


    def run(self):
        from seedsigner.gui.screens.sevenf_screens import SevenFReviewFieldScreen
        field = self.fields[self.page_num]
        is_final_page = self.page_num == len(self.fields) - 1

        selected_menu_num = self.run_screen(
            SevenFReviewFieldScreen,
            page_title=_("Review Genesis Config"),
            label_text=field.label,
            value_text=field.value,
            page_num=self.page_num,
            num_pages=len(self.fields),
            is_final_page=is_final_page,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            if self.page_num == 0:
                self.controller.sevenf_ceremony_data = None
            return Destination(BackStackView)

        if is_final_page:
            return Destination(SevenFConfirmSignView)
        else:
            return Destination(SevenFGenesisReviewFieldView, view_args=dict(page_num=self.page_num + 1))



class SevenFConfirmSignView(View):
    """ Final review step: confirms which chain and which Root CA address
        the signature will be attributed to, then performs the actual
        signing. This is the ONLY caller permitted to pass confirmed=True
        into root_ceremony.sign_with_root_ca() -- see that function's own
        docstring for why this is an enforced precondition, not a UI step
        that merely happens to run first. """
    def __init__(self):
        super().__init__()
        data = self.controller.sevenf_ceremony_data
        self.seed: Seed = data["seed"]
        self.chain_kind: ChainKind = data["chain_kind"]
        self.canonical_bytes: bytes = data["canonical_bytes"]

        keys = root_ceremony.derive_root_ceremony_keys(self.seed.seed_bytes, self.chain_kind)
        self.root_ca_address = keys.root_ca.address


    def run(self):
        from seedsigner.gui.screens.sevenf_screens import SevenFConfirmSignScreen
        selected_menu_num = self.run_screen(
            SevenFConfirmSignScreen,
            chain_kind_name=self.chain_kind.name.lower(),
            address=self.root_ca_address,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # Operator clicked "Sign" -- the one and only call site allowed to pass
        # confirmed=True (root_ceremony.sign_with_root_ca's own docstring).
        public_key, signature = root_ceremony.sign_with_root_ca(
            self.seed.seed_bytes,
            self.chain_kind,
            self.canonical_bytes,
            confirmed=True,
        )
        self.controller.sevenf_ceremony_data["public_key"] = public_key
        self.controller.sevenf_ceremony_data["signature"] = signature
        return Destination(SevenFGenesisSignedView)



class SevenFGenesisSignedView(View):
    """ Success confirmation, then on to exporting the signed result --
        matches how SeedWordsBackupTestSuccessView plays the same
        success-then-continue role for the backup-verification flow. """
    def run(self):
        from seedsigner.gui.screens.screen import ButtonOption, LargeIconStatusScreen
        self.run_screen(
            LargeIconStatusScreen,
            title=_("Genesis Config Signed"),
            show_back_button=False,
            status_headline=_("Success!"),
            text=_("The genesis-config has been signed with the Root CA key."),
            button_data=[ButtonOption("OK")],
        )
        return Destination(SevenFExportView)



class SevenFExportView(View):
    """ Menu offering the two export artifacts this story's own scope
        defines (_delivery/backlog.yaml's 7f-signing-support-root-ceremony-export-flow:
        "Two export artifacts, not three"): the Root CA public key (for
        cross-checking against sf-wallet-side output) and the final signed
        genesis-config JSON. QR-only, per that requirements doc's R16 -- no
        SD-card export, matching this story's own "no longer a size-driven
        requirement" note. Reachable repeatedly (each export routes back
        here) so an operator can export both artifacts in one sitting. """
    EXPORT_PUBKEY = ButtonOption("Export Root CA Pubkey")
    EXPORT_SIGNED_CONFIG = ButtonOption("Export Signed Config")

    def run(self):
        from seedsigner.gui.screens.screen import ButtonListScreen
        button_data = [self.EXPORT_PUBKEY, self.EXPORT_SIGNED_CONFIG]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Export"),
            is_button_text_centered=True,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(MainMenuView, skip_current_view=True)

        if button_data[selected_menu_num] == self.EXPORT_PUBKEY:
            return Destination(SevenFExportPubkeyQRView)
        else:
            return Destination(SevenFExportSignedConfigQRView)



class SevenFExportPubkeyQRView(View):
    """ Exports the Root CA public key as hex, BBQr-encoded -- the first of
        the two export artifacts, for cross-checking against sf-wallet-side
        output (per sf-root.rs's own root_vk_hex = hex::encode(pubkey)). """
    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
        from seedsigner.models.encode_qr import BBQrEncoder
        data = self.controller.sevenf_ceremony_data
        pubkey_hex = data["public_key"].hex().encode("utf-8")

        self.run_screen(
            QRDisplayScreen,
            qr_encoder=BBQrEncoder(data=pubkey_hex, file_type="U"),  # 'U': BBQr unicode/plain-text
        )
        return Destination(SevenFExportView, skip_current_view=True)



class SevenFExportSignedConfigQRView(View):
    """ Exports the final signed genesis-config as BBQr-encoded JSON -- the
        second export artifact, matching sf-core::GenesisConfig's real,
        current on-wire shape exactly (genesis_config.build_signed_json()'s
        own docstring has the field-by-field confirmation). """
    def run(self):
        import json

        from seedsigner.gui.screens.screen import QRDisplayScreen
        from seedsigner.models.encode_qr import BBQrEncoder
        data = self.controller.sevenf_ceremony_data
        signed_json = genesis_config.build_signed_json(
            data["fields"], data["public_key"], data["signature"],
        )
        json_bytes = json.dumps(signed_json).encode("utf-8")

        self.run_screen(
            QRDisplayScreen,
            qr_encoder=BBQrEncoder(data=json_bytes, file_type="J"),  # 'J': BBQr JSON
        )
        return Destination(SevenFExportView, skip_current_view=True)
