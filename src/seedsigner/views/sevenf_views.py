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
from seedsigner.views.view import BackStackView, Destination, MainMenuView, View, guard_active_chain

# Conservative, character-count-based page budget for a single review field's
# value -- found live 2026-09-27 (7F hardware walkthrough): the genesis-
# config's `message` field is arbitrary-length, coordinator-supplied text
# with no length limit enforced anywhere (Jorge's own call: an arbitrary cap
# invented on the device side would be a protocol decision, not a UI one --
# raise with Patrick separately if the ceremony protocol itself ever wants
# one). IconTextLine's value display has no scrolling primitive and no cap
# of its own -- a long-enough message silently renders past the canvas
# bounds with zero visual indication, which is a real no-blind-signing gap:
# the operator could approve a message they never actually saw in full.
# This is a character-count estimate, not exact pixel measurement -- same
# class of approximation as evm_screens.py's own _MAX_UNBROKEN_VALUE_CHARS.
# If it ever renders a page that doesn't quite fit some font/locale
# combination, the fix is tuning this constant down, not a correctness
# regression: every character is still shown on some page.
_MAX_CHARS_PER_REVIEW_PAGE = 180


def _paginate_value(value: str, max_chars: int = _MAX_CHARS_PER_REVIEW_PAGE) -> list[str]:
    """ Splits a field value into screen-sized pages, breaking only on word
        boundaries. Text already containing "\\n" (only the Timestamp field
        today, via genesis_config._format_timestamp() -- always short) is
        returned as a single page unchanged; pagination only kicks in for
        content that actually needs it and has no embedded hard breaks to
        preserve. """
    if len(value) <= max_chars or "\n" in value:
        return [value]

    pages = []
    current = ""
    for word in value.split(" "):
        candidate = f"{current} {word}".strip() if current else word
        if len(candidate) > max_chars and current:
            pages.append(current)
            current = word
        else:
            current = candidate
    if current:
        pages.append(current)
    return pages if pages else [value]


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

        if guard_active_chain(self, "sevenf"):
            return


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
        gui/screens/sevenf_screens.py's SevenFReviewFieldScreen.

        Pages through *chunks*, not raw fields directly: any field whose
        value doesn't fit _MAX_CHARS_PER_REVIEW_PAGE (see that constant's own
        docstring) gets split into multiple consecutive pages sharing the
        same label, rather than silently rendering past the screen bounds --
        found live 2026-09-27 (7F hardware walkthrough) as a real
        no-blind-signing gap on the message field specifically, but applied
        generically here since any field could in principle grow long. """
    def __init__(self, page_num: int = 0):
        super().__init__()
        self.page_num = page_num
        data = self.controller.sevenf_ceremony_data
        fields: list[ReviewField] = data["review_fields"]
        self.chunks: list[ReviewField] = [
            ReviewField(label=field.label, value=chunk_value)
            for field in fields
            for chunk_value in _paginate_value(field.value)
        ]

        if self.page_num >= len(self.chunks):
            raise Exception("Bug in 7F genesis-config review field paging")


    def run(self):
        from seedsigner.gui.screens.sevenf_screens import SevenFReviewFieldScreen
        chunk = self.chunks[self.page_num]
        is_final_page = self.page_num == len(self.chunks) - 1

        selected_menu_num = self.run_screen(
            SevenFReviewFieldScreen,
            page_title=_("Review Genesis Config"),
            label_text=chunk.label,
            value_text=chunk.value,
            page_num=self.page_num,
            num_pages=len(self.chunks),
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



class SevenFCertRequestReviewFieldView(View):
    """ Pages through a CertRequest's review fields one concern per screen --
        the no-blind-signing screen this project's adversarial plan-stage
        review (2026-09-28) found entirely missing from the original Root
        self-certification / Deputy cross-certification story filing
        (CRITICAL, confirmed independently by two reviewers). Mirrors
        SevenFGenesisReviewFieldView's own pagination exactly (same
        _paginate_value() mechanism, same reason: any field's value could in
        principle grow long, and no-blind-signing means every field is shown
        in full, never silently truncated).

        Deliberately parameterized rather than hardcoded to one flow: Root
        self-certification and Deputy cross-certification both page through
        a CertRequest, via cert_request.review_fields(), but diverge on what
        happens after the operator confirms (a different sign call, a
        different export). Each call site supplies its own page_title and
        the View class + view_args to route to once every field has been
        shown -- this view does not itself call into cert_request.py or
        perform any signing, keeping it reusable and testable in isolation.
        State is carried entirely through view_args (not
        controller.sevenf_ceremony_data, which the unrelated genesis-config
        flow already owns) so this view has no shared-state collision risk
        with that flow. """
    def __init__(
        self,
        review_fields: list[ReviewField],
        page_title: str,
        confirmed_destination: type,
        confirmed_view_args: dict = None,
        page_num: int = 0,
    ):
        super().__init__()
        self.review_fields = review_fields
        self.page_title = page_title
        self.confirmed_destination = confirmed_destination
        self.confirmed_view_args = confirmed_view_args or {}
        self.page_num = page_num
        self.chunks: list[ReviewField] = [
            ReviewField(label=field.label, value=chunk_value)
            for field in review_fields
            for chunk_value in _paginate_value(field.value)
        ]

        if self.page_num >= len(self.chunks):
            raise Exception("Bug in 7F CertRequest review field paging")


    def run(self):
        from seedsigner.gui.screens.sevenf_screens import SevenFReviewFieldScreen
        chunk = self.chunks[self.page_num]
        is_final_page = self.page_num == len(self.chunks) - 1

        selected_menu_num = self.run_screen(
            SevenFReviewFieldScreen,
            page_title=self.page_title,
            label_text=chunk.label,
            value_text=chunk.value,
            page_num=self.page_num,
            num_pages=len(self.chunks),
            is_final_page=is_final_page,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if is_final_page:
            return Destination(self.confirmed_destination, view_args=self.confirmed_view_args)
        else:
            return Destination(
                SevenFCertRequestReviewFieldView,
                view_args=dict(
                    review_fields=self.review_fields,
                    page_title=self.page_title,
                    confirmed_destination=self.confirmed_destination,
                    confirmed_view_args=self.confirmed_view_args,
                    page_num=self.page_num + 1,
                ),
            )



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
    """ Exports the genesis-config signature as BBQr-encoded JSON -- the
        second export artifact. Matches sf-core::genesis_config::RootSig's
        real, current on-wire shape exactly (genesis_config.build_root_sig_json()'s
        own docstring has the field-by-field confirmation): only the
        signature leaves the device per ceremony (D11), not the config
        again -- the coordinator that produced the unsigned config already
        has every other field. """
    def run(self):
        import json

        from seedsigner.gui.screens.screen import QRDisplayScreen
        from seedsigner.models.encode_qr import BBQrEncoder
        data = self.controller.sevenf_ceremony_data
        signed_json = genesis_config.build_root_sig_json(
            data["public_key"], data["signature"],
        )
        json_bytes = json.dumps(signed_json).encode("utf-8")

        self.run_screen(
            QRDisplayScreen,
            qr_encoder=BBQrEncoder(data=json_bytes, file_type="J"),  # 'J': BBQr JSON
        )
        return Destination(SevenFExportView, skip_current_view=True)
