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
from seedsigner.models.sevenf import cert_request, devfund_config, genesis_config, root_ceremony
from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.models.sevenf.cert_request import CertRequestError
from seedsigner.models.sevenf.devfund_config import DevFundConfigError
from seedsigner.models.sevenf.genesis_config import GenesisConfigJsonError
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
        seed-selection sub-flow is needed at all.

        RESOLVED 2026-10-03 (7f-signing-support-genesis-wire-envelope-
        undefined): the scanned payload is the REAL coordinator artifact --
        `sf-root prepare-genesis`'s JSON file -- not raw canonical bytes.
        This view parses that JSON directly (genesis_config.
        parse_genesis_config_json()) and builds canonical bytes from the
        extracted fields internally; everything downstream
        (SevenFGenesisReviewStartView onward) is unchanged and still
        operates on, and signs, the exact bytes `sf-root sign-genesis`
        would. """
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
        payload = self.decoder.get_sevenf_bbqr_data()

        # Self-validation: file_type on the wire is not authoritative (any
        # BBQr file-type byte could be attached to any bytes) -- the real
        # check is whether parse_genesis_config_json() itself accepts them,
        # the same "refuse rather than guess" doctrine every other
        # scan-dispatch branch in this codebase already applies (see e.g.
        # EvmScanSignRequestView's own is_real_transaction_payload() check).
        try:
            fields = genesis_config.parse_genesis_config_json(payload)
        except GenesisConfigJsonError as e:
            return Destination(SevenFUnsupportedArtefactView, view_args=dict(
                reason=_("Couldn't parse this as a genesis-config: {}").format(e)))

        canonical_bytes = genesis_config.build_canonical_bytes(
            fields.chain_kind, fields.timestamp, fields.message, fields.consensus,
        )

        return Destination(
            SevenFGenesisReviewStartView,
            view_args=dict(seed=self.seed, canonical_bytes=canonical_bytes),
            skip_current_view=True,
        )



class SevenFSelectChainKindForRootSelfCertView(View):
    """ Entry point for Root self-certification's PKCS#10-era rework (see
        cert_request.py's own "ROOT SELF-CERT PKCS#10 REWORK" docstring
        note, and docs/7f-integration/root-self-cert-pkcs10-rework-plan.md).
        7fchain's real `sign-root-cert` has no external input at all -- the
        Root derives its own key, builds its own TBS, signs, and assembles
        a complete certificate, all locally. This device mirrors that: no
        scan step exists at all (the retired `SevenFScanRootCertRequestView`
        and `_parse_root_request_or_error_destination()` are both gone --
        confirmed via `grep` that neither had any other caller), just an
        explicit chain_kind selection, mirroring
        `SevenFSelectChainKindForDeputyCrossCertView`'s already-shipped
        pattern exactly.

        Removing the scanned CertRequest also removes the old
        `subject_matches()` fail-closed cross-check it carried (nothing
        left to compare the derived key against) -- the plan's §5.1/§8
        compensating control is the mandatory enrollment-fingerprint check
        on the review screen this view routes to, not a device-side
        pin allowlist (deferred, a federation-level question). """
    def __init__(self, seed: Seed):
        super().__init__()
        self.seed = seed

        if guard_active_chain(self, "sevenf"):
            return


    def run(self):
        import time

        from seedsigner.gui.screens.screen import ButtonListScreen
        kinds = list(ChainKind)
        button_data = [ButtonOption(k.name.lower()) for k in kinds]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Root Self-Cert: Chain"),
            is_button_text_centered=True,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        chain_kind = kinds[selected_menu_num]
        keys = root_ceremony.derive_root_ceremony_keys(self.seed.seed_bytes, chain_kind)
        subject_vk = keys.root_ca.public_key
        serial = cert_request.generate_serial()
        not_before = int(time.time())
        days = cert_request.ROOT_DAYS

        try:
            tbs_bytes = cert_request.build_root_tbs(subject_vk, chain_kind, not_before, days, serial)
        except CertRequestError as e:
            return Destination(SevenFUnsupportedArtefactView, view_args=dict(
                reason=_("Couldn't build the certificate body: {}").format(e)))

        # DAY = 86_400 seconds, matching cert_request.rs's own constant --
        # no clamping applies to a self-signed Root certificate (unlike
        # Deputy's TBS, which clamps to the issuing Root's own window), so
        # this is the exact value the TBS just built also carries.
        not_after = not_before + days * 86_400
        review_fields = cert_request.root_self_cert_review_fields(subject_vk, chain_kind, not_before, not_after, serial)

        return Destination(
            SevenFCertRequestReviewFieldView,
            view_args=dict(
                review_fields=review_fields,
                page_title=_("Review Root Certificate"),
                confirmed_destination=SevenFConfirmSignRootCertView,
                confirmed_view_args=dict(
                    seed=self.seed,
                    chain_kind=chain_kind,
                    tbs_bytes=tbs_bytes,
                    signed_view_args=dict(
                        export_destination=SevenFExportRootCertQRView,
                    ),
                ),
            ),
        )



class SevenFSelectChainKindForDeputyCrossCertView(View):
    """ First step of the PKCS#10-based Deputy cross-certification flow
        (see cert_request.py's own "PKCS#10 REWORK" docstring note, and
        docs/7f-integration/deputy-cross-cert-pkcs10-rework-plan.md). A real
        signed X.509 certificate carries no separate "which 7F network"
        signal of its own distinct from its embedded chain_kind extension
        (plan §3.4) -- so, unlike the retired JSON-CertRequest flow, the
        operator must state the chain explicitly before anything is
        scanned. The chain chosen here is then cross-checked against the
        scanned Root certificate's own embedded chain_kind in
        SevenFScanRootCertificateView (fail-closed on mismatch), exactly
        the way the retired flow's Deputy request was checked against the
        Root request's `kind` -- the cross-check moved, it was not
        dropped. Mirrors EvmNetworkView's own ButtonListScreen usage. """
    def __init__(self, seed: Seed):
        super().__init__()
        self.seed = seed

        if guard_active_chain(self, "sevenf"):
            return


    def run(self):
        from seedsigner.gui.screens.screen import ButtonListScreen
        kinds = list(ChainKind)
        button_data = [ButtonOption(k.name.lower()) for k in kinds]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Deputy Cross-Cert: Chain"),
            is_button_text_centered=True,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        return Destination(
            SevenFScanRootCertificateView,
            view_args=dict(seed=self.seed, chain_kind=kinds[selected_menu_num]),
        )



class SevenFScanRootCertificateView(ScanView):
    """ First of two scans for the PKCS#10-based Deputy cross-certification
        flow: the Root's OWN real, signed X.509 certificate -- never
        reconstructed (plan §2's rejected-alternative). Two fail-closed
        checks before proceeding, both at the scan boundary rather than
        deferred to review (same doctrine as the retired flow's
        _parse_root_request_or_error_destination(), which this flow no
        longer shares since there is no CertRequest JSON left to parse
        here):

        1. Chain mismatch: the certificate's own embedded chain_kind
           (parse_root_certificate_der) must equal the operator's
           selection from the prior screen -- a PKCS#10-adjacent
           certificate carries no other network signal to check against
           (plan §3.4).
        2. Wrong key: the certificate's subject_vk must equal THIS
           device's own derived Root CA key for the selected chain --
           otherwise this device would go on to issue a Deputy
           certificate under an identity it doesn't hold, mirroring the
           "Wrong Key" refusal _parse_root_request_or_error_destination()
           already enforced in the retired flow (not named as its own
           explicit plan bullet, but the same reasoning applies
           unchanged: a well-formed artefact for the wrong identity is
           still not this device's business to sign). """
    instructions_text = _mft("Scan the Root's own certificate")
    invalid_qr_type_message = _mft("Expected a Root certificate QR (BBQr, from the coordinator)")


    def __init__(self, seed: Seed, chain_kind: ChainKind):
        super().__init__()
        self.seed = seed
        self.chain_kind = chain_kind

        if guard_active_chain(self, "sevenf"):
            return


    @property
    def is_valid_qr_type(self):
        return self.decoder.is_sevenf_bbqr


    def _handle_complete_scan(self):
        data = self.decoder.get_sevenf_bbqr_data()

        try:
            root_cert = cert_request.parse_root_certificate_der(data)
        except CertRequestError as e:
            return Destination(SevenFUnsupportedArtefactView, view_args=dict(
                reason=_("Couldn't parse this as a Root certificate: {}").format(e)))

        if root_cert.chain_kind != self.chain_kind:
            return Destination(SevenFUnsupportedArtefactView, view_args=dict(
                headline=_("Chain Mismatch"),
                reason=_("This certificate is for {}, but {} was selected. "
                         "A cross-certification never spans networks.").format(
                             root_cert.chain_kind.name.lower(), self.chain_kind.name.lower()),
            ))

        keys = root_ceremony.derive_root_ceremony_keys(self.seed.seed_bytes, self.chain_kind)
        if root_cert.subject_vk != keys.root_ca.public_key:
            return Destination(SevenFUnsupportedArtefactView, view_args=dict(
                headline=_("Wrong Key"),
                reason=_("This certificate is for a different Root's key. This seed's own Root CA key for "
                         "{} does not match the subject key in the scanned certificate.").format(
                             self.chain_kind.name.lower()),
            ))

        return Destination(
            SevenFScanDeputyCsrView,
            view_args=dict(seed=self.seed, chain_kind=self.chain_kind, root_cert_der=data, root_cert=root_cert),
            skip_current_view=True,
        )



class SevenFScanDeputyCsrView(ScanView):
    """ Second of two scans: the Deputy's own self-signed PKCS#10 CSR,
        proof-of-possession verified on-device (this device's first-ever
        signature verification over untrusted scanned input -- see
        cert_request.py's own "PKCS#10 REWORK" docstring note). Builds the
        Deputy TBS body against the real Root certificate from the prior
        scan, using a fresh device-CSPRNG serial and the current wall-clock
        time (the Rust-side `build_deputy_tbs_v2` re-parses/re-verifies
        both inputs itself -- no earlier parse is trusted, closing any
        TOCTOU gap). Review fields show BOTH the real Root certificate's
        own identity and validity window (plan §8: a genuine-but-wrong
        certificate -- different Root, backdated, unexpectedly long-lived
        -- must be just as catchable as a wrong fingerprint) and the
        Deputy's own fields, via cert_request.deputy_cross_cert_v2_review_fields(). """
    instructions_text = _mft("Scan the Deputy's certificate request")
    invalid_qr_type_message = _mft("Expected a Deputy certificate request QR (BBQr, from the coordinator)")


    def __init__(self, seed: Seed, chain_kind: ChainKind, root_cert_der: bytes, root_cert):
        super().__init__()
        self.seed = seed
        self.chain_kind = chain_kind
        self.root_cert_der = root_cert_der
        self.root_cert = root_cert

        if guard_active_chain(self, "sevenf"):
            return


    @property
    def is_valid_qr_type(self):
        return self.decoder.is_sevenf_bbqr


    def _handle_complete_scan(self):
        import time
        deputy_csr_der = self.decoder.get_sevenf_bbqr_data()

        try:
            csr = cert_request.verify_and_parse_csr_der(deputy_csr_der)
        except CertRequestError as e:
            return Destination(SevenFUnsupportedArtefactView, view_args=dict(
                reason=_("Couldn't verify this certificate request: {}").format(e)))

        now = int(time.time())
        days = cert_request.DEPUTY_DAYS
        serial = cert_request.generate_serial()

        try:
            tbs_bytes = cert_request.build_deputy_tbs_v2(
                self.root_cert_der, deputy_csr_der, self.chain_kind, now, days, serial,
            )
        except CertRequestError as e:
            return Destination(SevenFUnsupportedArtefactView, view_args=dict(
                reason=_("Couldn't build the Deputy certificate body: {}").format(e)))

        review_fields = cert_request.deputy_cross_cert_v2_review_fields(
            self.root_cert, csr, self.chain_kind, now, days, serial,
        )

        return Destination(
            SevenFCertRequestReviewFieldView,
            view_args=dict(
                review_fields=review_fields,
                page_title=_("Review Deputy Certificate"),
                confirmed_destination=SevenFConfirmSignRootCertView,
                confirmed_view_args=dict(
                    seed=self.seed,
                    chain_kind=self.chain_kind,
                    tbs_bytes=tbs_bytes,
                    root_cert_der=self.root_cert_der,
                    signed_view_args=dict(
                        title=_("Deputy Certificate Signed"),
                        text=_("This Deputy's certificate has been signed by this Root and is ready to export."),
                        export_destination=SevenFExportDeputyCertQRView,
                    ),
                ),
            ),
            skip_current_view=True,
        )



class SevenFUnsupportedArtefactView(View):
    """ Same role as evm_views.EvmUnsupportedSignRequestView -- a scanned
        artefact that claims to be a 7F ceremony payload but doesn't
        actually parse as one, or (via the optional `headline` override)
        parses fine but must still be refused for a different reason --
        e.g. a well-formed CertRequest whose subject_vk doesn't match this
        device's own derived key (the fail-closed refusal an adversarial
        security review required: "This request is for Root X, and this
        database holds Root Y", mirroring sf-root.rs's own hard refusal).
        `headline` defaults to the original "Can't Parse This" wording so
        every existing call site is unaffected. """
    def __init__(self, reason: str, headline: str = None):
        super().__init__()
        self.reason = reason
        self.headline = headline if headline is not None else _("Can't Parse This")


    def run(self):
        from seedsigner.gui.screens import DireWarningScreen
        from seedsigner.gui.components import SeedSignerIconConstants
        self.run_screen(
            DireWarningScreen,
            title=_("Unsupported Artefact"),
            show_back_button=False,
            status_icon_name=SeedSignerIconConstants.ERROR,
            status_headline=self.headline,
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



class SevenFConfirmSignRootCertView(View):
    """ Final review step for Root self-certification: confirms which chain
        and which Root CA address the signature will be attributed to (same
        confirmation content and same SevenFConfirmSignScreen as genesis
        signing -- confirming WHICH key signs is identical regardless of
        WHAT artefact it signs), then performs the actual signing. This is
        the ONLY caller permitted to pass confirmed=True for this flow, same
        contract as SevenFConfirmSignView.

        Reuses root_ceremony.sign_with_root_ca() unmodified -- it already
        signs an arbitrary `message`, so signing a CertRequest's TBS bytes
        needs no new signing primitive, only a new caller. Writes into
        controller.sevenf_ceremony_data on success, now including
        `tbs_bytes` itself (previously discarded here -- see
        docs/7f-integration/root-self-cert-pkcs10-rework-plan.md §3 for why
        that was a real, already-shipped bug: a TBS whose serial/not_before
        are device-chosen can never be reconstructed downstream from a
        detached signature alone). `root_cert_der` is the Deputy flow's own
        extra piece of context (the issuing Root's real certificate,
        carried from SevenFScanRootCertificateView) -- None for Root
        self-cert, which has no separate issuer to carry. Closes the Deputy
        half of 7f-signing-support-detached-sig-export-unreconstructable
        (the Root half shipped in the PKCS#10 rework above).

        Shared by Root self-certification AND Deputy cross-certification
        (both sign an arbitrary TBS body with this same Root key) --
        `signed_view_args` is the one thing that differs between them (the
        success message's wording, and now which export view follows),
        passed straight through to SevenFRootCertSignedView; defaults to
        that view's own Root self-cert wording/export so the Deputy call
        site needs no changes. """
    def __init__(self, seed: Seed, chain_kind: ChainKind, tbs_bytes: bytes, root_cert_der: bytes = None, signed_view_args: dict = None):
        super().__init__()
        self.seed = seed
        self.chain_kind = chain_kind
        self.tbs_bytes = tbs_bytes
        self.root_cert_der = root_cert_der
        self.signed_view_args = signed_view_args or {}

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
        # confirmed=True for this flow (root_ceremony.sign_with_root_ca's own docstring).
        public_key, signature = root_ceremony.sign_with_root_ca(
            self.seed.seed_bytes,
            self.chain_kind,
            self.tbs_bytes,
            confirmed=True,
        )
        self.controller.sevenf_ceremony_data = dict(
            public_key=public_key, signature=signature, tbs_bytes=self.tbs_bytes, root_cert_der=self.root_cert_der,
        )
        return Destination(SevenFRootCertSignedView, view_args=self.signed_view_args)



class SevenFRootCertSignedView(View):
    """ Success confirmation for Root self-certification AND Deputy cross-
        certification (both sign via SevenFConfirmSignRootCertView, which
        is itself artefact-agnostic -- see that class's own docstring).
        `title`/`text` default to the original Root self-cert wording so
        that flow's pre-existing behavior stays unchanged for callers that
        don't override them; the Deputy flow supplies its own.
        `export_destination` defaults to SevenFExportView (the original
        pubkey/signed-config menu, kept only as the fallback for any future
        caller that doesn't override it). Both existing flows now override
        it: Root self-cert's call site to SevenFExportRootCertQRView, and
        Deputy cross-certification's to SevenFExportDeputyCertQRView --
        each exports the complete assembled certificate rather than a
        detached signature (see
        docs/7f-integration/root-self-cert-pkcs10-rework-plan.md §3-§4 and
        docs/7f-integration/deputy-cross-cert-detached-sig-export-fix-plan.md).
        Mirrors SevenFGenesisSignedView's shape but kept as its own class
        rather than parameterizing THAT one too -- genesis-config signing is
        a separate artefact family with its own hardware-tested call site,
        and giving it this override it never actually uses would only add
        unused surface. """
    def __init__(self, title: str = None, text: str = None, export_destination: type = None):
        super().__init__()
        self.title = title if title is not None else _("Root Certificate Signed")
        self.text = text if text is not None else _("This Root's own certificate has been signed and is ready to export.")
        # Defaults to the ORIGINAL export menu, not the new certificate
        # export -- this keeps every existing caller (Deputy's own
        # signed_view_args, which never sets this) unchanged. Root
        # self-cert's own call site is the one that explicitly opts into
        # SevenFExportRootCertQRView.
        self.export_destination = export_destination if export_destination is not None else SevenFExportView


    def run(self):
        from seedsigner.gui.screens.screen import ButtonOption, LargeIconStatusScreen
        self.run_screen(
            LargeIconStatusScreen,
            title=self.title,
            show_back_button=False,
            status_headline=_("Success!"),
            text=self.text,
            button_data=[ButtonOption("OK")],
        )
        return Destination(self.export_destination)



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



class SevenFExportRootCertQRView(View):
    """ Exports the complete, assembled Root self-certification certificate
        as BBQr-encoded binary -- the Root self-cert PKCS#10-era rework's
        fix (docs/7f-integration/root-self-cert-pkcs10-rework-plan.md §3-§4)
        for the detached-signature-export bug: the real ceremony's
        `sign-root-cert` exports a complete certificate, and this device's
        prior detached-signature export (D11's RootSig shape) is
        unreconstructable downstream for an artifact whose TBS carries
        device-chosen fields (a CSPRNG serial, a wall-clock `not_before`).
        Does NOT route through SevenFExportView's pubkey/signed-config menu
        -- those two options are for genesis-config signing's own
        detached-signature shape, which this artifact doesn't use (single
        artifact, no menu -- mirrors SevenFExportSignedDevFundConfigQRView's
        direct-to-MainMenuView routing, not the two-option menu's). """
    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
        from seedsigner.models.encode_qr import BBQrEncoder
        data = self.controller.sevenf_ceremony_data
        cert_der = cert_request.assemble_root_cert_der(
            data["tbs_bytes"], data["signature"], data["public_key"],
        )

        self.run_screen(
            QRDisplayScreen,
            qr_encoder=BBQrEncoder(data=cert_der, file_type="B"),  # 'B': BBQr generic binary
        )
        return Destination(MainMenuView, skip_current_view=True)



class SevenFExportDeputyCertQRView(View):
    """ Exports the complete, assembled Deputy cross-certification
        certificate as BBQr-encoded binary -- the Deputy half of
        7f-signing-support-detached-sig-export-unreconstructable's fix
        (docs/7f-integration/deputy-cross-cert-detached-sig-export-fix-plan.md),
        mirroring SevenFExportRootCertQRView exactly except for the one real
        design difference: assemble_deputy_cert_der() verifies the signature
        against the ISSUING ROOT's real key (re-parsed from `root_cert_der`),
        not the Deputy's own subject key, since this certificate is CA-issued
        rather than self-signed. Does NOT route through SevenFExportView's
        pubkey/signed-config menu, same reasoning as the Root export. """
    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
        from seedsigner.models.encode_qr import BBQrEncoder
        data = self.controller.sevenf_ceremony_data
        cert_der = cert_request.assemble_deputy_cert_der(
            data["tbs_bytes"], data["signature"], data["root_cert_der"],
        )

        self.run_screen(
            QRDisplayScreen,
            qr_encoder=BBQrEncoder(data=cert_der, file_type="B"),  # 'B': BBQr generic binary
        )
        return Destination(MainMenuView, skip_current_view=True)



class SevenFScanDevFundConfigView(ScanView):
    """ Scans the BBQr-encoded devfund-config the coordinator (sf-root)
        sends to this signer -- R11's "development-fund configuration"
        artefact, the third of the three signable artefacts that section
        requires (genesis config and Deputy certificates are the other
        two, both already built). Mirrors SevenFScanGenesisConfigView
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
        CA address shown by SevenFConfirmSignRootCertView's own confirm
        screen, "different derived keys off the same seed." That was the
        exact bug root_ceremony.py's own BUG FIX note fixed -- devfund and
        Root CA are now the SAME key (confirmed against 7fchain's real
        sf-root.rs: cmd_sign_genesis/cmd_sign_devfund both call the
        byte-identical root_key_from_file()). This screen still shows
        `keys.devfund.address` (now always equal to `keys.root_ca.address`)
        -- kept as a separate View/confirm screen from
        SevenFConfirmSignRootCertView for artefact-type clarity (genesis
        vs. devfund-config is still a real distinction the operator should
        see named), not because it disambiguates two different signing
        identities any more. Do not "restore" a separate devfund derivation
        here -- that would reintroduce the fixed bug.

        Reuses root_ceremony.sign_with_devfund() unmodified. This is the
        ONLY caller permitted to pass confirmed=True for this flow, same
        contract as SevenFConfirmSignRootCertView. """
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
        two-artifact SevenFExportView menu, devfund signing only ever
        produces one exportable artifact (the signature), so there's no
        menu to show. """
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
        other export in this file. """
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
