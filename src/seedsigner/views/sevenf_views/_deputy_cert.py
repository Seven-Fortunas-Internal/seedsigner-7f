"""
    Deputy cross-certification flow (PKCS#10-based ceremony): select the
    chain, scan the Root's own real signed certificate, scan the Deputy's
    real self-signed PKCS#10 CSR, review, sign, export the complete
    assembled Deputy certificate. See docs/7f-integration/
    deputy-cross-cert-pkcs10-rework-plan.md.

    Confirm-sign and export of signing happen through _common.py's shared
    SevenFConfirmSignRootCertView/SevenFRootCertSignedView (also used by
    Root self-certification) -- this module holds the four views specific
    to Deputy cross-cert: chain selection, the two scans, and the
    certificate export.
"""
from gettext import gettext as _

from seedsigner.helpers.l10n import mark_for_translation as _mft
from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
from seedsigner.gui.screens.screen import ButtonOption
from seedsigner.models.seed import Seed
from seedsigner.models.sevenf import cert_request, root_ceremony
from seedsigner.models.sevenf.cert_request import CertRequestError
from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.views.scan_views import ScanView
from seedsigner.views.view import BackStackView, Destination, MainMenuView, View, guard_active_chain

from ._common import SevenFCertRequestReviewFieldView, SevenFConfirmSignRootCertView, SevenFUnsupportedArtefactView


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



class SevenFExportDeputyCertQRView(View):
    """ Exports the complete, assembled Deputy cross-certification
        certificate as BBQr-encoded binary -- the Deputy half of
        7f-signing-support-detached-sig-export-unreconstructable's fix
        (docs/7f-integration/deputy-cross-cert-detached-sig-export-fix-plan.md),
        mirroring _root_cert.SevenFExportRootCertQRView exactly except for
        the one real design difference: assemble_deputy_cert_der() verifies
        the signature against the ISSUING ROOT's real key (re-parsed from
        `root_cert_der`), not the Deputy's own subject key, since this
        certificate is CA-issued rather than self-signed. Does NOT route
        through _genesis.SevenFExportView's pubkey/signed-config menu, same
        reasoning as the Root export. """
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
