"""
    Root self-certification flow (PKCS#10-era ceremony): select the chain,
    build and sign the Root's own certificate entirely locally, export the
    complete assembled certificate. See docs/7f-integration/
    root-self-cert-pkcs10-rework-plan.md.

    Confirm-sign and export of signing happen through _common.py's shared
    SevenFConfirmSignRootCertView/SevenFRootCertSignedView (also used by
    Deputy cross-certification) -- this module holds only the two views
    specific to Root self-cert: the chain-selection entry point and the
    certificate export.
"""
from gettext import gettext as _

from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
from seedsigner.gui.screens.screen import ButtonOption
from seedsigner.models.seed import Seed
from seedsigner.models.sevenf import cert_request, root_ceremony
from seedsigner.models.sevenf.cert_request import CertRequestError
from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.views.view import BackStackView, Destination, MainMenuView, View, guard_active_chain

from ._common import (
    SevenFCertRequestReviewFieldView,
    SevenFConfirmSignRootCertView,
    SevenFSignedCertificate,
    SevenFUnsupportedArtefactView,
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
        `_deputy_cert.SevenFSelectChainKindForDeputyCrossCertView`'s
        already-shipped pattern exactly.

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



class SevenFExportRootCertQRView(View):
    """ Exports the complete, assembled Root self-certification certificate
        as BBQr-encoded binary -- the Root self-cert PKCS#10-era rework's
        fix (docs/7f-integration/root-self-cert-pkcs10-rework-plan.md §3-§4)
        for the detached-signature-export bug: the real ceremony's
        `sign-root-cert` exports a complete certificate, and this device's
        prior detached-signature export (D11's RootSig shape) is
        unreconstructable downstream for an artifact whose TBS carries
        device-chosen fields (a CSPRNG serial, a wall-clock `not_before`).
        Does NOT route through _genesis.SevenFExportView's pubkey/signed-
        config menu -- those two options are for genesis-config signing's
        own detached-signature shape, which this artifact doesn't use
        (single artifact, no menu -- mirrors
        _devfund.SevenFExportSignedDevFundConfigQRView's direct-to-
        MainMenuView routing, not the two-option menu's).

        `certificate` (added 2026-10-04, 7f-review-ceremony-data-untyped-
        shared-dict) replaces the former read of
        controller.sevenf_ceremony_data. """
    def __init__(self, certificate: SevenFSignedCertificate):
        super().__init__()
        self.certificate = certificate


    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
        from seedsigner.models.encode_qr import BBQrEncoder
        cert_der = cert_request.assemble_root_cert_der(
            self.certificate.tbs_bytes, self.certificate.signature, self.certificate.public_key,
        )

        self.run_screen(
            QRDisplayScreen,
            qr_encoder=BBQrEncoder(data=cert_der, file_type="B"),  # 'B': BBQr generic binary
        )
        return Destination(MainMenuView, skip_current_view=True)
