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

from ._clock import ceremony_now, require_confirmed_clock
from ._common import (
    root_public_key,
    SevenFCertRequestReviewFieldView,
    SevenFConfirmSignRootCertView,
    SevenFSignedCertificate,
    SevenFUnsupportedArtefactView,
    key_index_review_field,
)
from ._key_index import SevenFSelectKeyIndexView


class SevenFSelectChainKindForRootSelfCertView(View):
    """ Entry point for Root self-certification's PKCS#10-era rework (see
        cert_request.py's own "ROOT SELF-CERT PKCS#10 REWORK" docstring
        note, and docs/7f-integration/archive/root-self-cert-pkcs10-rework-plan.md).
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
        left to compare the derived key against) -- the compensating control
        is the subject key id on the review screen, read to the coordinator
        and checked against the Root key they enrolled, not a device-side pin
        allowlist (deferred, a federation-level question). """
    def __init__(self, seed: Seed, date_confirmed: bool = False):
        super().__init__()
        self.seed = seed
        self.date_confirmed = date_confirmed

        if guard_active_chain(self, "sevenf"):
            return


    def run(self):
        from seedsigner.gui.screens.screen import ButtonListScreen

        # The certificate's validity starts "now": ask the operator for the
        # date first (once per boot); this device has no clock to trust.
        ask_date = require_confirmed_clock(self)
        if ask_date:
            return ask_date

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

        return Destination(SevenFSelectKeyIndexView, view_args=dict(
            role="root",
            next_destination=SevenFBuildRootSelfCertView,
            next_view_args=dict(seed=self.seed, chain_kind=kinds[selected_menu_num]),
        ))



class SevenFBuildRootSelfCertView(View):
    """ After the network and the Root key index: derive that key, build the
        certificate body and its review fields (7f-signing-support-key-index-
        selector). Moved out of the network view, which used to do this
        inline, because the key depends on the index. """
    def __init__(self, seed: Seed, chain_kind: ChainKind, key_index: int):
        super().__init__()
        self.seed = seed
        self.chain_kind = chain_kind
        self.key_index = key_index


    def run(self):
        chain_kind = self.chain_kind
        subject_vk = root_public_key(self.seed, chain_kind, self.key_index)
        serial = cert_request.generate_serial()
        not_before = ceremony_now(self.controller)
        if not_before is None:
            return Destination(SevenFUnsupportedArtefactView, view_args=dict(
                reason=_("The date and time haven't been confirmed; start again from the menu.")),
                skip_current_view=True)
        days = cert_request.ROOT_DAYS

        try:
            tbs_bytes = cert_request.build_root_tbs(subject_vk, chain_kind, not_before, days, serial)
        except CertRequestError as e:
            return Destination(SevenFUnsupportedArtefactView, view_args=dict(
                reason=_("Couldn't build the certificate body: {}").format(e)),
                skip_current_view=True)

        # DAY = 86_400 seconds, matching cert_request.rs's own constant --
        # no clamping applies to a self-signed Root certificate (unlike
        # Deputy's TBS, which clamps to the issuing Root's own window), so
        # this is the exact value the TBS just built also carries.
        not_after = not_before + days * 86_400
        try:
            review_fields = [
                key_index_review_field(chain_kind, self.key_index),
                *cert_request.root_self_cert_review_fields(subject_vk, chain_kind, not_before, not_after, serial),
            ]
        except CertRequestError as e:
            return Destination(SevenFUnsupportedArtefactView, view_args=dict(
                reason=_("Couldn't show the certificate for review: {}").format(e)),
                skip_current_view=True)

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
                    key_index=self.key_index,
                    signed_view_args=dict(
                        export_destination=SevenFExportRootCertQRView,
                    ),
                ),
            ),
            skip_current_view=True,
        )





class SevenFSelectChainKindForDevfundEnrollmentView(View):
    """ Dev-fund key enrollment: the second vk a federation member sends
        (ceremony-federation-member.md Step 3, sf-wallet-gov `derive-vk --role
        devfund`). 7fchain 89d3d39 locks the dev fund with per-holder keys at
        devfund/<chain_kind>/0/ml-dsa/v1 -- NOT the Root key, and the runbook
        says a dev-fund id equal to the Root id means "stop and call".
        Chain, index, subject key id, then the QR (no pin screen: derive-vk
        prints none for a dev-fund key), titled "Dev-fund VK". """
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
            title=_("Dev-fund: Chain"),
            is_button_text_centered=True,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        return Destination(SevenFSelectKeyIndexView, view_args=dict(
            role="devfund",
            next_destination=SevenFDeriveEnrollmentVkView,
            next_view_args=dict(seed=self.seed, chain_kind=kinds[selected_menu_num], role="devfund"),
        ))



class SevenFDeriveEnrollmentVkView(View):
    """ After the network and the key index: derive the dev-fund key at that
        index and show its ski (7f-signing-support-key-index-selector). The
        dev-fund index is asked for on its own; it is never taken from the Root
        index (what pairs them is open on 7fchain#7). A Root key is not
        enrolled on its own: Self-Certify Root exports its .vk with the
        certificate, as sf-wallet-gov does (derive-vk writes nothing for a Root key). """
    def __init__(self, seed: Seed, chain_kind: ChainKind, role: str, key_index: int):
        super().__init__()
        self.seed = seed
        self.chain_kind = chain_kind
        self.role = role
        self.key_index = key_index


    def run(self):
        if self.role == "root":
            raise ValueError("a Root key needs no separate derive step: Self-Certify Root exports its .vk "
                             "with the certificate (sf-wallet-gov derive-vk writes nothing for a Root key)")
        if self.role != "devfund":
            raise ValueError(f"no enrollment key for role {self.role!r}")
        public_key = root_ceremony.derive_devfund_key(root_ceremony.seed_for_7f(self.seed), self.chain_kind, index=self.key_index).public_key
        title = _("Dev-fund VK")

        return Destination(
            SevenFRootVkFingerprintView,
            view_args=dict(public_key=public_key, title=title, role=self.role, key_index=self.key_index),
            skip_current_view=True,
        )



class SevenFRootVkFingerprintView(View):
    """ Shows the enrollment vk's subject key id (ski -- the 40-hex id
        sf-wallet-gov prints and names the holder's `<ski>.vk` by, 7fchain
        ce04ae9/416f576) directly on the
        device screen before the QR export, so the operator has an
        authoritative value read with their own eyes to compare against
        whatever a phone scanner later decodes from the QR -- catching a
        transport/encoding bug the QR round-trip alone couldn't surface.
        Found live 2026-10-07, asked for mid-ceremony during the first real
        testnet Root VK enrollment ("how can I verify it? -- can I display
        it on the seedsigner screen?"). Same subject key id as
        root_self_cert_review_fields's "Subject key id" field, but this
        operation has no review-fields flow of its own to attach it to
        (derive-vk makes no claim beyond "here is a public key" -- nothing
        else to review), so it gets this one small dedicated screen. Shared
        by Root and dev-fund enrollment; `title` says which key this is. """
    def __init__(self, public_key: bytes, title: str, key_index: int, role: str = "root"):
        super().__init__()
        self.public_key = public_key
        self.title = title
        self.key_index = key_index
        self.role = role


    def run(self):
        from seedsigner.gui.screens.screen import LargeIconStatusScreen
        from seedsigner.models.sevenf.review_format import group_hex_for_display, ski

        selected_menu_num = self.run_screen(
            LargeIconStatusScreen,
            title=self.title,
            status_headline=_("Subject key id"),
            # The index on its own line: in the headline it runs off the screen.
            text=group_hex_for_display(ski(self.public_key.hex())) + "\n" + _("index {}").format(self.key_index),
            button_data=[ButtonOption("Next")],
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # sf-wallet-gov prints a root pin for a Root key only (sign-root-cert);
        # derive-vk prints none for a dev-fund key, so neither does the device.
        if self.role != "root":
            return Destination(SevenFExportRootVkQRView, view_args=dict(public_key=self.public_key, role=self.role))
        return Destination(
            SevenFVkPinView,
            view_args=dict(public_key=self.public_key, title=self.title, role=self.role, key_index=self.key_index),
        )



class SevenFVkPinView(View):
    """ Shows a Root key's root pin -- the full SHA-256 of the key, 7fchain's
        x509::vk_pin(), as sf-wallet-gov sign-root-cert prints it -- before
        the QR export (a dev-fund key has none). A member reports the pin over
        a second channel so the coordinator can confirm the key they received
        is the key the member holds (ceremony-federation-member.md Step 4).
        That check only means something if the pin is read off this device:
        the phone scanner computes it from whatever it scanned, so it would
        agree with a bad scan. Own screen because 64 hex (16 groups) doesn't
        fit beside the subject key id. """
    def __init__(self, public_key: bytes, title: str, key_index: int, role: str = "root"):
        super().__init__()
        self.public_key = public_key
        self.title = title
        self.key_index = key_index
        self.role = role


    def run(self):
        from seedsigner.gui.screens.screen import LargeIconStatusScreen
        from seedsigner.models.sevenf.review_format import group_hex_for_display, pin

        selected_menu_num = self.run_screen(
            LargeIconStatusScreen,
            title=self.title,
            status_headline=_("Index {}: root pin").format(self.key_index),
            text=group_hex_for_display(pin(self.public_key.hex())),
            button_data=[ButtonOption("Continue to QR")],
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        return Destination(
            SevenFExportRootVkQRView,
            view_args=dict(public_key=self.public_key, role=self.role),
        )



class SevenFExportRootVkQRView(View):
    """ Exports an enrollment verification key -- the Root key, or the dev-fund
        key -- as a role-tagged envelope (BBQr 'J', export_envelope.vk_export)
        whose body is exactly sf-wallet-gov's `<ski>.vk` (lowercase hex and a
        newline). Returns to the main menu: nothing else follows a standalone
        enrollment export. """
    def __init__(self, public_key: bytes, role: str = "root"):
        super().__init__()
        self.public_key = public_key
        self.role = role


    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
        from seedsigner.models.encode_qr import BBQrEncoder
        from seedsigner.models.sevenf.export_envelope import vk_export

        # <ski>.vk exactly as sf-wallet-gov writes it, tagged root/devfund so
        # the host page says which inbox it belongs in.
        self.run_screen(
            QRDisplayScreen,
            qr_encoder=BBQrEncoder(data=vk_export(self.role, self.public_key), file_type="J"),
        )
        return Destination(MainMenuView, skip_current_view=True)



class SevenFExportRootCertQRView(View):
    """ Exports the complete, assembled Root self-certification certificate
        as BBQr-encoded binary -- the Root self-cert PKCS#10-era rework's
        fix (docs/7f-integration/archive/root-self-cert-pkcs10-rework-plan.md §3-§4)
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

        from seedsigner.models.sevenf.export_envelope import root_cert_export

        # root-<ski>.pem exactly as sign-root-cert writes it, in an envelope
        # that tells the host page the file name (export_envelope.py).
        self.run_screen(
            QRDisplayScreen,
            qr_encoder=BBQrEncoder(data=root_cert_export(cert_der, self.certificate.public_key), file_type="J"),
        )
        # Runbook Step 2 yields root-<ski>.pem AND <ski>.vk: carry straight on
        # to the Root VK (ski -> pin -> QR) in the same sitting.
        return Destination(
            SevenFRootVkFingerprintView,
            view_args=dict(public_key=self.certificate.public_key, title=_("Root VK"), role="root",
                           key_index=self.certificate.key_index),
            skip_current_view=True,
        )
