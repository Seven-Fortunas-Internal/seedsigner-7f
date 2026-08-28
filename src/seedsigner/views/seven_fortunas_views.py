"""
    7F integration (Phase 1 UI-walkthrough demo).

    Full View/Screen navigation flow for 7F address display and sign-request
    review/sign, using placeholder addresses and a fake signature -- NO real
    derivation, NO real Falcon-512 signing. The goal of this phase is purely to put
    the actual review screens in front of reviewers before any crypto backend work is
    invested (see docs/7f-integration/README.md's "Phased rollout", Phase 2, and its
    "No blind-signing" principle, in the diy-seedsigner repo).

    Follows the same file-pairing convention as the rest of this codebase
    (seed_views.py <-> seed_screens.py); see seven_fortunas_screens.py for the paired
    Screen classes.

    Reached from one new gated button on SeedOptionsView (see seed_views.py), behind
    Settings > Advanced > "7F signing (demo)" (SETTING__SEVENF_ENABLED, disabled by
    default). Reuses the already-loaded `Seed` object exactly the way every other
    SeedOptionsView destination does -- no new seed-acquisition code needed.
"""
import hashlib
import logging
import os

from gettext import gettext as _

from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
from seedsigner.gui.screens.screen import ButtonOption
from seedsigner.models.encode_qr import GenericStaticQrEncoder
from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants
from seedsigner.views.view import BackStackView, Destination, MainMenuView, NotYetImplementedView, OptionDisabledView, View


logger = logging.getLogger(__name__)


# Ordered (label, data-key) pairs for the paged sign-request review. Any key whose
# value is missing/None on the scanned payload is skipped -- not every 7F operation
# type carries an amount/counterparty (e.g. some L1 approvals don't), matching the
# "no-blind-signing" requirement to show only fields that are actually meaningful for
# a given operation type, never a blank/misleading one.
_REVIEW_FIELDS = [
    ("Operation", "operation"),
    ("Network / Layer", "network_layer"),
    ("Amount / Counterparty", "amount_counterparty"),
]


def _mock_derivation_path(seed: Seed) -> str:
    """
        PLACEHOLDER derivation path for the Phase 1 UI demo only. Real path
        construction (m/7fchain/wallet/{account} -> falcon/v1/{index}) doesn't exist
        yet -- see docs/7f-integration/README.md's derivation-chain diagram.
    """
    return "m/7fchain/wallet/0'/falcon/v1/0'"


def _mock_sevenf_address(seed: Seed, derivation_path: str) -> str:
    """
        Deterministic PLACEHOLDER address for the Phase 1 UI demo only -- NOT a real
        7F address (real derivation is SHA-512(pubkey)[:25] + network/layer prefix,
        which doesn't exist in this codebase yet; see the "Phased rollout" Phase 4).
        Deterministic per (seed, path) purely so re-visiting the same screen shows a
        stable value, same as a real address would.
    """
    digest = hashlib.sha256(seed.seed_bytes + derivation_path.encode()).hexdigest()
    return f"7fdemo1{digest[:42]}"



"""****************************************************************************
    7F Address Display Views
****************************************************************************"""
class SevenFOptionsView(View):
    ADDRESS = ButtonOption("Receive address")
    SIGN = ButtonOption("Sign message (demo)")


    def __init__(self, seed: Seed):
        super().__init__()
        self.seed = seed

        if self.settings.get_value(SettingsConstants.SETTING__SEVENF_ENABLED) == SettingsConstants.OPTION__DISABLED:
            self.set_redirect(Destination(OptionDisabledView, view_args=dict(settings_attr=SettingsConstants.SETTING__SEVENF_ENABLED)))


    def run(self):
        from seedsigner.gui.screens.screen import ButtonListScreen
        button_data = [self.ADDRESS, self.SIGN]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("7F Chain (DEMO)"),
            is_button_text_centered=True,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == self.ADDRESS:
            return Destination(SevenFDerivationView, view_args=dict(seed=self.seed))

        elif button_data[selected_menu_num] == self.SIGN:
            from seedsigner.views.scan_views import ScanSevenFView
            self.controller.sevenf_data = dict(seed=self.seed)
            return Destination(ScanSevenFView)



class SevenFDerivationView(View):
    """
        Phase 1 stand-in for real layer/account/index selection: a short menu of
        canned demo paths covering the two L1/L2 shapes documented in the derivation
        diagram, rather than a full numeric picker widget (net-new UI work deferred
        past this walkthrough phase).
    """
    L1_WALLET = ButtonOption("L1 wallet, account 0")
    L2_MINTER = ButtonOption("L2 minter, account 0")


    def __init__(self, seed: Seed):
        super().__init__()
        self.seed = seed


    def run(self):
        from seedsigner.gui.screens.screen import ButtonListScreen
        button_data = [self.L1_WALLET, self.L2_MINTER]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("7F Derivation (DEMO)"),
            is_button_text_centered=True,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == self.L1_WALLET:
            derivation_path = "m/7fchain/wallet/0'/falcon/v1/0'"
        else:
            derivation_path = "m/7fchain/l2/0/value/0'/0'/falcon/v1/0'"

        return Destination(SevenFAddressView, view_args=dict(seed=self.seed, derivation_path=derivation_path))



class SevenFAddressView(View):
    def __init__(self, seed: Seed, derivation_path: str):
        super().__init__()
        self.seed = seed
        self.derivation_path = derivation_path
        self.address = _mock_sevenf_address(seed, derivation_path)


    def run(self):
        from seedsigner.gui.screens.seven_fortunas_screens import SevenFAddressScreen
        selected_menu_num = self.run_screen(
            SevenFAddressScreen,
            derivation_path=self.derivation_path,
            address=self.address,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # User clicked "Export QR"
        return Destination(SevenFAddressQRView, view_args=dict(address=self.address))



class SevenFAddressQRView(View):
    def __init__(self, address: str):
        super().__init__()
        self.address = address


    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
        qr_encoder = GenericStaticQrEncoder(data=self.address)

        self.run_screen(
            QRDisplayScreen,
            qr_encoder=qr_encoder,
        )

        # Exiting/Canceling the QR display screen always returns Home, same
        # convention as ToolsAddressExplorerAddressView / SeedSignMessageSignedMessageQRView.
        return Destination(MainMenuView, skip_current_view=True)



"""****************************************************************************
    7F Sign Views
****************************************************************************"""
class SevenFSignStartView(View):
    """
        Entry point after ScanSevenFView has scanned and stashed a (mocked) sign
        request into `controller.sevenf_data`. Normalizes the scanned payload into the
        ordered review fields and kicks off the paged review.
    """
    def __init__(self):
        super().__init__()

        # ScanView's generic dispatch routes here on any recognized 7F sign-request QR
        # regardless of Settings -- it doesn't know about SETTING__SEVENF_ENABLED, so
        # this entry point has to guard itself the same way SeedSignMessageStartView
        # guards SETTING__MESSAGE_SIGNING (SeedOptionsView hiding its own button isn't
        # sufficient on its own).
        if self.settings.get_value(SettingsConstants.SETTING__SEVENF_ENABLED) == SettingsConstants.OPTION__DISABLED:
            self.set_redirect(Destination(OptionDisabledView, view_args=dict(settings_attr=SettingsConstants.SETTING__SEVENF_ENABLED)))
            self.controller.sevenf_data = None
            return

        data = self.controller.sevenf_data

        if data is None or data.get("seed") is None:
            # Reached via the generic ScanView with no seed loaded/selected yet.
            # SeedSignMessageStartView's equivalent case redirects to
            # SeedSelectSeedView to pick or load one and resume the flow -- that's
            # deferred past this Phase 1 walkthrough (see seed_views.SeedOptionsView's
            # SEVENF button, which always already has a seed in hand), so for now this
            # just explains the limitation instead of crashing to UnhandledExceptionView.
            self.controller.sevenf_data = None
            self.set_redirect(Destination(NotYetImplementedView, view_args=dict(
                text=_("Load a seed first, then use \"7F signing (demo)\" from that seed's menu."),
            )))
            return

        self.seed = data["seed"]
        self.derivation_path = data.get("derivation_path") or _mock_derivation_path(self.seed)

        network_layer = " / ".join(filter(None, [data.get("network"), data.get("layer")])) or "testnet / L1"
        amount_counterparty = " to ".join(filter(None, [data.get("amount"), data.get("counterparty")])) or None

        data["network_layer"] = network_layer
        data["amount_counterparty"] = amount_counterparty
        data.setdefault("operation", "Transfer (demo)")
        data["derivation_path"] = self.derivation_path


    def run(self):
        return Destination(SevenFConfirmPayloadView, view_args=dict(page_num=0), skip_current_view=True)



class SevenFConfirmPayloadView(View):
    """
        Pages through the sign request's review fields one concern per screen -- the
        concrete mechanism for this project's no-blind-signing principle: operation
        type, network/layer, and amount/counterparty (when applicable) each get their
        own unhurried screen before the operator ever sees a "Sign" button.
    """
    def __init__(self, page_num: int = 0):
        super().__init__()
        self.page_num = page_num
        data = self.controller.sevenf_data
        self.fields = [(label, data.get(key)) for label, key in _REVIEW_FIELDS if data.get(key)]

        if self.page_num >= len(self.fields):
            raise Exception("Bug in 7F review field paging")


    def run(self):
        from seedsigner.gui.screens.seven_fortunas_screens import SevenFReviewFieldScreen
        label, value = self.fields[self.page_num]
        is_final_page = self.page_num == len(self.fields) - 1

        selected_menu_num = self.run_screen(
            SevenFReviewFieldScreen,
            page_title=_("Review Sign Request"),
            label_text=label,
            value_text=value,
            page_num=self.page_num,
            num_pages=len(self.fields),
            is_final_page=is_final_page,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            if self.page_num == 0:
                self.controller.sevenf_data = None
            return Destination(BackStackView)

        if is_final_page:
            return Destination(SevenFConfirmAddressView)
        else:
            return Destination(SevenFConfirmPayloadView, view_args=dict(page_num=self.page_num + 1))



class SevenFConfirmAddressView(View):
    def __init__(self):
        super().__init__()
        data = self.controller.sevenf_data
        self.seed = data["seed"]
        self.derivation_path = data["derivation_path"]
        self.address = _mock_sevenf_address(self.seed, self.derivation_path)


    def run(self):
        from seedsigner.gui.screens.seven_fortunas_screens import SevenFConfirmSignScreen
        selected_menu_num = self.run_screen(
            SevenFConfirmSignScreen,
            derivation_path=self.derivation_path,
            address=self.address,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # User clicked "Sign (DEMO -- not real)"
        return Destination(SevenFSignedQRView)



class SevenFSignedQRView(View):
    """
        Displays a FAKE signature as a QR code. `os.urandom` output, not a Falcon-512
        signature -- there is no crypto core wired up yet (Phase 3 of the rollout).
        Kept short (32 bytes) rather than Falcon-512's real ~666-byte signature size,
        since a full-size static QR isn't legible at this display's density; real
        signature export needs the fountain/UR encoder proposed in
        docs/7f-integration/qr-envelope-ur-types.md, not built here.
    """
    def __init__(self):
        super().__init__()
        self.fake_signature_hex = os.urandom(32).hex()


    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
        qr_encoder = GenericStaticQrEncoder(data=f"7F-DEMO-SIG:{self.fake_signature_hex}")

        self.run_screen(
            QRDisplayScreen,
            qr_encoder=qr_encoder,
        )

        # cleanup
        self.controller.sevenf_data = None

        # Exiting/Canceling the QR display screen always returns Home
        return Destination(MainMenuView, skip_current_view=True)
