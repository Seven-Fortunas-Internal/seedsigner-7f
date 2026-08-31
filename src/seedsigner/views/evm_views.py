"""
    Multi-chain (Phase 1 UI-walkthrough demo). Full View/Screen navigation flow for
    EVM address display and sign-request review/sign, using placeholder addresses and
    a fake signature -- NO real derivation, NO real ECDSA signing. Goal of this phase
    is purely to put the actual review screens (including the anti-scam warnings) in
    front of a reviewer before any backend work is invested. See
    docs/multi-chain/README.md's "Architecture: chain-plugin model" and
    docs/multi-chain/research/anti-scam-ux.md for why these specific fields/warnings
    exist.

    Follows the same file-pairing convention as the rest of this codebase
    (seed_views.py <-> seed_screens.py); see gui/screens/evm_screens.py for the paired
    Screen classes. Reached via multichain_views.MultiChainOptionsView, which is
    itself reached from SeedOptionsView behind Settings > Advanced >
    "Multi-chain (demo)".

    No real camera scan step in Phase 1 (matching the 7F work's own Phase 1 decision,
    made after finding this dev hardware's camera stack doesn't work at all against a
    libcamera-only kernel) -- sign requests are one of three synthetic demo scenarios
    picked from a menu, not scanned.
"""
from gettext import gettext as _

from seedsigner.chains.base import ReviewField
from seedsigner.chains.evm.constants import NETWORKS
from seedsigner.chains.evm.plugin import DEMO_SCENARIOS, DERIVATION_PATH_TEMPLATE
from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
from seedsigner.gui.screens.screen import ButtonOption
from seedsigner.models.seed import Seed
from seedsigner.views.view import BackStackView, Destination, MainMenuView, OptionDisabledView, View


_SCENARIO_MENU = [
    ("transfer", "Ordinary transfer"),
    ("approve_unlimited", "Token approval (unlimited)"),
    ("permit", "Permit (off-chain signature)"),
]



def _guard_multichain_enabled(view: View):
    """
        Shared settings-gate check. Reached from two places (SeedOptionsView's button,
        which hides itself when disabled, and here, called at every EVM view's own
        __init__) because a future real scan entry point -- like the 7F work's
        generic ScanView dispatch -- would bypass SeedOptionsView's hidden button
        entirely; guarding each entry point directly is the same defense-in-depth
        the 7F work already established for SETTING__SEVENF_ENABLED.
    """
    from seedsigner.models.settings import SettingsConstants
    if view.settings.get_value(SettingsConstants.SETTING__MULTICHAIN_ENABLED) == SettingsConstants.OPTION__DISABLED:
        view.set_redirect(Destination(OptionDisabledView, view_args=dict(settings_attr=SettingsConstants.SETTING__MULTICHAIN_ENABLED)))
        return True
    return False



"""****************************************************************************
    EVM Address Display Views
****************************************************************************"""
class EvmOptionsView(View):
    ADDRESS = ButtonOption("Receive address")
    SIGN = ButtonOption("Sign message (demo)")


    def __init__(self, seed: Seed):
        super().__init__()
        self.seed = seed
        _guard_multichain_enabled(self)


    def run(self):
        from seedsigner.gui.screens.screen import ButtonListScreen
        button_data = [self.ADDRESS, self.SIGN]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("EVM Chain (DEMO)"),
            is_button_text_centered=True,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == self.ADDRESS:
            return Destination(EvmNetworkView, view_args=dict(seed=self.seed))

        elif button_data[selected_menu_num] == self.SIGN:
            return Destination(EvmSignSelectView, view_args=dict(seed=self.seed))



class EvmNetworkView(View):
    def __init__(self, seed: Seed):
        super().__init__()
        self.seed = seed


    def run(self):
        from seedsigner.gui.screens.screen import ButtonListScreen
        button_data = [ButtonOption(n.display_name) for n in NETWORKS]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("EVM Network (DEMO)"),
            is_button_text_centered=True,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        network = NETWORKS[selected_menu_num]
        return Destination(EvmAddressView, view_args=dict(seed=self.seed, network_id=network.network_id))



class EvmAddressView(View):
    def __init__(self, seed: Seed, network_id: str):
        super().__init__()
        from seedsigner.chains import ChainRegistry
        from seedsigner.chains.evm.constants import NETWORKS_BY_ID

        self.seed = seed
        self.network = NETWORKS_BY_ID[network_id]
        self.derivation_path = DERIVATION_PATH_TEMPLATE.format(account=0, index=0)
        address = ChainRegistry.get("evm").derive_address(seed.seed_bytes, self.derivation_path)
        self.address = address.address


    def run(self):
        from seedsigner.gui.screens.evm_screens import EvmAddressScreen
        selected_menu_num = self.run_screen(
            EvmAddressScreen,
            derivation_path=self.derivation_path,
            address=self.address,
            network_name=self.network.display_name,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # User clicked "Export QR"
        return Destination(EvmAddressQRView, view_args=dict(address=self.address))



class EvmAddressQRView(View):
    def __init__(self, address: str):
        super().__init__()
        self.address = address


    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
        from seedsigner.models.encode_qr import GenericStaticQrEncoder
        qr_encoder = GenericStaticQrEncoder(data=self.address)

        self.run_screen(
            QRDisplayScreen,
            qr_encoder=qr_encoder,
        )

        # Exiting/Canceling the QR display screen always returns Home, same
        # convention used throughout the codebase (ToolsAddressExplorerAddressView,
        # SeedSignMessageSignedMessageQRView, the 7F work's SevenFAddressQRView).
        return Destination(MainMenuView, skip_current_view=True)



"""****************************************************************************
    EVM Sign Views
****************************************************************************"""
class EvmSignSelectView(View):
    """ Phase 1 stand-in for a real scan step: pick one of three demo sign-request
        scenarios, chosen directly from the anti-scam research (see module
        docstring) rather than one arbitrary example. """
    def __init__(self, seed: Seed):
        super().__init__()
        self.seed = seed


    def run(self):
        from seedsigner.gui.screens.screen import ButtonListScreen
        button_data = [ButtonOption(label) for _key, label in _SCENARIO_MENU]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Sign Request (DEMO)"),
            is_button_text_centered=True,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        scenario_key, _label = _SCENARIO_MENU[selected_menu_num]
        return Destination(EvmSignStartView, view_args=dict(seed=self.seed, scenario_key=scenario_key))



class EvmSignStartView(View):
    """ Entry point for a (demo) sign request: parses the chosen scenario via the
        EvmPlugin -- the same call path a real scanned request would go through --
        and stashes the result for the paged review. """
    def __init__(self, seed: Seed, scenario_key: str):
        super().__init__()
        self.seed = seed

        if _guard_multichain_enabled(self):
            return

        from seedsigner.chains import ChainRegistry
        plugin = ChainRegistry.get("evm")
        payload = DEMO_SCENARIOS[scenario_key]
        parsed = plugin.parse_sign_request(payload)

        # Derivation path is a wallet-side choice, not part of the signed payload
        # itself (a real transaction/permit carries no such field) -- the view layer
        # owns it, same as EvmAddressView already does. Account 0 / index 0 for this
        # demo menu; a real scanned request would let the operator pick an account.
        derivation_path = DERIVATION_PATH_TEMPLATE.format(account=0, index=0)

        self.controller.multichain_data = dict(
            seed=seed,
            chain_id="evm",
            derivation_path=derivation_path,
            payload=payload,
            fields=parsed.review_fields,
        )


    def run(self):
        return Destination(EvmConfirmPayloadView, view_args=dict(page_num=0), skip_current_view=True)



class EvmConfirmPayloadView(View):
    """ Pages through the sign request's review fields one concern per screen -- the
        concrete mechanism for no-blind-signing. Warning-flagged fields (unlimited
        approval, off-chain permit signature, first-time address) render distinctly --
        see gui/screens/evm_screens.py's EvmReviewFieldScreen. """
    def __init__(self, page_num: int = 0):
        super().__init__()
        self.page_num = page_num
        data = self.controller.multichain_data
        self.fields: list[ReviewField] = data["fields"]

        if self.page_num >= len(self.fields):
            raise Exception("Bug in EVM review field paging")


    def run(self):
        from seedsigner.gui.screens.evm_screens import EvmReviewFieldScreen
        field = self.fields[self.page_num]
        is_final_page = self.page_num == len(self.fields) - 1

        selected_menu_num = self.run_screen(
            EvmReviewFieldScreen,
            page_title=_("Review Sign Request"),
            label_text=field.label,
            value_text=field.value,
            warning_detail=field.warning_detail,
            is_warning=field.is_warning,
            page_num=self.page_num,
            num_pages=len(self.fields),
            is_final_page=is_final_page,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            if self.page_num == 0:
                self.controller.multichain_data = None
            return Destination(BackStackView)

        if is_final_page:
            return Destination(EvmConfirmAddressView)
        else:
            return Destination(EvmConfirmPayloadView, view_args=dict(page_num=self.page_num + 1))



class EvmConfirmAddressView(View):
    def __init__(self):
        super().__init__()
        from seedsigner.chains import ChainRegistry

        data = self.controller.multichain_data
        self.seed = data["seed"]
        self.derivation_path = data["derivation_path"]
        address = ChainRegistry.get("evm").derive_address(self.seed.seed_bytes, self.derivation_path)
        self.address = address.address


    def run(self):
        from seedsigner.gui.screens.evm_screens import EvmConfirmSignScreen
        selected_menu_num = self.run_screen(
            EvmConfirmSignScreen,
            derivation_path=self.derivation_path,
            address=self.address,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # User clicked "Sign (DEMO -- not real)"
        return Destination(EvmSignedQRView)



class EvmSignedQRView(View):
    """ Real signature for the transfer/approve_unlimited demo scenarios (real
        RLP-encoded transactions, signed for real -- see chains/evm/plugin.py); the
        permit scenario still gets a FAKE os.urandom signature, since permit signing
        itself is still Phase 1 (see plugin.py's module docstring). """
    def __init__(self):
        super().__init__()
        from seedsigner.chains import ChainRegistry

        data = self.controller.multichain_data
        plugin = ChainRegistry.get("evm")
        signature = plugin.sign(data["seed"].seed_bytes, data["derivation_path"], payload=data["payload"])
        self.encoded_signature = plugin.encode_response(signature).decode()


    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
        from seedsigner.models.encode_qr import GenericStaticQrEncoder
        qr_encoder = GenericStaticQrEncoder(data=f"EVM-DEMO-SIG:{self.encoded_signature}")

        self.run_screen(
            QRDisplayScreen,
            qr_encoder=qr_encoder,
        )

        # cleanup
        self.controller.multichain_data = None

        # Exiting/Canceling the QR display screen always returns Home
        return Destination(MainMenuView, skip_current_view=True)
