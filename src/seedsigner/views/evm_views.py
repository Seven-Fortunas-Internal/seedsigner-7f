"""
    EVM chain UI: address display and sign-request review/sign. Real BIP-32/secp256k1
    derivation, real EIP-1559 RLP decode, real ECDSA signing (see chains/evm/) -- the
    review screens (including the anti-scam warnings) are the concrete no-blind-signing
    mechanism, not a placeholder. See docs/multi-chain/README.md's "Architecture:
    chain-plugin model", docs/multi-chain/research/anti-scam-ux.md for why these
    specific fields/warnings exist, and docs/multi-chain/evm-first-class-plan.md for
    what's still ahead (real ERC-4527 scan-and-sign, replacing the fixed
    demo-scenario menu below).

    Follows the same file-pairing convention as the rest of this codebase
    (seed_views.py <-> seed_screens.py); see gui/screens/evm_screens.py for the paired
    Screen classes. Reached via multichain_views.MultiChainOptionsView, which is
    itself reached from SeedOptionsView behind Settings > Advanced >
    "Other Blockchains".

    Sign requests are still picked from a fixed demo-scenario menu, not scanned --
    real camera-based scan-and-sign (ERC-4527) is planned (see the doc above) but not
    yet built. The scenarios themselves are real, signable transactions (RLP-encoded,
    really ECDSA-signed) even though the *source* of the request is a menu, not a scan.
"""
from gettext import gettext as _

from seedsigner.helpers.l10n import mark_for_translation as _mft
from seedsigner.chains.base import ReviewField
from seedsigner.chains.evm.constants import NETWORKS
from seedsigner.chains.evm.plugin import DEMO_SCENARIOS, DERIVATION_PATH_TEMPLATE
from seedsigner.chains.evm.ur_types import DATA_TYPE_TYPED_TRANSACTION, EthSignature
from seedsigner.gui.components import SeedSignerIconConstants
from seedsigner.gui.screens import DireWarningScreen, RET_CODE__BACK_BUTTON
from seedsigner.gui.screens.screen import ButtonOption
from seedsigner.models.seed import Seed
from seedsigner.views.scan_views import ScanView
from seedsigner.views.view import BackStackView, Destination, MainMenuView, OptionDisabledView, View

# BIP-32 non-hardened child index range -- same constraint SeedBIP85SelectChildIndexView
# already enforces for the same underlying reason (see gui/screens/evm_screens.py's
# EvmSelectAddressIndexScreen docstring).
_MAX_ADDRESS_INDEX = 2**31


_SCENARIO_MENU = [
    ("transfer", "Ordinary transfer"),
    ("approve_unlimited", "Token approval (unlimited)"),
    ("usdc_transfer", "USDC transfer"),
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
    SCAN = ButtonOption("Scan sign request")
    SIGN = ButtonOption("Sign message")


    def __init__(self, seed: Seed):
        super().__init__()
        self.seed = seed
        _guard_multichain_enabled(self)


    def run(self):
        from seedsigner.gui.screens.screen import ButtonListScreen
        button_data = [self.ADDRESS, self.SCAN, self.SIGN]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Ethereum / EVM"),
            is_button_text_centered=True,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == self.ADDRESS:
            return Destination(EvmNetworkView, view_args=dict(seed=self.seed))

        elif button_data[selected_menu_num] == self.SCAN:
            return Destination(EvmScanSignRequestView, view_args=dict(seed=self.seed))

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
            title=_("EVM Network"),
            is_button_text_centered=True,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        network = NETWORKS[selected_menu_num]
        return Destination(EvmSelectAddressIndexView, view_args=dict(seed=self.seed, network_id=network.network_id))



class EvmSelectAddressIndexView(View):
    """ Shared index picker for both places that need one: deriving a receive
        address (network_id set) and signing a menu-picked demo scenario
        (scenario_key set) -- exactly one of the two is set, matching the
        one-destination-in/one-destination-out shape every other forked step in
        this codebase already uses (e.g. SeedBIP85SelectChildIndexView). """
    def __init__(self, seed: Seed, network_id: str = None, scenario_key: str = None):
        super().__init__()
        self.seed = seed
        self.network_id = network_id
        self.scenario_key = scenario_key


    def run(self):
        from seedsigner.gui.screens.evm_screens import EvmSelectAddressIndexScreen
        ret = self.run_screen(EvmSelectAddressIndexScreen)

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if not ret or not 0 <= int(ret) < _MAX_ADDRESS_INDEX:
            return Destination(
                EvmInvalidAddressIndexView,
                view_args=dict(seed=self.seed, network_id=self.network_id, scenario_key=self.scenario_key),
                skip_current_view=True,
            )

        address_index = int(ret)
        if self.network_id is not None:
            return Destination(EvmAddressView, view_args=dict(
                seed=self.seed, network_id=self.network_id, address_index=address_index))
        else:
            return Destination(EvmSignStartView, view_args=dict(
                seed=self.seed, scenario_key=self.scenario_key, address_index=address_index))



class EvmInvalidAddressIndexView(View):
    def __init__(self, seed: Seed, network_id: str = None, scenario_key: str = None):
        super().__init__()
        self.seed = seed
        self.network_id = network_id
        self.scenario_key = scenario_key


    def run(self):
        self.run_screen(
            DireWarningScreen,
            title=_("Index Error"),
            show_back_button=False,
            status_icon_name=SeedSignerIconConstants.ERROR,
            status_headline=_("Invalid Address Index"),
            text=_("Address index must be between 0 and 2^31-1."),
            button_data=[ButtonOption("Try again")],
        )

        return Destination(
            EvmSelectAddressIndexView,
            view_args=dict(seed=self.seed, network_id=self.network_id, scenario_key=self.scenario_key),
            skip_current_view=True,
        )



class EvmAddressView(View):
    def __init__(self, seed: Seed, network_id: str, address_index: int):
        super().__init__()
        from seedsigner.chains import ChainRegistry
        from seedsigner.chains.evm.constants import NETWORKS_BY_ID

        self.seed = seed
        self.network = NETWORKS_BY_ID[network_id]
        self.derivation_path = DERIVATION_PATH_TEMPLATE.format(account=0, index=address_index)
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
class EvmScanSignRequestView(ScanView):
    """ Real free-form send: scans an ERC-4527 eth-sign-request QR -- what
        MetaMask/Rabby/etc. actually produce -- instead of picking from the fixed
        demo-scenario menu below. Reached with the seed already known (this is a
        per-seed submenu item, unlike the top-level catch-all Scan button PSBT
        uses, which has to ask which seed applies after scanning) -- overrides
        _handle_complete_scan() rather than duplicating ScanView's shared
        scan-screen scaffolding (see scan_views.py). """
    instructions_text = _mft("Scan sign request")
    invalid_qr_type_message = _mft("Expected an eth-sign-request QR (from MetaMask, Rabby, etc.)")


    def __init__(self, seed: Seed):
        super().__init__()
        self.seed = seed
        _guard_multichain_enabled(self)


    @property
    def is_valid_qr_type(self):
        return self.decoder.is_eth_sign_request


    def _handle_complete_scan(self):
        eth_sign_request = self.decoder.get_eth_sign_request()
        if eth_sign_request is None:
            return Destination(EvmUnsupportedSignRequestView, view_args=dict(
                reason=_("Couldn't decode the scanned request.")))

        if eth_sign_request.data_type != DATA_TYPE_TYPED_TRANSACTION:
            return Destination(EvmUnsupportedSignRequestView, view_args=dict(
                reason=_("Only real EIP-1559 transactions are supported today "
                         "(request type {} isn't).").format(eth_sign_request.data_type)))

        from seedsigner.chains import ChainRegistry
        plugin = ChainRegistry.get("evm")
        try:
            parsed = plugin.parse_sign_request(eth_sign_request.sign_data)
        except Exception as e:
            return Destination(EvmUnsupportedSignRequestView, view_args=dict(
                reason=_("Couldn't parse the transaction: {}").format(e)))

        # Self-validation: this request itself names which derivation path/address
        # it wants signed with (crypto-keypath) -- surface it as its own review
        # field, not just inside EvmConfirmAddressView's final screen. Unlike the
        # demo menu below (where the operator always picks the index), this path
        # comes from untrusted external input.
        fields = [ReviewField(label="Derivation Path", value=eth_sign_request.derivation_path)] + list(parsed.review_fields)

        self.controller.multichain_data = dict(
            seed=self.seed,
            chain_id="evm",
            derivation_path=eth_sign_request.derivation_path,
            payload=eth_sign_request.sign_data,
            fields=fields,
            eth_sign_request=eth_sign_request,
        )
        return Destination(EvmConfirmPayloadView, view_args=dict(page_num=0), skip_current_view=True)



class EvmUnsupportedSignRequestView(View):
    def __init__(self, reason: str):
        super().__init__()
        self.reason = reason


    def run(self):
        self.run_screen(
            DireWarningScreen,
            title=_("Unsupported Request"),
            show_back_button=False,
            status_icon_name=SeedSignerIconConstants.ERROR,
            status_headline=_("Can't Sign This Request"),
            text=self.reason,
            button_data=[ButtonOption("OK")],
        )
        return Destination(MainMenuView, skip_current_view=True)



class EvmSignSelectView(View):
    """ Fixed demo-scenario menu, kept as a testing convenience now that
        EvmScanSignRequestView above is the real, primary way to sign -- pick one
        of three demo sign-request scenarios, chosen directly from the anti-scam
        research (see module docstring) rather than one arbitrary example. """
    def __init__(self, seed: Seed):
        super().__init__()
        self.seed = seed


    def run(self):
        from seedsigner.gui.screens.screen import ButtonListScreen
        button_data = [ButtonOption(label) for _key, label in _SCENARIO_MENU]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Sign Request"),
            is_button_text_centered=True,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        scenario_key, _label = _SCENARIO_MENU[selected_menu_num]
        return Destination(EvmSelectAddressIndexView, view_args=dict(seed=self.seed, scenario_key=scenario_key))



class EvmSignStartView(View):
    """ Entry point for a menu-picked sign request: parses the chosen scenario via the
        EvmPlugin -- the same call path a real scanned request would go through --
        and stashes the result for the paged review. """
    def __init__(self, seed: Seed, scenario_key: str, address_index: int):
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
        # owns it, same as EvmAddressView already does. Account 0, operator-picked
        # index (see EvmSelectAddressIndexView) -- a real scanned ERC-4527 request
        # would eventually let the incoming crypto-keypath name this instead.
        derivation_path = DERIVATION_PATH_TEMPLATE.format(account=0, index=address_index)

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

        # User clicked "Sign". A real scanned request needs an eth-signature UR
        # response (what MetaMask/etc. actually expect back); the demo-menu path
        # keeps the existing plain-text EVM-DEMO-SIG: QR.
        if self.controller.multichain_data.get("eth_sign_request") is not None:
            return Destination(EvmSignedUrQRView)
        return Destination(EvmSignedQRView)



class EvmSignedUrQRView(View):
    """ Real ERC-4527 response: encodes the device's signature as an eth-signature
        UR, matched back to the incoming request via its request_id (see
        chains/evm/ur_types.py) -- what a real requester actually needs back, unlike
        EvmSignedQRView's EVM-DEMO-SIG: plain text, which nothing outside
        tools/broadcast_evm_demo.py understands. """
    def __init__(self):
        super().__init__()
        from seedsigner.chains import ChainRegistry

        data = self.controller.multichain_data
        eth_sign_request = data["eth_sign_request"]
        plugin = ChainRegistry.get("evm")
        signature = plugin.sign(data["seed"].seed_bytes, data["derivation_path"], payload=data["payload"])

        # request-id is optional on the request but required on the response --
        # generate one in the rare case a requester omitted it, so correlation is
        # still possible even though this specific requester didn't ask for it.
        import os
        request_id = eth_sign_request.request_id or os.urandom(16)

        self.eth_signature = EthSignature(request_id=request_id, signature=signature.signature_bytes, origin="seedsigner")


    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
        from seedsigner.models.encode_qr import UrEthSignatureQrEncoder
        from seedsigner.models.settings import SettingsConstants

        qr_encoder = UrEthSignatureQrEncoder(
            eth_signature=self.eth_signature,
            qr_density=self.settings.get_value(SettingsConstants.SETTING__QR_DENSITY),
        )
        self.run_screen(
            QRDisplayScreen,
            qr_encoder=qr_encoder,
        )

        # cleanup
        self.controller.multichain_data = None

        # Exiting/Canceling the QR display screen always returns Home
        return Destination(MainMenuView, skip_current_view=True)



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
