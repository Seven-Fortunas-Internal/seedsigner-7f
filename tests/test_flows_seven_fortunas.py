import json
from unittest.mock import patch

# Must import test base before the Controller
from base import BaseTest, FlowTest, FlowStep

from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON
from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants
from seedsigner.views.view import MainMenuView, NotYetImplementedView, OptionDisabledView
from seedsigner.views import seed_views, scan_views, settings_views, seven_fortunas_views as sevenf_views


def load_seed_into_decoder(view: scan_views.ScanView):
    view.decoder.add_data("0000" * 11 + "0003")


# Common prefix for every flow test below: scan a SeedQR, finalize it, land on
# SeedOptionsView. `run_sequence` always starts a fresh Controller.start() from its
# first FlowStep, so this has to be prepended to one continuous sequence per test
# rather than run as its own separate call.
ENTER_SEED_OPTIONS_STEPS = [
    FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
    FlowStep(scan_views.ScanView, before_run=load_seed_into_decoder),
    FlowStep(seed_views.SeedFinalizeView, button_data_selection=seed_views.SeedFinalizeView.FINALIZE),
]

DEFAULT_SIGN_REQUEST = dict(
    operation="Transfer",
    network="testnet",
    layer="L1",
    amount="12.5 7F",
    counterparty="7fdemo1counterpartyplaceholderxxxxxxxxxxxx",
    derivation_path="m/7fchain/wallet/0'/falcon/v1/0'",
)

# No amount/counterparty -- exercises the "skip fields the payload doesn't carry" path.
NO_AMOUNT_SIGN_REQUEST = dict(
    operation="Mint",
    network="mainnet",
    layer="L2",
    derivation_path="m/7fchain/l2/0/value/0'/0'/falcon/v1/0'",
)


def load_sign_request_into_decoder(view: scan_views.ScanView, payload: dict = None):
    view.decoder.add_data(f"sevenf-sign-request:{json.dumps(payload or DEFAULT_SIGN_REQUEST)}")



class TestSevenFFlows(FlowTest):
    """
        Phase 1 UI-walkthrough demo flows: address display and sign-request
        review/sign, both against mocked data. See
        docs/7f-integration/README.md in the diy-seedsigner repo.
    """

    def seed_fixture(self) -> Seed:
        """
            A finalized Seed without driving the full scan/finalize UI flow -- for
            tests that only need a seed object to exist, not a rendered flow.
        """
        seed = Seed(mnemonic=["abandon"] * 11 + ["about"], wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)
        self.controller.storage.seeds.append(seed)
        return seed


    def test_sevenf_address_flow(self):
        """
            SeedOptionsView -> SevenFOptionsView -> SevenFDerivationView ->
            SevenFAddressView -> SevenFAddressQRView -> MainMenuView.
        """
        self.settings.set_value(SettingsConstants.SETTING__SEVENF_ENABLED, SettingsConstants.OPTION__ENABLED)

        self.run_sequence(ENTER_SEED_OPTIONS_STEPS + [
            FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF),
            FlowStep(sevenf_views.SevenFOptionsView, button_data_selection=sevenf_views.SevenFOptionsView.ADDRESS),
            FlowStep(sevenf_views.SevenFDerivationView, button_data_selection=sevenf_views.SevenFDerivationView.L1_WALLET),
            FlowStep(sevenf_views.SevenFAddressView, screen_return_value=0),  # "Export QR"
            FlowStep(sevenf_views.SevenFAddressQRView, screen_return_value=0),
            FlowStep(MainMenuView),
        ])


    def test_sevenf_address_is_deterministic_per_derivation_path(self):
        """
            The Phase 1 mocked address is a placeholder, but it should still be
            deterministic per (seed, path) -- a real address would be too, and a
            walkthrough reviewer re-visiting the screen shouldn't see it change.
        """
        seed = self.seed_fixture()

        view1 = sevenf_views.SevenFAddressView(seed=seed, derivation_path="m/7fchain/wallet/0'/falcon/v1/0'")
        view2 = sevenf_views.SevenFAddressView(seed=seed, derivation_path="m/7fchain/wallet/0'/falcon/v1/0'")
        view3 = sevenf_views.SevenFAddressView(seed=seed, derivation_path="m/7fchain/l2/0/value/0'/0'/falcon/v1/0'")

        assert view1.address == view2.address
        assert view1.address != view3.address
        assert view1.address.startswith("7fdemo1")


    def test_sevenf_sign_flow(self):
        """
            SeedOptionsView -> SevenFOptionsView -> SevenFSignStartView (redirect,
            synthetic demo payload -- no camera/scan needed, see _DEMO_SIGN_REQUEST) ->
            SevenFConfirmPayloadView (paged) -> SevenFConfirmAddressView ->
            SevenFSignedQRView -> MainMenuView.
        """
        self.settings.set_value(SettingsConstants.SETTING__SEVENF_ENABLED, SettingsConstants.OPTION__ENABLED)

        self.run_sequence(ENTER_SEED_OPTIONS_STEPS + [
            FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF),
            FlowStep(sevenf_views.SevenFOptionsView, button_data_selection=sevenf_views.SevenFOptionsView.SIGN),
            FlowStep(sevenf_views.SevenFSignStartView, is_redirect=True),
            FlowStep(sevenf_views.SevenFConfirmPayloadView, screen_return_value=0),  # Operation (1/3)
            FlowStep(sevenf_views.SevenFConfirmPayloadView, screen_return_value=0),  # Network / Layer (2/3)
            FlowStep(sevenf_views.SevenFConfirmPayloadView, screen_return_value=0),  # Amount / Counterparty (3/3)
            FlowStep(sevenf_views.SevenFConfirmAddressView, screen_return_value=0),  # Sign (DEMO)
            FlowStep(sevenf_views.SevenFSignedQRView, screen_return_value=0),
            FlowStep(MainMenuView),
        ])

        # cleanup is expected once the flow completes
        assert self.controller.sevenf_data is None


    def test_sevenf_sign_flow_skips_absent_fields(self):
        """
            A sign request with no amount/counterparty should page through only the
            fields it actually carries (Operation, Network / Layer) -- never a blank
            or misleading "Amount / Counterparty" page.

            The demo SIGN button always uses the fixed _DEMO_SIGN_REQUEST (which does
            carry amount/counterparty), so this exercises the field-skipping logic
            directly against SevenFConfirmPayloadView/SevenFSignStartView rather than
            through a button-driven flow.
        """
        self.settings.set_value(SettingsConstants.SETTING__SEVENF_ENABLED, SettingsConstants.OPTION__ENABLED)
        seed = self.seed_fixture()
        self.controller.sevenf_data = dict(seed=seed, **NO_AMOUNT_SIGN_REQUEST)

        sevenf_views.SevenFSignStartView()  # normalizes controller.sevenf_data in place
        payload_view = sevenf_views.SevenFConfirmPayloadView(page_num=0)

        assert [label for label, _value in payload_view.fields] == ["Operation", "Network / Layer"]


    def test_sevenf_confirm_payload_back_button_navigation(self):
        """
            Backing out of a later page should return to the previous review page;
            backing out of the first page should abandon the flow (clearing the
            stashed sign-request data) and, per BackStackView's normal "pop current +
            previous" semantics, land back on SevenFOptionsView -- mirroring
            SeedSignMessageConfirmMessageView's page-0 back-button behavior.
        """
        self.settings.set_value(SettingsConstants.SETTING__SEVENF_ENABLED, SettingsConstants.OPTION__ENABLED)

        self.run_sequence(ENTER_SEED_OPTIONS_STEPS + [
            FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF),
            FlowStep(sevenf_views.SevenFOptionsView, button_data_selection=sevenf_views.SevenFOptionsView.SIGN),
            FlowStep(sevenf_views.SevenFSignStartView, is_redirect=True),
            FlowStep(sevenf_views.SevenFConfirmPayloadView, screen_return_value=0),  # page 1/3 -> Next
            FlowStep(sevenf_views.SevenFConfirmPayloadView, screen_return_value=RET_CODE__BACK_BUTTON),  # page 2/3 -> Back
            FlowStep(sevenf_views.SevenFConfirmPayloadView, screen_return_value=RET_CODE__BACK_BUTTON),  # page 1/3 -> Back, abandons flow
            FlowStep(sevenf_views.SevenFOptionsView),
        ])

        assert self.controller.sevenf_data is None


    def test_scan_sevenf_view_is_valid_qr_type(self):
        """
            ScanSevenFView isn't reachable from the demo SIGN button anymore (see
            _DEMO_SIGN_REQUEST), but it's still real, working code for whenever a real
            camera or the real CBOR/UR envelope is wired up -- keep it covered
            directly.
        """
        seed = self.seed_fixture()
        self.controller.sevenf_data = dict(seed=seed)

        view = scan_views.ScanSevenFView()
        assert view.is_valid_qr_type is False  # nothing decoded yet

        load_sign_request_into_decoder(view)
        assert view.is_valid_qr_type is True
        assert view.decoder.get_qr_data()["operation"] == DEFAULT_SIGN_REQUEST["operation"]


    def test_sevenf_sign_request_scanned_with_no_seed_loaded(self):
        """
            Scanning a `sevenf-sign-request:` QR from the generic Scan menu with no
            seed loaded/selected yet shouldn't crash to UnhandledExceptionView --
            SevenFSignStartView should fail gracefully (full SeedSelectSeedView-style
            resume is deferred past this Phase 1 walkthrough).
        """
        self.settings.set_value(SettingsConstants.SETTING__SEVENF_ENABLED, SettingsConstants.OPTION__ENABLED)

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load_sign_request_into_decoder),
            FlowStep(sevenf_views.SevenFSignStartView, is_redirect=True),
            FlowStep(NotYetImplementedView),
            FlowStep(MainMenuView),
        ])

        assert self.controller.sevenf_data is None


    def test_sevenf_option_disabled_hides_seed_options_button(self):
        """
            With the demo feature off (the default), SeedOptionsView shouldn't offer
            the "7F signing (demo)" button at all.
        """
        self.settings.set_value(SettingsConstants.SETTING__SEVENF_ENABLED, SettingsConstants.OPTION__DISABLED)
        seed = self.seed_fixture()

        view = seed_views.SeedOptionsView(seed=seed)
        with patch.object(view, "run_screen", return_value=RET_CODE__BACK_BUTTON) as mock_run_screen:
            view.run()

        button_data = mock_run_screen.call_args.kwargs["button_data"]
        assert seed_views.SeedOptionsView.SEVENF not in button_data


    def test_sevenf_option_disabled_guards_scan_entry_point(self):
        """
            Even if a `sevenf-sign-request:` QR is scanned directly from the generic
            Scan menu (bypassing SeedOptionsView's hidden button and SevenFOptionsView
            entirely -- exactly how SeedSignMessageStartView's equivalent bypass
            works), the disabled setting should still route to OptionDisabledView.
            The generic ScanView's dispatch doesn't know about
            SETTING__SEVENF_ENABLED, so SevenFSignStartView has to guard itself.
        """
        self.settings.set_value(SettingsConstants.SETTING__SEVENF_ENABLED, SettingsConstants.OPTION__DISABLED)
        seed = self.seed_fixture()

        def scan_with_seed_already_stashed(view):
            # MainMenuView wipes `sevenf_data` on the way through, same as every other
            # flow-scoped controller attr, so stash it here -- right where
            # SevenFOptionsView.SIGN would have, immediately before the scan -- rather
            # than before run_sequence() starts.
            self.controller.sevenf_data = dict(seed=seed)
            load_sign_request_into_decoder(view)

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=scan_with_seed_already_stashed),
            FlowStep(sevenf_views.SevenFSignStartView, is_redirect=True),
            FlowStep(OptionDisabledView, button_data_selection=OptionDisabledView.UPDATE_SETTING),
            FlowStep(settings_views.SettingsEntryUpdateSelectionView),
        ])

        assert self.controller.sevenf_data is None
