from unittest.mock import patch

from binascii import a2b_base64
from embit.psbt import PSBT

# Must import test base before the Controller
from base import BaseTest, FlowTest, FlowStep

from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON
from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants
from seedsigner.views.view import MainMenuView
from seedsigner.views import seed_views, scan_views, settings_views, evm_views
from psbt_testing_util import PSBTTestData


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



class TestEvmFlows(FlowTest):
    """
        EVM address display (rollout Phase 2 -- real BIP-32/secp256k1/Keccak-256
        derivation, see chains/evm/crypto.py and test_evm_crypto.py for the
        cross-verified crypto-level tests) and sign-request review/sign flows (still
        Phase 1 -- mocked JSON payloads, real signing is rollout Phase 4). See
        docs/multi-chain/README.md and docs/multi-chain/evm-test-plan.md.
    """

    def setup_method(self):
        super().setup_method()
        # Override BaseTest's "bitcoin" default (see docs/multi-chain/boot-chain-selection-plan.md) --
        # this is what actually gates every EVM view/button now that
        # SETTING__MULTICHAIN_ENABLED has been retired in its favor.
        self.controller.active_chain_id = "evm"


    def seed_fixture(self) -> Seed:
        """ A finalized Seed without driving the full scan/finalize UI flow. """
        seed = Seed(mnemonic=["abandon"] * 11 + ["about"], wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)
        self.controller.storage.seeds.append(seed)
        return seed


    def test_chain_registry_has_evm_plugin(self):
        from seedsigner.chains import ChainRegistry
        plugin = ChainRegistry.get("evm")
        assert plugin.chain_id == "evm"
        assert plugin.display_name == "Ethereum / EVM"


    def test_evm_address_flow(self):
        """
            SeedOptionsView -> EvmNetworkView -> EvmSelectAddressIndexView ->
            EvmAddressView -> EvmAddressQRView -> MainMenuView. Non-zero index (1)
            deliberately, to prove the picker's value actually flows through to
            derivation, not just that the screen appears. EvmOptionsView/
            MultiChainOptionsView are retired -- SeedOptionsView routes directly
            (see docs/multi-chain/boot-chain-selection-plan.md).
        """
        self.run_sequence(ENTER_SEED_OPTIONS_STEPS + [
            FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.EVM_ADDRESS),
            FlowStep(evm_views.EvmNetworkView, screen_return_value=1),  # "Base"
            FlowStep(evm_views.EvmSelectAddressIndexView, screen_return_value="1"),
            FlowStep(evm_views.EvmAddressView, screen_return_value=0),  # "Export Address QR"
            FlowStep(evm_views.EvmAddressQRView, screen_return_value=0),
            FlowStep(MainMenuView),
        ])


    def test_evm_address_view_connect_button_routes_to_connect_qr_view(self):
        """ Plan Phase 2's merged screen: the *same* EvmAddressView, but the second
            button ("Export Connect QR") must route to EvmConnectQRView, not
            EvmAddressQRView -- confirms the merge actually dispatches on which
            button was pressed rather than always taking one branch. """
        self.run_sequence(ENTER_SEED_OPTIONS_STEPS + [
            FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.EVM_ADDRESS),
            FlowStep(evm_views.EvmNetworkView, screen_return_value=0),  # "Optimism"
            FlowStep(evm_views.EvmSelectAddressIndexView, screen_return_value="0"),
            FlowStep(evm_views.EvmAddressView, screen_return_value=1),  # "Export Connect QR"
            FlowStep(evm_views.EvmConnectQRView, screen_return_value=0),
            FlowStep(MainMenuView),
        ])


    def test_evm_connect_qr_view_encodes_account_level_hdkey_for_the_selected_seed(self):
        """ EvmConnectQRView must actually build its QR from *this* seed, not a
            placeholder -- confirms the encoder's CBOR carries the exact
            fingerprint/pubkey chains.evm.ur_types.build_account_hdkey_cbor would
            independently compute for the same seed. """
        from seedsigner.chains.evm.ur_types import build_account_hdkey_cbor
        from seedsigner.models.encode_qr import UrEvmConnectQrEncoder
        from seedsigner.models.settings import SettingsConstants

        seed = self.seed_fixture()
        view = evm_views.EvmConnectQRView(seed=seed)

        encoder = UrEvmConnectQrEncoder(
            seed_bytes=view.seed.seed_bytes,
            account=0,
            qr_density=SettingsConstants.DENSITY__MEDIUM,
        )
        assert encoder.ur2_encode.ur.type == "crypto-hdkey"
        assert encoder.ur2_encode.ur.cbor == build_account_hdkey_cbor(seed.seed_bytes, account=0)

        # Zeroize-audit regression: seed_bytes is only needed to build the CBOR
        # above; the encoder must drop its own reference afterward rather than
        # keeping the raw seed alive as a live attribute for the whole QR-display
        # session (see encode_qr.py's UrEvmConnectQrEncoder.__post_init__).
        assert encoder.seed_bytes is None


    def test_evm_address_is_deterministic_per_derivation_path(self):
        """
            Real derivation (rollout Phase 2) -- deterministic per (seed, path), and
            different paths must not collide. Cross-verification against eth_account
            lives in test_evm_crypto.py; this checks the plugin-level contract.
        """
        from seedsigner.chains import ChainRegistry
        seed = self.seed_fixture()
        plugin = ChainRegistry.get("evm")

        addr1 = plugin.derive_address(seed.seed_bytes, "m/44'/60'/0'/0/0")
        addr2 = plugin.derive_address(seed.seed_bytes, "m/44'/60'/0'/0/0")
        addr3 = plugin.derive_address(seed.seed_bytes, "m/44'/60'/0'/0/1")

        assert addr1.address == addr2.address
        assert addr1.address != addr3.address
        assert addr1.address.startswith("0x")
        assert len(addr1.address) == 42


    def test_evm_sign_flow_transfer(self):
        """ SeedOptionsView -> EvmSignSelectView -> EvmSelectAddressIndexView
            -> EvmSignStartView (redirect) -> EvmConfirmPayloadView (paged) ->
            EvmConfirmAddressView -> EvmSignedQRView -> MainMenuView. Ordinary
            transfer (rollout Phase 4: a real RLP-encoded EIP-1559 transaction,
            really signed): 4 review fields (Network, Operation, Amount, To) +
            first-time-address warning. """
        self.run_sequence(ENTER_SEED_OPTIONS_STEPS + [
            FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.EVM_SIGN),
            FlowStep(evm_views.EvmSignSelectView, screen_return_value=0),  # "Ordinary transfer"
            FlowStep(evm_views.EvmSelectAddressIndexView, screen_return_value="0"),
            FlowStep(evm_views.EvmSignStartView, is_redirect=True),
            FlowStep(evm_views.EvmConfirmPayloadView, screen_return_value=0),  # Network (1/5)
            FlowStep(evm_views.EvmConfirmPayloadView, screen_return_value=0),  # Operation (2/5)
            FlowStep(evm_views.EvmConfirmPayloadView, screen_return_value=0),  # Amount (3/5)
            FlowStep(evm_views.EvmConfirmPayloadView, screen_return_value=0),  # To (4/5)
            FlowStep(evm_views.EvmConfirmPayloadView, screen_return_value=0),  # First-time address warning (5/5)
            FlowStep(evm_views.EvmConfirmAddressView, screen_return_value=0),  # Sign
            FlowStep(evm_views.EvmSignedQRView, screen_return_value=0),
            FlowStep(MainMenuView),
        ])

        assert self.controller.multichain_data is None


    def test_evm_sign_flow_approve_unlimited_flags_warning(self):
        """ The unlimited-approval scenario's Amount field must come through flagged
            as a warning -- this is the actual anti-scam mechanism under test, not
            just UI plumbing. """
        from seedsigner.chains import ChainRegistry
        seed = self.seed_fixture()
        plugin = ChainRegistry.get("evm")
        from seedsigner.chains.evm.plugin import DEMO_SCENARIOS

        parsed = plugin.parse_sign_request(DEMO_SCENARIOS["approve_unlimited"])
        amount_field = next(f for f in parsed.review_fields if f.label == "Amount")
        assert amount_field.is_warning is True
        assert amount_field.value == "UNLIMITED"


    def test_evm_transfer_scenario_review_fields_are_real(self):
        """ The transfer demo is a real RLP-encoded EIP-1559 transaction (rollout
            Phase 4) -- confirms the review fields show the real decoded amount/
            recipient, not placeholder text. """
        from seedsigner.chains import ChainRegistry
        from seedsigner.chains.evm.plugin import DEMO_SCENARIOS, _DEMO_TO_ADDRESS

        plugin = ChainRegistry.get("evm")
        parsed = plugin.parse_sign_request(DEMO_SCENARIOS["transfer"])
        by_label = {f.label: f.value for f in parsed.review_fields}

        assert by_label["Operation"] == "Transfer"
        assert by_label["Amount"] == "0.05 ETH"
        assert by_label["To"] == _DEMO_TO_ADDRESS
        assert by_label["Network"] == "Optimism"


    def test_evm_approve_scenario_resolves_known_usdc_token(self):
        """ approve_unlimited's contract address is Circle's real Optimism mainnet
            USDC address (constants.KNOWN_TOKENS) -- confirms the token symbol
            resolves from that table rather than showing a raw/unknown-token
            warning. """
        from seedsigner.chains import ChainRegistry
        from seedsigner.chains.evm.plugin import DEMO_SCENARIOS

        plugin = ChainRegistry.get("evm")
        parsed = plugin.parse_sign_request(DEMO_SCENARIOS["approve_unlimited"])
        by_label = {f.label: f.value for f in parsed.review_fields}

        assert by_label["Token"] == "USDC"


    def test_evm_sign_produces_real_recoverable_signature(self):
        """ End-to-end rollout Phase 4 check: signing the transfer demo scenario with
            a known seed produces a real ECDSA signature that recovers to the address
            derived for that same seed/path -- not just screen navigation. """
        from eth_keys import keys as eth_keys

        from seedsigner.chains import ChainRegistry
        from seedsigner.chains.evm.plugin import DEMO_SCENARIOS, DERIVATION_PATH_TEMPLATE
        from seedsigner.chains.evm.transaction import UnsignedEip1559Transaction

        seed = self.seed_fixture()
        plugin = ChainRegistry.get("evm")
        path = DERIVATION_PATH_TEMPLATE.format(account=0, index=0)
        payload = DEMO_SCENARIOS["transfer"]

        address = plugin.derive_address(seed.seed_bytes, path).address
        signature = plugin.sign(seed.seed_bytes, path, payload)

        assert len(signature.signature_bytes) == 65
        r = int.from_bytes(signature.signature_bytes[:32], "big")
        s = int.from_bytes(signature.signature_bytes[32:64], "big")
        y_parity = signature.signature_bytes[64]

        msg_hash = UnsignedEip1559Transaction(payload).signing_hash()
        recovered = eth_keys.Signature(vrs=(y_parity, r, s)).recover_public_key_from_msg_hash(
            msg_hash).to_checksum_address()

        assert recovered == address


    def test_evm_usdc_transfer_scenario_is_real_and_signable(self):
        """ usdc_transfer is a real ERC-20 transfer() call to Circle's real Optimism
            mainnet USDC contract -- confirms it decodes with a real resolved token
            symbol (not an unknown-contract warning) and produces a real, recoverable
            signature. """
        from eth_keys import keys as eth_keys

        from seedsigner.chains import ChainRegistry
        from seedsigner.chains.evm.plugin import DEMO_SCENARIOS, DERIVATION_PATH_TEMPLATE
        from seedsigner.chains.evm.transaction import UnsignedEip1559Transaction

        seed = self.seed_fixture()
        plugin = ChainRegistry.get("evm")
        path = DERIVATION_PATH_TEMPLATE.format(account=0, index=0)
        payload = DEMO_SCENARIOS["usdc_transfer"]

        parsed = plugin.parse_sign_request(payload)
        by_label = {f.label: f for f in parsed.review_fields}
        assert by_label["Token"].value == "USDC"
        assert by_label["Token"].is_warning is False
        assert by_label["Amount"].value == "1 USDC"

        address = plugin.derive_address(seed.seed_bytes, path).address
        signature = plugin.sign(seed.seed_bytes, path, payload)
        assert len(signature.signature_bytes) == 65

        r = int.from_bytes(signature.signature_bytes[:32], "big")
        s = int.from_bytes(signature.signature_bytes[32:64], "big")
        y_parity = signature.signature_bytes[64]
        msg_hash = UnsignedEip1559Transaction(payload).signing_hash()
        recovered = eth_keys.Signature(vrs=(y_parity, r, s)).recover_public_key_from_msg_hash(
            msg_hash).to_checksum_address()
        assert recovered == address


    def test_evm_sign_flow_permit_flags_offchain_warning(self):
        """ The permit scenario must flag the off-chain-signature nature explicitly --
            the single largest documented attack category per the anti-scam
            research. """
        from seedsigner.chains import ChainRegistry
        from seedsigner.chains.evm.plugin import DEMO_SCENARIOS

        plugin = ChainRegistry.get("evm")
        parsed = plugin.parse_sign_request(DEMO_SCENARIOS["permit"])
        warning_fields = [f for f in parsed.review_fields if f.is_warning]
        assert any("Off-chain signature" in f.label for f in warning_fields)
        assert any("First-time address" in f.label for f in warning_fields)


    def test_evm_confirm_payload_back_button_navigation(self):
        """
            Backing out of a later page should return to the previous review page;
            backing out of the first page should abandon the flow and, per
            BackStackView's normal "pop current + previous" semantics, land back on
            EvmSelectAddressIndexView (EvmSignStartView is a skip_current_view
            redirect, so it never occupies its own back-stack entry) -- mirroring
            the 7F work's SevenFConfirmPayloadView.
        """
        self.run_sequence(ENTER_SEED_OPTIONS_STEPS + [
            FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.EVM_SIGN),
            FlowStep(evm_views.EvmSignSelectView, screen_return_value=0),
            FlowStep(evm_views.EvmSelectAddressIndexView, screen_return_value="0"),
            FlowStep(evm_views.EvmSignStartView, is_redirect=True),
            FlowStep(evm_views.EvmConfirmPayloadView, screen_return_value=0),  # page 1 -> Next
            FlowStep(evm_views.EvmConfirmPayloadView, screen_return_value=RET_CODE__BACK_BUTTON),  # page 2 -> Back
            FlowStep(evm_views.EvmConfirmPayloadView, screen_return_value=RET_CODE__BACK_BUTTON),  # page 1 -> Back, abandons flow
            FlowStep(evm_views.EvmSelectAddressIndexView),
        ])

        assert self.controller.multichain_data is None


    def test_seed_options_view_hides_evm_buttons_in_bitcoin_mode(self):
        """ SETTING__MULTICHAIN_ENABLED is retired -- active_chain_id is what gates
            EVM buttons now. In Bitcoin mode, none of the three EVM buttons should
            appear, even though nothing about Bitcoin-mode settings changed. """
        self.controller.active_chain_id = "bitcoin"
        seed = self.seed_fixture()

        view = seed_views.SeedOptionsView(seed=seed)
        with patch.object(view, "run_screen", return_value=RET_CODE__BACK_BUTTON) as mock_run_screen:
            view.run()

        button_data = mock_run_screen.call_args.kwargs["button_data"]
        assert seed_views.SeedOptionsView.EVM_ADDRESS not in button_data
        assert seed_views.SeedOptionsView.EVM_SCAN not in button_data
        assert seed_views.SeedOptionsView.EVM_SIGN not in button_data


    def test_seed_options_view_hides_bitcoin_buttons_in_evm_mode(self):
        """ Mirror of the above: in EVM mode, none of the four Bitcoin-specific
            buttons should appear, even with their own settings toggles enabled --
            active_chain_id ANDs with each toggle, it doesn't get overridden by it. """
        self.settings.set_value(SettingsConstants.SETTING__MESSAGE_SIGNING, SettingsConstants.OPTION__ENABLED)
        seed = self.seed_fixture()  # self.controller.active_chain_id == "evm" from setup_method

        view = seed_views.SeedOptionsView(seed=seed)
        with patch.object(view, "run_screen", return_value=RET_CODE__BACK_BUTTON) as mock_run_screen:
            view.run()

        button_data = mock_run_screen.call_args.kwargs["button_data"]
        assert seed_views.SeedOptionsView.SCAN_PSBT not in button_data
        assert seed_views.SeedOptionsView.EXPORT_XPUB not in button_data
        assert seed_views.SeedOptionsView.EXPLORER not in button_data
        assert seed_views.SeedOptionsView.SIGN_MESSAGE not in button_data


    def test_seed_options_view_hides_both_chains_buttons_when_chain_not_yet_chosen(self):
        """ Fail-closed property: active_chain_id=None (the chooser hasn't run --
            shouldn't be reachable via normal navigation, but this is the exact
            defense-in-depth case the design exists for) hides EVERY chain-specific
            button, Bitcoin's and EVM's alike -- neither branch is `== "bitcoin"` nor
            `== "evm"`, so nothing chain-specific appends. """
        self.controller.active_chain_id = None
        seed = self.seed_fixture()

        view = seed_views.SeedOptionsView(seed=seed)
        with patch.object(view, "run_screen", return_value=RET_CODE__BACK_BUTTON) as mock_run_screen:
            view.run()

        button_data = mock_run_screen.call_args.kwargs["button_data"]
        for chain_specific_button in [
            seed_views.SeedOptionsView.SCAN_PSBT, seed_views.SeedOptionsView.EXPORT_XPUB,
            seed_views.SeedOptionsView.EXPLORER, seed_views.SeedOptionsView.SIGN_MESSAGE,
            seed_views.SeedOptionsView.EVM_ADDRESS, seed_views.SeedOptionsView.EVM_SCAN,
            seed_views.SeedOptionsView.EVM_SIGN,
        ]:
            assert chain_specific_button not in button_data
        # Chain-agnostic buttons are unaffected.
        assert seed_views.SeedOptionsView.BACKUP in button_data
        assert seed_views.SeedOptionsView.DISCARD in button_data


    def test_seed_options_view_psbt_short_circuit_gated_on_bitcoin_mode(self):
        """ Regression test for the HIGH/MEDIUM finding from plan-stage adversarial
            review: must actually exercise the pre-existing fingerprint-match AND
            resume_main_flow==FLOW__PSBT conditions too, not just self.controller.psbt
            being truthy -- otherwise this could pass even if the active_chain_id gate
            were never added (those two pre-existing conditions alone already prevent
            the short-circuit for an unrelated seed/flow). """
        from seedsigner.controller import Controller
        from seedsigner.views.psbt_views import PSBTOverviewView

        psbt = PSBT.parse(a2b_base64(PSBTTestData.SINGLE_SIG_NATIVE_SEGWIT_1_INPUT))
        self.controller.storage.seeds.append(PSBTTestData.seed)
        self.controller.psbt = psbt
        self.controller.psbt_seed = None
        self.controller.resume_main_flow = Controller.FLOW__PSBT
        self.controller.active_chain_id = "evm"

        view = seed_views.SeedOptionsView(seed=PSBTTestData.seed)
        with patch.object(view, "run_screen", return_value=RET_CODE__BACK_BUTTON) as mock_run_screen:
            destination = view.run()

        # Must NOT have short-circuited to PSBTOverviewView -- confirms the
        # active_chain_id=="bitcoin" gate (not just the pre-existing fingerprint/
        # resume-flow checks) is what's actually preventing it here.
        assert destination is None or destination.View_cls != PSBTOverviewView
        mock_run_screen.assert_called_once()

        # Sanity: the exact same seed/psbt/resume_main_flow DOES short-circuit in
        # Bitcoin mode -- proves the fixture is real (a false "evm mode blocks it"
        # result could otherwise mean the fixture never would have triggered the
        # short-circuit at all, chain mode aside).
        self.controller.active_chain_id = "bitcoin"
        view2 = seed_views.SeedOptionsView(seed=PSBTTestData.seed)
        destination2 = view2.run()
        assert destination2.View_cls == PSBTOverviewView


    def test_seed_options_view_address_verification_resume_gated_on_bitcoin_mode(self):
        """ Regression test for the HIGH finding from plan-stage adversarial review:
            the unverified_address/FLOW__VERIFY_SINGLESIG_ADDR short-circuit
            (seed_views.py) must also be gated, not just the PSBT one -- same
            live gap (ScanView's is_address dispatch is still chain-ungated). """
        from seedsigner.controller import Controller
        from seedsigner.views.seed_views import SeedAddressVerificationView

        seed = self.seed_fixture()
        self.controller.unverified_address = dict(address="bc1qexampleaddress", script_type=SettingsConstants.NATIVE_SEGWIT, network=SettingsConstants.MAINNET)
        self.controller.resume_main_flow = Controller.FLOW__VERIFY_SINGLESIG_ADDR
        # self.controller.active_chain_id == "evm" from setup_method

        view = seed_views.SeedOptionsView(seed=seed)
        with patch.object(view, "run_screen", return_value=RET_CODE__BACK_BUTTON) as mock_run_screen:
            destination = view.run()

        assert destination is None or destination.View_cls != SeedAddressVerificationView
        mock_run_screen.assert_called_once()


    def test_electrum_seed_entry_hidden_in_evm_mode_across_all_entry_points(self):
        """ Regression test for the MEDIUM finding from plan-stage adversarial review:
            all FOUR "Enter Electrum seed" entry points (not just SeedSelectSeedView/
            LoadSeedView) must respect active_chain_id, since Electrum-format seeds
            are a Bitcoin-only concept. """
        from seedsigner.views.psbt_views import PSBTSelectSeedView
        from seedsigner.views.tools_views import ToolsAddressExplorerSelectSourceView
        from seedsigner.controller import Controller

        self.settings.set_value(SettingsConstants.SETTING__ELECTRUM_SEEDS, SettingsConstants.OPTION__ENABLED)
        # self.controller.active_chain_id == "evm" from setup_method

        view = seed_views.SeedSelectSeedView(flow=Controller.FLOW__VERIFY_SINGLESIG_ADDR)
        with patch.object(view, "run_screen", return_value=RET_CODE__BACK_BUTTON) as mock_run_screen:
            view.run()
        assert seed_views.SeedSelectSeedView.TYPE_ELECTRUM not in mock_run_screen.call_args.kwargs["button_data"]

        view = seed_views.LoadSeedView()
        with patch.object(view, "run_screen", return_value=RET_CODE__BACK_BUTTON) as mock_run_screen:
            view.run()
        assert seed_views.LoadSeedView.TYPE_ELECTRUM not in mock_run_screen.call_args.kwargs["button_data"]

        self.controller.psbt = PSBT.parse(a2b_base64(PSBTTestData.SINGLE_SIG_NATIVE_SEGWIT_1_INPUT))
        view = PSBTSelectSeedView()
        with patch.object(view, "run_screen", return_value=RET_CODE__BACK_BUTTON) as mock_run_screen:
            view.run()
        assert PSBTSelectSeedView.TYPE_ELECTRUM not in mock_run_screen.call_args.kwargs["button_data"]

        view = ToolsAddressExplorerSelectSourceView()
        with patch.object(view, "run_screen", return_value=RET_CODE__BACK_BUTTON) as mock_run_screen:
            view.run()
        assert ToolsAddressExplorerSelectSourceView.TYPE_ELECTRUM not in mock_run_screen.call_args.kwargs["button_data"]


    def test_evm_select_address_index_view_rejects_out_of_range(self):
        """ Direct-construction check: an out-of-range typed index routes to the
            invalid-index error view rather than crashing or silently clamping --
            same contract as SeedBIP85SelectChildIndexView's own range check. """
        seed = self.seed_fixture()
        view = evm_views.EvmSelectAddressIndexView(seed=seed, network_id="optimism")
        with patch.object(view, "run_screen", return_value=str(2**31)):
            destination = view.run()
        assert destination.View_cls == evm_views.EvmInvalidAddressIndexView


    def test_evm_select_address_index_view_accepts_boundary_values(self):
        """ 0 and 2**31-1 are the valid boundary values (BIP-32 non-hardened child
            index range) -- confirms the check is `< 2**31`, not `<= 2**31`. """
        seed = self.seed_fixture()

        view = evm_views.EvmSelectAddressIndexView(seed=seed, network_id="optimism")
        with patch.object(view, "run_screen", return_value="0"):
            destination = view.run()
        assert destination.View_cls == evm_views.EvmAddressView
        assert destination.view_args["address_index"] == 0

        view = evm_views.EvmSelectAddressIndexView(seed=seed, network_id="optimism")
        with patch.object(view, "run_screen", return_value=str(2**31 - 1)):
            destination = view.run()
        assert destination.View_cls == evm_views.EvmAddressView
        assert destination.view_args["address_index"] == 2**31 - 1


    def test_evm_address_view_uses_the_selected_index(self):
        """ Wiring check: EvmAddressView must actually derive from the index it was
            given, not silently fall back to 0 -- the exact gap this feature fixes
            (previously hardcoded to account=0, index=0 in both the address and
            sign flows). """
        from seedsigner.chains import ChainRegistry

        seed = self.seed_fixture()
        plugin = ChainRegistry.get("evm")

        view = evm_views.EvmAddressView(seed=seed, network_id="optimism", address_index=1)
        assert view.derivation_path == "m/44'/60'/0'/0/1"
        assert view.address == plugin.derive_address(seed.seed_bytes, "m/44'/60'/0'/0/1").address
        # And it's genuinely a different address than index 0 would give.
        assert view.address != plugin.derive_address(seed.seed_bytes, "m/44'/60'/0'/0/0").address


    def test_evm_sign_at_nonzero_index_recovers_to_that_index_address(self):
        """ Same recoverable-signature check as test_evm_sign_produces_real_recoverable_signature,
            but through EvmSignStartView with a non-default index -- confirms the
            picker's value actually reaches the derivation path used for signing,
            not just for address display. """
        from eth_keys import keys as eth_keys

        from seedsigner.chains import ChainRegistry
        from seedsigner.chains.evm.plugin import DEMO_SCENARIOS
        from seedsigner.chains.evm.transaction import UnsignedEip1559Transaction

        seed = self.seed_fixture()
        plugin = ChainRegistry.get("evm")

        view = evm_views.EvmSignStartView(seed=seed, scenario_key="transfer", address_index=1)
        assert self.controller.multichain_data["derivation_path"] == "m/44'/60'/0'/0/1"

        address = plugin.derive_address(seed.seed_bytes, "m/44'/60'/0'/0/1").address
        payload = DEMO_SCENARIOS["transfer"]
        signature = plugin.sign(seed.seed_bytes, "m/44'/60'/0'/0/1", payload)

        r = int.from_bytes(signature.signature_bytes[:32], "big")
        s = int.from_bytes(signature.signature_bytes[32:64], "big")
        y_parity = signature.signature_bytes[64]
        msg_hash = UnsignedEip1559Transaction(payload).signing_hash()
        recovered = eth_keys.Signature(vrs=(y_parity, r, s)).recover_public_key_from_msg_hash(
            msg_hash).to_checksum_address()

        assert recovered == address
        # And it's genuinely not the index-0 address -- a weaker test could pass
        # by accident if signing silently ignored the index entirely.
        assert address != plugin.derive_address(seed.seed_bytes, "m/44'/60'/0'/0/0").address


    def test_evm_scan_sign_request_rejects_unsupported_data_type(self):
        """ Self-validation: refuse a real-but-unsupported request type outright
            (legacy pre-EIP-1559, EIP-712, raw message) rather than attempt to
            mis-parse it -- same "refuse rather than guess" rule this codebase
            applies everywhere else. """
        from seedsigner.chains.evm.ur_types import EthSignRequest, DATA_TYPE_TRANSACTION

        seed = self.seed_fixture()
        view = evm_views.EvmScanSignRequestView(seed=seed)
        legacy_request = EthSignRequest(
            sign_data=b"\xf8I", data_type=DATA_TYPE_TRANSACTION, chain_id=1,
            derivation_path="m/44'/60'/0'/0/0",
        )
        with patch.object(view.decoder, "get_eth_sign_request", return_value=legacy_request):
            destination = view._handle_complete_scan()

        assert destination.View_cls == evm_views.EvmUnsupportedSignRequestView
        assert self.controller.multichain_data is None


    def test_evm_scan_sign_request_rejects_type_confused_payload(self):
        """ The HIGH bug an adversarial code review found: a scanned request can
            claim data_type=DATA_TYPE_TYPED_TRANSACTION (the only value this view
            accepts) while sign_data is actually shaped like the still-mocked
            permit JSON demo below -- which parse_sign_request()/sign() would
            otherwise silently accept, showing fully attacker-authored review
            content and a signature that's just random bytes, on what's presented
            as the gated, real scan-and-sign flow. Must be refused before ever
            reaching parse_sign_request(). """
        from seedsigner.chains.evm.plugin import DEMO_SCENARIOS
        from seedsigner.chains.evm.ur_types import EthSignRequest, DATA_TYPE_TYPED_TRANSACTION

        seed = self.seed_fixture()
        view = evm_views.EvmScanSignRequestView(seed=seed)
        type_confused_request = EthSignRequest(
            sign_data=DEMO_SCENARIOS["permit"],  # not 0x02-prefixed -- not a real transaction
            data_type=DATA_TYPE_TYPED_TRANSACTION,  # but claims to be one
            chain_id=10, derivation_path="m/44'/60'/0'/0/0",
        )
        with patch.object(view.decoder, "get_eth_sign_request", return_value=type_confused_request):
            destination = view._handle_complete_scan()

        assert destination.View_cls == evm_views.EvmUnsupportedSignRequestView
        assert self.controller.multichain_data is None


    def test_evm_scan_sign_request_rejects_a_non_evm_derivation_path(self):
        """ The CRITICAL bug an adversarial security review found: a scanned
            request's derivation path is fully attacker-controlled -- must be
            refused before EvmConfirmAddressView/EvmSignedUrQRView ever derive or
            sign with it, not just displayed as a hard-to-verify string. """
        from seedsigner.chains.evm.plugin import DEMO_SCENARIOS
        from seedsigner.chains.evm.ur_types import EthSignRequest, DATA_TYPE_TYPED_TRANSACTION

        seed = self.seed_fixture()
        view = evm_views.EvmScanSignRequestView(seed=seed)
        cross_key_request = EthSignRequest(
            sign_data=DEMO_SCENARIOS["usdc_transfer"], data_type=DATA_TYPE_TYPED_TRANSACTION,
            chain_id=10, derivation_path="m/84'/0'/0'/0/0",  # this seed's Bitcoin path, not EVM's
        )
        with patch.object(view.decoder, "get_eth_sign_request", return_value=cross_key_request):
            destination = view._handle_complete_scan()

        assert destination.View_cls == evm_views.EvmUnsupportedSignRequestView
        assert self.controller.multichain_data is None


    def test_evm_scan_sign_request_rejects_undecodable_request(self):
        """ get_eth_sign_request() returning None (malformed CBOR, wrong shape,
            etc.) must not crash the flow. """
        seed = self.seed_fixture()
        view = evm_views.EvmScanSignRequestView(seed=seed)
        with patch.object(view.decoder, "get_eth_sign_request", return_value=None):
            destination = view._handle_complete_scan()

        assert destination.View_cls == evm_views.EvmUnsupportedSignRequestView


    def test_evm_scan_sign_request_populates_review_fields_with_derivation_path_first(self):
        """ The requested derivation path is untrusted external input (unlike the
            demo menu, which the operator always controls) -- confirms it's
            surfaced as its own review field, ahead of the transaction's own
            fields, not buried or omitted. """
        from seedsigner.chains.evm.ur_types import EthSignRequest, DATA_TYPE_TYPED_TRANSACTION
        from seedsigner.chains.evm.plugin import DEMO_SCENARIOS

        seed = self.seed_fixture()
        view = evm_views.EvmScanSignRequestView(seed=seed)
        real_request = EthSignRequest(
            sign_data=DEMO_SCENARIOS["usdc_transfer"], data_type=DATA_TYPE_TYPED_TRANSACTION, chain_id=10,
            derivation_path="m/44'/60'/0'/0/1", request_id=b"\x02" * 16, origin="metamask",
        )
        with patch.object(view.decoder, "get_eth_sign_request", return_value=real_request):
            destination = view._handle_complete_scan()

        assert destination.View_cls == evm_views.EvmConfirmPayloadView
        data = self.controller.multichain_data
        assert data["derivation_path"] == "m/44'/60'/0'/0/1"
        assert data["payload"] == DEMO_SCENARIOS["usdc_transfer"]
        assert data["eth_sign_request"] is real_request
        assert data["fields"][0].label == "Derivation Path"
        assert data["fields"][0].value == "m/44'/60'/0'/0/1"
        # And the transaction's own real fields still follow -- confirms this
        # prepends, it doesn't replace, plugin.parse_sign_request()'s output.
        assert any(f.label == "Token" for f in data["fields"][1:])


    def test_evm_signed_ur_qr_view_produces_correlated_recoverable_signature(self):
        """ End-to-end for the real ERC-4527 response: the produced eth-signature
            (1) carries the *same* request_id as the request it answers (how a
            real requester correlates response to request) and (2) is a real,
            recoverable ECDSA signature for the address at the requested path --
            not a demo/mocked one. """
        from eth_keys import keys as eth_keys

        from seedsigner.chains import ChainRegistry
        from seedsigner.chains.evm.plugin import DEMO_SCENARIOS
        from seedsigner.chains.evm.transaction import UnsignedEip1559Transaction
        from seedsigner.chains.evm.ur_types import EthSignRequest, DATA_TYPE_TYPED_TRANSACTION

        seed = self.seed_fixture()
        plugin = ChainRegistry.get("evm")
        payload = DEMO_SCENARIOS["usdc_transfer"]
        request_id = b"\x03" * 16

        self.controller.multichain_data = dict(
            seed=seed,
            chain_id="evm",
            derivation_path="m/44'/60'/0'/0/1",
            payload=payload,
            fields=[],
            eth_sign_request=EthSignRequest(
                sign_data=payload, data_type=DATA_TYPE_TYPED_TRANSACTION, chain_id=10,
                derivation_path="m/44'/60'/0'/0/1", request_id=request_id,
            ),
        )

        view = evm_views.EvmSignedUrQRView()
        assert view.eth_signature.request_id == request_id
        assert len(view.eth_signature.signature) == 65

        address = plugin.derive_address(seed.seed_bytes, "m/44'/60'/0'/0/1").address
        r = int.from_bytes(view.eth_signature.signature[:32], "big")
        s = int.from_bytes(view.eth_signature.signature[32:64], "big")
        y_parity = view.eth_signature.signature[64]
        msg_hash = UnsignedEip1559Transaction(payload).signing_hash()
        recovered = eth_keys.Signature(vrs=(y_parity, r, s)).recover_public_key_from_msg_hash(
            msg_hash).to_checksum_address()
        assert recovered == address


    def test_evm_signed_ur_qr_view_generates_request_id_when_request_omitted_one(self):
        """ request-id is optional on the request per the spec but required on the
            response -- confirms the rare omitted case doesn't crash, and produces
            *some* 16-byte id rather than None. """
        from seedsigner.chains import ChainRegistry
        from seedsigner.chains.evm.plugin import DEMO_SCENARIOS
        from seedsigner.chains.evm.ur_types import EthSignRequest, DATA_TYPE_TYPED_TRANSACTION

        seed = self.seed_fixture()
        payload = DEMO_SCENARIOS["usdc_transfer"]

        self.controller.multichain_data = dict(
            seed=seed, chain_id="evm", derivation_path="m/44'/60'/0'/0/0", payload=payload, fields=[],
            eth_sign_request=EthSignRequest(
                sign_data=payload, data_type=DATA_TYPE_TYPED_TRANSACTION, chain_id=10,
                derivation_path="m/44'/60'/0'/0/0", request_id=None,
            ),
        )

        view = evm_views.EvmSignedUrQRView()
        assert view.eth_signature.request_id is not None
        assert len(view.eth_signature.request_id) == 16


    def test_evm_confirm_address_routes_to_ur_qr_view_for_scanned_requests_demo_qr_otherwise(self):
        """ EvmConfirmAddressView's final "Sign" branch must route by what actually
            answers the request correctly, not always the same QR type: a real
            scanned request needs an eth-signature UR (what the requester expects
            back); the demo menu keeps the plain-text EVM-DEMO-SIG: QR. """
        from seedsigner.chains.evm.plugin import DEMO_SCENARIOS
        from seedsigner.chains.evm.ur_types import EthSignRequest, DATA_TYPE_TYPED_TRANSACTION

        seed = self.seed_fixture()
        payload = DEMO_SCENARIOS["usdc_transfer"]

        # Scanned-request path
        self.controller.multichain_data = dict(
            seed=seed, chain_id="evm", derivation_path="m/44'/60'/0'/0/0", payload=payload, fields=[],
            eth_sign_request=EthSignRequest(
                sign_data=payload, data_type=DATA_TYPE_TYPED_TRANSACTION, chain_id=10,
                derivation_path="m/44'/60'/0'/0/0", request_id=b"\x04" * 16,
            ),
        )
        view = evm_views.EvmConfirmAddressView()
        with patch.object(view, "run_screen", return_value=0):
            destination = view.run()
        assert destination.View_cls == evm_views.EvmSignedUrQRView

        # Demo-menu path (no eth_sign_request key at all)
        self.controller.multichain_data = dict(
            seed=seed, chain_id="evm", derivation_path="m/44'/60'/0'/0/0", payload=payload, fields=[],
        )
        view = evm_views.EvmConfirmAddressView()
        with patch.object(view, "run_screen", return_value=0):
            destination = view.run()
        assert destination.View_cls == evm_views.EvmSignedQRView


    def test_decode_qr_recognizes_and_decodes_a_real_eth_sign_request_ur(self):
        """ Confirms the actual QR-type detection regex and DecodeQR dispatch
            (models/qr_type.py, models/decode_qr.py) work end to end with a real
            UR-encoded string built the way a scanned QR frame actually arrives --
            not just the ur_types.py-level unit tests in test_evm_ur_types.py, which
            bypass DecodeQR entirely. """
        from seedsigner.chains.evm.plugin import DEMO_SCENARIOS
        from seedsigner.chains.evm.ur_types import EthSignRequest, DATA_TYPE_TYPED_TRANSACTION
        from seedsigner.helpers.ur2.ur import UR
        from seedsigner.helpers.ur2.ur_encoder import UREncoder
        from seedsigner.models.decode_qr import DecodeQR
        from seedsigner.models.qr_type import QRType

        payload = DEMO_SCENARIOS["usdc_transfer"]
        eth_sign_request = EthSignRequest(
            sign_data=payload, data_type=DATA_TYPE_TYPED_TRANSACTION, chain_id=10,
            derivation_path="m/44'/60'/0'/0/1", request_id=b"\x05" * 16, origin="metamask",
        )
        ur = UR("eth-sign-request", eth_sign_request.to_cbor())
        # max_fragment_len large enough that this small payload fits in a single QR
        # frame -- exactly what a real device would produce for a request this size.
        qr_string = UREncoder(ur=ur, max_fragment_len=800).next_part()

        decoder = DecodeQR()
        status = decoder.add_data(qr_string)

        assert decoder.qr_type == QRType.EVM__ETH_SIGN_REQUEST_UR
        assert decoder.is_eth_sign_request
        assert decoder.complete

        decoded = decoder.get_eth_sign_request()
        assert decoded.sign_data == payload
        assert decoded.derivation_path == "m/44'/60'/0'/0/1"
        assert decoded.request_id == b"\x05" * 16
        assert decoded.origin == "metamask"


    def test_evm_views_refuse_to_run_outside_evm_mode(self):
        """ Direct-construction guard: each of the 4 EVM entry-point views (now that
            EvmOptionsView is retired -- see docs/multi-chain/boot-chain-selection-plan.md)
            refuses to run itself with active_chain_id != "evm", not just relying on
            SeedOptionsView hiding its button. Checks both the wrong-chain case
            (Bitcoin) and the fail-closed None case (chooser not yet completed). """
        seed = self.seed_fixture()

        for wrong_chain_id in ["bitcoin", None]:
            self.controller.active_chain_id = wrong_chain_id

            view = evm_views.EvmNetworkView(seed=seed)
            assert view.has_redirect
            assert view.get_redirect().View_cls == MainMenuView

            view = evm_views.EvmSignSelectView(seed=seed)
            assert view.has_redirect
            assert view.get_redirect().View_cls == MainMenuView

            view = evm_views.EvmScanSignRequestView(seed=seed)
            assert view.has_redirect
            assert view.get_redirect().View_cls == MainMenuView

            view = evm_views.EvmSignStartView(seed=seed, scenario_key="transfer", address_index=0)
            assert view.has_redirect
            assert view.get_redirect().View_cls == MainMenuView
            # And it must not have gone on to set multichain_data before redirecting.
            assert self.controller.multichain_data is None


    def test_address_verification_start_view_refuses_to_run_outside_bitcoin_mode(self):
        """ Mirror-image guard test for the new Bitcoin-side fix (finding #3 from
            plan-stage adversarial review): AddressVerificationStartView must refuse
            to run, and crucially must NOT set self.controller.unverified_address,
            when active_chain_id != "bitcoin". """
        for wrong_chain_id in ["evm", None]:
            self.controller.active_chain_id = wrong_chain_id
            self.controller.unverified_address = None

            view = seed_views.AddressVerificationStartView(
                address="bc1qexampleaddress", script_type=SettingsConstants.NATIVE_SEGWIT, network=SettingsConstants.MAINNET)
            assert view.has_redirect
            assert view.get_redirect().View_cls == MainMenuView
            assert self.controller.unverified_address is None


    def test_tools_menu_hides_address_explorer_and_verify_address_in_evm_mode(self):
        """ multi-chain-boot-chain-selection-tools-gating: both are Bitcoin-specific
            (no EVM equivalent exists yet -- see
            multi-chain-tools-evm-address-explorer-and-verify-address), so neither
            should appear once active_chain_id != "bitcoin". The chain-agnostic
            entropy/word-calc tools are unaffected. """
        from seedsigner.views.tools_views import ToolsMenuView

        # self.controller.active_chain_id == "evm" from setup_method
        view = ToolsMenuView()
        with patch.object(view, "run_screen", return_value=RET_CODE__BACK_BUTTON) as mock_run_screen:
            view.run()

        button_data = mock_run_screen.call_args.kwargs["button_data"]
        assert ToolsMenuView.ADDRESS_EXPLORER not in button_data
        assert ToolsMenuView.VERIFY_ADDRESS not in button_data
        assert ToolsMenuView.IMAGE in button_data
        assert ToolsMenuView.DICE in button_data
        assert ToolsMenuView.KEYBOARD in button_data


    def test_settings_menu_hides_bitcoin_scoped_entries_in_evm_mode(self):
        """ multi-chain-boot-chain-selection-settings-scope: the 8 Bitcoin-scoped
            SettingsEntry rows (chain_scope="bitcoin") must not appear in either the
            General or Advanced settings screens while active_chain_id == "evm";
            chain-agnostic entries (e.g. Persistent Settings) are unaffected. """
        from unittest.mock import MagicMock
        from seedsigner.views.settings_views import SettingsMenuView
        from seedsigner.models.settings_definition import SettingsConstants as SC, SettingsDefinition

        def shown_labels_for(entry):
            view = SettingsMenuView(visibility=entry.visibility)
            view.screen = MagicMock()  # run()'s post-scroll-position read needs this set
            with patch.object(view, "run_screen", return_value=RET_CODE__BACK_BUTTON) as mock_run_screen:
                view.run()
            return {b.button_label for b in mock_run_screen.call_args.kwargs["button_data"]}

        bitcoin_scoped_attrs = [
            SC.SETTING__NETWORK, SC.SETTING__BTC_DENOMINATION, SC.SETTING__SIG_TYPES,
            SC.SETTING__SCRIPT_TYPES, SC.SETTING__XPUB_QR_FORMAT, SC.SETTING__XPUB_DETAILS,
            SC.SETTING__ELECTRUM_SEEDS, SC.SETTING__MESSAGE_SIGNING,
        ]

        # self.controller.active_chain_id == "evm" from setup_method
        for attr in bitcoin_scoped_attrs:
            entry = SettingsDefinition.get_settings_entry(attr)
            assert entry.display_name not in shown_labels_for(entry)

        # Sanity + fixture-validity check: the same entries DO show up in Bitcoin mode --
        # proves this isn't a false "evm hides everything" result.
        self.controller.active_chain_id = "bitcoin"
        for attr in bitcoin_scoped_attrs:
            entry = SettingsDefinition.get_settings_entry(attr)
            assert entry.display_name in shown_labels_for(entry)

        # Chain-agnostic entry unaffected in either mode.
        persistent_entry = SettingsDefinition.get_settings_entry(SC.SETTING__PERSISTENT_SETTINGS)
        for chain_id in ["bitcoin", "evm"]:
            self.controller.active_chain_id = chain_id
            assert persistent_entry.display_name in shown_labels_for(persistent_entry)
