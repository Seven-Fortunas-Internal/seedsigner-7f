from unittest.mock import patch

# Must import test base before the Controller
from base import BaseTest, FlowTest, FlowStep

from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON
from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants
from seedsigner.views.view import MainMenuView, OptionDisabledView
from seedsigner.views import seed_views, scan_views, settings_views, multichain_views, evm_views


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

ENTER_EVM_OPTIONS_STEPS = ENTER_SEED_OPTIONS_STEPS + [
    FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.MULTICHAIN),
    FlowStep(multichain_views.MultiChainOptionsView, screen_return_value=0),  # only EVM registered right now
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
        self.settings.set_value(SettingsConstants.SETTING__MULTICHAIN_ENABLED, SettingsConstants.OPTION__ENABLED)


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
            SeedOptionsView -> MultiChainOptionsView -> EvmOptionsView ->
            EvmNetworkView -> EvmAddressView -> EvmAddressQRView -> MainMenuView.
        """
        self.run_sequence(ENTER_EVM_OPTIONS_STEPS + [
            FlowStep(evm_views.EvmOptionsView, button_data_selection=evm_views.EvmOptionsView.ADDRESS),
            FlowStep(evm_views.EvmNetworkView, screen_return_value=1),  # "Base"
            FlowStep(evm_views.EvmAddressView, screen_return_value=0),  # "Export QR"
            FlowStep(evm_views.EvmAddressQRView, screen_return_value=0),
            FlowStep(MainMenuView),
        ])


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
        """ SeedOptionsView -> ... -> EvmSignSelectView -> EvmSignStartView (redirect)
            -> EvmConfirmPayloadView (paged) -> EvmConfirmAddressView ->
            EvmSignedQRView -> MainMenuView. Ordinary transfer (rollout Phase 4: a
            real RLP-encoded EIP-1559 transaction, really signed): 4 review fields
            (Network, Operation, Amount, To) + first-time-address warning. """
        self.run_sequence(ENTER_EVM_OPTIONS_STEPS + [
            FlowStep(evm_views.EvmOptionsView, button_data_selection=evm_views.EvmOptionsView.SIGN),
            FlowStep(evm_views.EvmSignSelectView, screen_return_value=0),  # "Ordinary transfer"
            FlowStep(evm_views.EvmSignStartView, is_redirect=True),
            FlowStep(evm_views.EvmConfirmPayloadView, screen_return_value=0),  # Network (1/5)
            FlowStep(evm_views.EvmConfirmPayloadView, screen_return_value=0),  # Operation (2/5)
            FlowStep(evm_views.EvmConfirmPayloadView, screen_return_value=0),  # Amount (3/5)
            FlowStep(evm_views.EvmConfirmPayloadView, screen_return_value=0),  # To (4/5)
            FlowStep(evm_views.EvmConfirmPayloadView, screen_return_value=0),  # First-time address warning (5/5)
            FlowStep(evm_views.EvmConfirmAddressView, screen_return_value=0),  # Sign (DEMO)
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
            EvmSignSelectView -- mirroring the 7F work's SevenFConfirmPayloadView.
        """
        self.run_sequence(ENTER_EVM_OPTIONS_STEPS + [
            FlowStep(evm_views.EvmOptionsView, button_data_selection=evm_views.EvmOptionsView.SIGN),
            FlowStep(evm_views.EvmSignSelectView, screen_return_value=0),
            FlowStep(evm_views.EvmSignStartView, is_redirect=True),
            FlowStep(evm_views.EvmConfirmPayloadView, screen_return_value=0),  # page 1 -> Next
            FlowStep(evm_views.EvmConfirmPayloadView, screen_return_value=RET_CODE__BACK_BUTTON),  # page 2 -> Back
            FlowStep(evm_views.EvmConfirmPayloadView, screen_return_value=RET_CODE__BACK_BUTTON),  # page 1 -> Back, abandons flow
            FlowStep(evm_views.EvmSignSelectView),
        ])

        assert self.controller.multichain_data is None


    def test_multichain_option_disabled_hides_seed_options_button(self):
        """
            With the "Other Blockchains" setting off, SeedOptionsView shouldn't offer
            that button at all.
        """
        self.settings.set_value(SettingsConstants.SETTING__MULTICHAIN_ENABLED, SettingsConstants.OPTION__DISABLED)
        seed = self.seed_fixture()

        view = seed_views.SeedOptionsView(seed=seed)
        with patch.object(view, "run_screen", return_value=RET_CODE__BACK_BUTTON) as mock_run_screen:
            view.run()

        button_data = mock_run_screen.call_args.kwargs["button_data"]
        assert seed_views.SeedOptionsView.MULTICHAIN not in button_data


    def test_evm_options_disabled_redirects(self):
        """ Direct-construction guard: EvmOptionsView itself refuses to run with the
            setting off, not just relying on SeedOptionsView hiding its button. """
        self.settings.set_value(SettingsConstants.SETTING__MULTICHAIN_ENABLED, SettingsConstants.OPTION__DISABLED)
        seed = self.seed_fixture()

        view = evm_views.EvmOptionsView(seed=seed)
        assert view.has_redirect
        destination = view.get_redirect()
        assert destination.View_cls == OptionDisabledView
