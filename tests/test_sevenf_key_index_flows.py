"""
    Every Root and dev-fund flow at a NONZERO key index
    (7f-signing-support-key-index-selector,
    docs/7f-integration/root-key-index-selector-plan.md): the chosen index
    reaches derivation and signing, is shown on review and confirm, and the
    result matches the real sf-wallet-gov (7fchain 06a47ba) on the canonical
    "abandon x23 + art" test phrase. test_sevenf_views.py covers index 0.
"""
import time
from pathlib import Path

import pytest

# Must import test base before the Controller (see base.py's own comment).
from base import FlowTest

from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants
from seedsigner.models.sevenf import cert_request, mldsa, root_ceremony
from seedsigner.models.sevenf.ceremony_clock import ConfirmedClock
from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.models.sevenf.export_envelope import pem_to_der
from seedsigner.models.sevenf.review_format import ski
from seedsigner.views import seed_views, sevenf_views

from test_sevenf_key_index import DEVFUND_SKI, ROOT_SKI
from test_sevenf_views import _past_key_index, _sample_canonical_bytes, _sample_devfund_canonical_bytes


def _lib_available() -> bool:
    try:
        mldsa._lib_handle()
        return True
    except FileNotFoundError:
        return False


pytestmark = pytest.mark.skipif(not _lib_available(), reason="mldsa7f library not built")

# `sf-wallet-gov sign-root-cert --index 1` on the canonical phrase, testnet.
INDEX_1_ROOT_CERT_DER = pem_to_der(
    (Path(__file__).parent / "fixtures" / "sf_wallet_gov_root_cert_abandon_art_testnet_index1.pem").read_text())


def _run(view, screen_return=0, captured=None):
    def fake_run_screen(screen_cls, **kwargs):
        if captured is not None:
            captured.update(kwargs)
        return screen_return

    with pytest.MonkeyPatch().context() as mp:
        mp.setattr(view, "run_screen", fake_run_screen)
        return view.run()


def _seed_of(view) -> Seed:
    return view.state.seed if hasattr(view, "state") else view.seed


class _IndexFlowTest(FlowTest):
    def seed_fixture(self) -> Seed:
        seed = Seed(mnemonic=["abandon"] * 23 + ["art"], wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)
        self.controller.storage.seeds.append(seed)
        return seed



class TestEnrollmentAtAnIndex(_IndexFlowTest):
    def test_root_vk_at_index_2_is_sf_wallet_gov_s(self):
        seed = self.seed_fixture()
        view = sevenf_views.SevenFSelectChainKindForRootEnrollmentView(seed=seed)
        destination = _past_key_index(_run(view, 1), key_index=2)  # 1 == testnet

        assert destination.View_cls == sevenf_views.SevenFRootVkFingerprintView
        assert ski(destination.view_args["public_key"].hex()) == ROOT_SKI[2]
        assert destination.view_args["key_index"] == 2

        captured = {}
        pin_destination = _run(sevenf_views.SevenFRootVkFingerprintView(**destination.view_args), 0, captured)
        assert captured["text"].endswith("\nindex 2")
        assert pin_destination.view_args["key_index"] == 2


    def test_devfund_vk_at_index_7_is_sf_wallet_gov_s_and_asks_a_devfund_index(self):
        seed = self.seed_fixture()
        view = sevenf_views.SevenFSelectChainKindForDevfundEnrollmentView(seed=seed)
        destination = _past_key_index(_run(view, 1), role="devfund", key_index=7)

        assert ski(destination.view_args["public_key"].hex()) == DEVFUND_SKI[7]
        assert destination.view_args["title"] == "Dev-fund VK"



class TestSelfCertAtAnIndex(_IndexFlowTest):
    def test_index_1_certificate_is_reviewed_signed_and_assembled_at_index_1(self):
        seed = self.seed_fixture()
        self.controller.sevenf_confirmed_clock = ConfirmedClock(utc=1_800_000_000, monotonic=time.monotonic())
        view = sevenf_views.SevenFSelectChainKindForRootSelfCertView(seed=seed, date_confirmed=True)
        review = _past_key_index(_run(view, 1), key_index=1)

        first = review.view_args["review_fields"][0]
        assert (first.label, first.value) == ("Root key", "index 1\nroot/testnet/1/\nml-dsa/v1")
        assert first.is_warning is True

        confirm = sevenf_views.SevenFConfirmSignRootCertView(**review.view_args["confirmed_view_args"])
        captured = {}
        signed = _run(confirm, 0, captured)
        assert captured["subject_key_id"].endswith("\nindex 1")
        certificate = signed.view_args["certificate"]
        assert certificate.key_index == 1
        assert ski(certificate.public_key.hex()) == ROOT_SKI[1]
        cert_request.assemble_root_cert_der(certificate.tbs_bytes, certificate.signature, certificate.public_key)

        # After the certificate export: the VK screens for the same index.
        export = sevenf_views.SevenFExportRootCertQRView(certificate=certificate)
        after = _run(export, 0)
        assert after.view_args["key_index"] == 1



class TestDeputyAtAnIndex(_IndexFlowTest):
    def _scan_root_cert(self, seed, key_index):
        view = sevenf_views.SevenFScanRootCertificateView(seed=seed, chain_kind=ChainKind.TESTNET, key_index=key_index)

        class _Decoder:
            def get_sevenf_bbqr_data(self):
                return INDEX_1_ROOT_CERT_DER

        view.decoder = _Decoder()
        return view._handle_complete_scan()


    def test_sf_wallet_gov_index_1_root_cert_is_accepted_at_index_1(self):
        destination = self._scan_root_cert(self.seed_fixture(), 1)
        assert destination.View_cls == sevenf_views.SevenFScanDeputyCsrView
        assert destination.view_args["key_index"] == 1


    def test_sf_wallet_gov_index_1_root_cert_is_refused_at_index_0(self):
        destination = self._scan_root_cert(self.seed_fixture(), 0)
        assert destination.View_cls == sevenf_views.SevenFUnsupportedArtefactView
        assert destination.view_args["headline"] == "Wrong Key"
        assert "at index 0" in destination.view_args["reason"]


    def test_deputy_cert_signed_at_index_1_verifies_under_the_real_index_1_root_cert(self):
        from test_sevenf_cert_request import DEPUTY_CSR_DER

        seed = self.seed_fixture()
        csr_scan = sevenf_views.SevenFScanDeputyCsrView(**self._scan_root_cert(seed, 1).view_args)

        class _Decoder:
            def get_sevenf_bbqr_data(self):
                return DEPUTY_CSR_DER

        csr_scan.decoder = _Decoder()
        root_cert = cert_request.parse_root_certificate_der(INDEX_1_ROOT_CERT_DER)
        self.controller.sevenf_confirmed_clock = ConfirmedClock(utc=root_cert.not_before + 86400, monotonic=time.monotonic())
        review = csr_scan._handle_complete_scan()
        assert review.view_args["review_fields"][0].value == "index 1\nroot/testnet/1/\nml-dsa/v1"

        signed = _run(sevenf_views.SevenFConfirmSignRootCertView(**review.view_args["confirmed_view_args"]), 0)
        certificate = signed.view_args["certificate"]
        # assemble_deputy_cert_der verifies the signature against the ISSUER's
        # key, read from sf-wallet-gov's own index-1 certificate.
        cert_request.assemble_deputy_cert_der(certificate.tbs_bytes, certificate.signature, INDEX_1_ROOT_CERT_DER)



class TestConfigSigningAtAnIndex(_IndexFlowTest):
    def test_genesis_signed_with_the_root_key_at_index_2(self):
        seed = self.seed_fixture()
        start = sevenf_views.SevenFGenesisReviewStartView(seed=seed, canonical_bytes=_sample_canonical_bytes(), key_index=2)
        state = start.state
        assert state.review_fields[0].value == "index 2\nroot/testnet/2/\nml-dsa/v1"

        captured = {}
        signed = _run(sevenf_views.SevenFConfirmSignView(state=state), 0, captured)
        assert captured["subject_key_id"].endswith("\nindex 2")
        assert ski(signed.view_args["state"].public_key.hex()) == ROOT_SKI[2]


    def test_devfund_config_signed_with_the_root_key_not_the_devfund_key(self):
        """ sf-wallet-gov sign-devfund --index N signs as Role::Root. """
        seed = self.seed_fixture()
        view = sevenf_views.SevenFConfirmSignDevFundView(
            seed=seed, chain_kind=ChainKind.TESTNET, tbs_bytes=_sample_devfund_canonical_bytes(), key_index=2)
        captured = {}
        signed = _run(view, 0, captured)
        assert captured["signing_role_label"] == "Root key"
        assert captured["subject_key_id"].endswith("\nindex 2")
        public_key = signed.view_args["artifact"].public_key
        assert ski(public_key.hex()) == ROOT_SKI[2]
        assert ski(public_key.hex()) != DEVFUND_SKI[2]


    def test_devfund_config_scan_asks_for_the_root_index(self):
        from test_sevenf_views import _load_genesis_config_into_decoder, _sample_devfund_json
        view = sevenf_views.SevenFScanDevFundConfigView(seed=self.seed_fixture())
        _load_genesis_config_into_decoder(_sample_devfund_json())(view)
        destination = view._handle_complete_scan()
        assert destination.View_cls == sevenf_views.SevenFSelectKeyIndexView
        assert destination.view_args["role"] == "root"



class TestSigningKeyMustBeTheKeyShown(_IndexFlowTest):
    """ H1 of the plan review: if the signer ever used another key than the
        one confirmed on screen, nothing is exported. """
    @pytest.mark.parametrize("make_view,sign_name", [
        (lambda seed: sevenf_views.SevenFConfirmSignRootCertView(
            seed=seed, chain_kind=ChainKind.TESTNET, tbs_bytes=b"x", key_index=2), "sign_with_root_ca"),
        (lambda seed: sevenf_views.SevenFConfirmSignDevFundView(
            seed=seed, chain_kind=ChainKind.TESTNET, tbs_bytes=b"x", key_index=2), "sign_with_devfund"),
        (lambda seed: sevenf_views.SevenFConfirmSignView(state=sevenf_views.SevenFGenesisCeremonyState(
            seed=seed, chain_kind=ChainKind.TESTNET, canonical_bytes=b"x", review_fields=[], key_index=2)),
         "sign_with_root_ca"),
    ])
    def test_a_different_signing_key_is_refused(self, make_view, sign_name):
        view = make_view(self.seed_fixture())
        index_0_key = root_ceremony.derive_root_ceremony_keys(_seed_of(view).seed_bytes, ChainKind.TESTNET, index=0).root_ca.public_key

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(root_ceremony, sign_name, lambda *a, **kw: (index_0_key, b"sig"))
            destination = _run(view, 0)

        assert destination.View_cls == sevenf_views.SevenFUnsupportedArtefactView
        assert destination.view_args["headline"] == "Key Mismatch"



class TestBackFromAfterTheIndex(_IndexFlowTest):
    """ Back from the screen after the index returns to the screen before
        the index, whichever way the index was chosen: none of the index
        screens stays on the real controller's back stack. """
    def _back_stack_at_fingerprint(self, index_steps):
        from base import FlowStep
        from seedsigner.gui.screens.screen import ButtonOption
        self.controller.active_chain_id = "sevenf"
        captured = {}
        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF_EXPORT_ROOT_VK),
                FlowStep(sevenf_views.SevenFSelectChainKindForRootEnrollmentView, button_data_selection=ButtonOption("testnet")),
                *index_steps,
                FlowStep(sevenf_views.SevenFDeriveEnrollmentVkView, is_redirect=True),
                FlowStep(sevenf_views.SevenFRootVkFingerprintView, screen_return_value=0,
                         before_run=lambda v: captured.update(stack=[d.View_cls for d in self.controller.back_stack])),
                FlowStep(sevenf_views.SevenFVkPinView),
            ],
            initial_destination_view_args=dict(seed=self.seed_fixture()),
        )
        stack = captured["stack"]
        # The current screen is on top; Back goes to the one under it.
        assert stack[-1] is sevenf_views.SevenFRootVkFingerprintView
        return stack[:-1]


    def test_default_index(self):
        from base import FlowStep
        stack = self._back_stack_at_fingerprint([FlowStep(sevenf_views.SevenFSelectKeyIndexView, screen_return_value=0)])
        assert stack[-1] is sevenf_views.SevenFSelectChainKindForRootEnrollmentView


    def test_other_index_through_the_keypad_and_warning(self):
        from base import FlowStep
        stack = self._back_stack_at_fingerprint([
            FlowStep(sevenf_views.SevenFSelectKeyIndexView, screen_return_value=1),  # "Other index"
            FlowStep(sevenf_views.SevenFEnterKeyIndexView, screen_return_value="5"),
            FlowStep(sevenf_views.SevenFConfirmKeyIndexView, screen_return_value=0),  # "Use index 5"
        ])
        assert stack[-1] is sevenf_views.SevenFSelectChainKindForRootEnrollmentView
        index_views = {sevenf_views.SevenFSelectKeyIndexView, sevenf_views.SevenFEnterKeyIndexView,
                       sevenf_views.SevenFConfirmKeyIndexView, sevenf_views.SevenFInvalidKeyIndexView}
        assert not index_views & set(stack)
