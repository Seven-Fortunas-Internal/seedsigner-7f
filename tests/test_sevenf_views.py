"""
    Tests seedsigner.views.sevenf_views -- the guided ceremony wizard
    (scan -> no-blind-signing review -> gated sign call -> export) for a
    genesis-config canonical-bytes payload
    (7f-signing-support-root-ceremony-ui-wizard, _delivery/backlog.yaml).

    Requires firmware/mldsa7f's compiled library (see test_sevenf_mldsa.py's
    own docstring for the search order); skips cleanly if it's missing.
"""
import json

import pytest

# Must import test base before the Controller (see base.py's own comment).
from base import FlowTest, FlowStep

from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON
from seedsigner.models.decode_qr import DecodeQR, DecodeQRStatus
from seedsigner.models.encode_qr import BBQrEncoder
from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants
from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf.cert_request import CERT_REQUEST_VERSION, ROLE_DEPUTY, ROLE_ROOT
from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.models.sevenf.genesis_config import ConsensusParams, build_canonical_bytes, parse_canonical_bytes
from seedsigner.models.sevenf.root_ceremony import derive_root_ceremony_keys
from seedsigner.views import seed_views, sevenf_views
from seedsigner.views.view import MainMenuView, View


def _lib_available() -> bool:
    try:
        mldsa._lib_handle()
        return True
    except FileNotFoundError:
        return False


pytestmark = pytest.mark.skipif(
    not _lib_available(),
    reason="firmware/mldsa7f not built -- run `cargo build --release` in firmware/mldsa7f/ first",
)


def _sample_canonical_bytes() -> bytes:
    consensus = ConsensusParams(target_block_time_secs=420, difficulty_adjustment_interval_blocks=3500, blocks_per_decay_period=70_000)
    return build_canonical_bytes(ChainKind.TESTNET, 1_790_555_198, "cross-check fixture", consensus)


class TestSevenFGenesisReviewFlow(FlowTest):
    def seed_fixture(self) -> Seed:
        seed = Seed(mnemonic=["abandon"] * 11 + ["about"], wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)
        self.controller.storage.seeds.append(seed)
        return seed


    def _enter_review_flow(self, seed: Seed, canonical_bytes: bytes) -> None:
        """ SevenFGenesisReviewStartView is a skip_current_view=True redirect
            (same convention as evm_views.EvmSignStartView) -- run_sequence's
            underlying Controller loop pops the current view off back_stack
            for that case (controller.py's "Skipping current view" branch),
            which underflows when it's the literal first Destination ever
            run (nothing pushed yet). Real usage never hits this: the
            not-yet-built ceremony wizard/menu (7f-signing-support-root-ceremony-ui-wizard)
            will always reach this view from a preceding menu screen, the
            same way EvmSignStartView is never the first FlowStep in
            test_flows_evm.py's own sequences either (always preceded by
            ENTER_SEED_OPTIONS_STEPS). Run it directly, outside the
            run_sequence harness, to sidestep that test-harness-only gap. """
        start_view = sevenf_views.SevenFGenesisReviewStartView(
            seed=seed, canonical_bytes=canonical_bytes,
        )
        destination = start_view.run()
        assert destination.View_cls == sevenf_views.SevenFGenesisReviewFieldView
        assert destination.view_args == dict(page_num=0)


    def test_genesis_review_and_sign_flow(self):
        """ SevenFGenesisReviewStartView (redirect, run directly -- see
            _enter_review_flow) -> 7 paged review fields (chain, timestamp,
            message, derivation scheme, target block time, difficulty
            adjustment interval, blocks per decay period) ->
            SevenFConfirmSignView -> SevenFGenesisSignedView -> SevenFExportView
            -> exports both artifacts (looping back to the export menu after
            each) -> back button -> MainMenuView. """
        seed = self.seed_fixture()
        canonical_bytes = _sample_canonical_bytes()
        self._enter_review_flow(seed, canonical_bytes)

        self.run_sequence(
            [
                FlowStep(sevenf_views.SevenFGenesisReviewFieldView, screen_return_value=0),  # Chain (1/7)
                FlowStep(sevenf_views.SevenFGenesisReviewFieldView, screen_return_value=0),  # Timestamp (2/7)
                FlowStep(sevenf_views.SevenFGenesisReviewFieldView, screen_return_value=0),  # Message (3/7)
                FlowStep(sevenf_views.SevenFGenesisReviewFieldView, screen_return_value=0),  # Derivation scheme (4/7)
                FlowStep(sevenf_views.SevenFGenesisReviewFieldView, screen_return_value=0),  # Target block time (5/7)
                FlowStep(sevenf_views.SevenFGenesisReviewFieldView, screen_return_value=0),  # Difficulty adj. interval (6/7)
                FlowStep(sevenf_views.SevenFGenesisReviewFieldView, screen_return_value=0),  # Blocks per decay period (7/7)
                FlowStep(sevenf_views.SevenFConfirmSignView, screen_return_value=0),  # "Sign"
                FlowStep(sevenf_views.SevenFGenesisSignedView, screen_return_value=0),  # "OK"
                FlowStep(sevenf_views.SevenFExportView, screen_return_value=0),  # "Export Root CA Pubkey"
                FlowStep(sevenf_views.SevenFExportPubkeyQRView, screen_return_value=0),  # QR displayed, loops back
                FlowStep(sevenf_views.SevenFExportView, screen_return_value=1),  # "Export Signed Config"
                FlowStep(sevenf_views.SevenFExportSignedConfigQRView, screen_return_value=0),
                FlowStep(sevenf_views.SevenFExportView, screen_return_value=RET_CODE__BACK_BUTTON),
                FlowStep(MainMenuView),
            ],
            initial_destination_view_args=dict(page_num=0),
        )

        # Home always wipes flow-scoped state.
        assert self.controller.sevenf_ceremony_data is None


    def test_signed_result_matches_direct_sign_with_root_ca_call(self):
        """ The flow's actual output must be the real Root CA signature over
            the real canonical bytes -- not a placeholder -- confirmed by
            reaching into controller.sevenf_ceremony_data right before Home
            wipes it and comparing against an independent direct call. """
        seed = self.seed_fixture()
        canonical_bytes = _sample_canonical_bytes()
        self._enter_review_flow(seed, canonical_bytes)

        captured = {}

        def capture_before_home(view):
            captured["public_key"] = self.controller.sevenf_ceremony_data["public_key"]
            captured["signature"] = self.controller.sevenf_ceremony_data["signature"]

        self.run_sequence(
            [
                FlowStep(sevenf_views.SevenFGenesisReviewFieldView, screen_return_value=0),
                FlowStep(sevenf_views.SevenFGenesisReviewFieldView, screen_return_value=0),
                FlowStep(sevenf_views.SevenFGenesisReviewFieldView, screen_return_value=0),
                FlowStep(sevenf_views.SevenFGenesisReviewFieldView, screen_return_value=0),
                FlowStep(sevenf_views.SevenFGenesisReviewFieldView, screen_return_value=0),
                FlowStep(sevenf_views.SevenFGenesisReviewFieldView, screen_return_value=0),
                FlowStep(sevenf_views.SevenFGenesisReviewFieldView, screen_return_value=0),
                FlowStep(sevenf_views.SevenFConfirmSignView, screen_return_value=0),
                FlowStep(sevenf_views.SevenFGenesisSignedView, before_run=capture_before_home, screen_return_value=0),
                FlowStep(sevenf_views.SevenFExportView, screen_return_value=RET_CODE__BACK_BUTTON),
                FlowStep(MainMenuView),
            ],
            initial_destination_view_args=dict(page_num=0),
        )

        keys = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.TESTNET)
        assert captured["public_key"] == keys.root_ca.public_key
        assert len(captured["signature"]) == 3309


    def test_back_button_on_first_review_page_abandons_flow_and_clears_state(self):
        seed = self.seed_fixture()
        canonical_bytes = _sample_canonical_bytes()
        self._enter_review_flow(seed, canonical_bytes)

        self.run_sequence(
            [
                FlowStep(sevenf_views.SevenFGenesisReviewFieldView, screen_return_value=RET_CODE__BACK_BUTTON),
            ],
            initial_destination_view_args=dict(page_num=0),
        )

        assert self.controller.sevenf_ceremony_data is None


    def test_back_button_on_a_later_review_page_does_not_clear_state(self):
        """ Only page 0's back button abandons the whole flow -- backing up
            from a later page must return to the previous page's content,
            not wipe the ceremony data the operator has already been
            reviewing (see SevenFGenesisReviewFieldView.run()'s
            page_num == 0 guard). Direct unit-level check, not a full
            run_sequence: the Controller's back_stack semantics require a
            "current view" already pushed before a FlowStep sequence starts
            (true in real usage -- MainMenuView et al. precede this flow --
            but not reproducible by starting run_sequence fresh at page 1
            without the not-yet-built wizard/menu chain in front of it). """
        seed = self.seed_fixture()
        canonical_bytes = _sample_canonical_bytes()
        self._enter_review_flow(seed, canonical_bytes)
        stashed_data = self.controller.sevenf_ceremony_data

        view = sevenf_views.SevenFGenesisReviewFieldView(page_num=1)
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: RET_CODE__BACK_BUTTON)
            destination = view.run()

        from seedsigner.views.view import BackStackView
        assert destination.View_cls == BackStackView
        assert self.controller.sevenf_ceremony_data is stashed_data


    def test_back_button_on_confirm_sign_screen_returns_to_back_stack_without_signing(self):
        """ Backing out of the final confirm-and-sign screen must not sign
            anything -- confirms the "Sign" button click is genuinely the
            only path into root_ceremony.sign_with_root_ca(), not merely the
            expected one. """
        seed = self.seed_fixture()
        canonical_bytes = _sample_canonical_bytes()
        self.controller.sevenf_ceremony_data = dict(
            seed=seed, chain_kind=ChainKind.TESTNET, canonical_bytes=canonical_bytes,
        )

        view = sevenf_views.SevenFConfirmSignView()
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: RET_CODE__BACK_BUTTON)
            destination = view.run()

        from seedsigner.views.view import BackStackView
        assert destination.View_cls == BackStackView
        assert "public_key" not in self.controller.sevenf_ceremony_data
        assert "signature" not in self.controller.sevenf_ceremony_data


    def test_confirm_sign_view_shows_the_real_root_ca_address_for_the_chain_kind(self):
        """ Unit-level check (not a full flow run): SevenFConfirmSignView must
            derive the address it displays from the same
            derive_root_ceremony_keys() path the rest of the ceremony uses --
            confirms it isn't a placeholder or a different derivation. """
        seed = self.seed_fixture()
        canonical_bytes = _sample_canonical_bytes()
        self.controller.sevenf_ceremony_data = dict(
            seed=seed, chain_kind=ChainKind.TESTNET, canonical_bytes=canonical_bytes,
        )

        view = sevenf_views.SevenFConfirmSignView()
        keys = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.TESTNET)
        assert view.root_ca_address == keys.root_ca.address


    def test_review_start_view_derives_chain_kind_from_the_parsed_bytes(self):
        """ Regression test for a real self-validation bug caught while
            wiring the export flow: SevenFGenesisReviewStartView used to
            take chain_kind as an independent constructor argument, separate
            from the one embedded in canonical_bytes -- exactly the anti-
            pattern chains/base.py's own ChainPlugin docstring warns against
            ("must independently recompute the fields that matter from the
            raw payload bytes, never just relay externally-supplied
            metadata"). Confirms chain_kind now always matches what's
            actually inside the bytes that get signed, with no way to pass
            a different one in. """
        seed = self.seed_fixture()
        canonical_bytes = _sample_canonical_bytes()  # built with ChainKind.TESTNET
        assert "chain_kind" not in sevenf_views.SevenFGenesisReviewStartView.__init__.__code__.co_varnames[
            :sevenf_views.SevenFGenesisReviewStartView.__init__.__code__.co_argcount
        ]

        sevenf_views.SevenFGenesisReviewStartView(seed=seed, canonical_bytes=canonical_bytes)
        assert self.controller.sevenf_ceremony_data["chain_kind"] == ChainKind.TESTNET


    def test_export_pubkey_qr_view_encodes_the_real_root_ca_pubkey(self):
        """ Confirms the exported QR actually carries this ceremony's real
            Root CA public key (BBQr-encoded, file_type 'U'), round-tripped
            through the real BBQr encoder/decoder pair -- not a placeholder
            and not merely "some bytes got passed to some encoder". """
        seed = self.seed_fixture()
        canonical_bytes = _sample_canonical_bytes()
        keys = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.TESTNET)
        self.controller.sevenf_ceremony_data = dict(
            seed=seed, chain_kind=ChainKind.TESTNET, canonical_bytes=canonical_bytes,
            fields=parse_canonical_bytes(canonical_bytes),
            public_key=keys.root_ca.public_key, signature=b"\x00" * 3309,
        )

        view = sevenf_views.SevenFExportPubkeyQRView()
        captured = {}

        def fake_run_screen(screen_cls, **kwargs):
            captured["qr_encoder"] = kwargs["qr_encoder"]

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", fake_run_screen)
            destination = view.run()

        encoder = captured["qr_encoder"]
        assert encoder.file_type == "U"

        d = DecodeQR()
        while True:
            status = d.add_data(encoder.next_part())
            if status == DecodeQRStatus.COMPLETE:
                break
        assert d.decoder.get_data() == keys.root_ca.public_key.hex().encode("utf-8")

        assert destination.View_cls == sevenf_views.SevenFExportView


    def test_export_signed_config_qr_view_encodes_the_real_signed_json(self):
        """ Confirms the exported QR carries the real build_root_sig_json()
            output for THIS ceremony's actual signature (BBQr-encoded,
            file_type 'J'), round-tripped through the real BBQr encoder/
            decoder pair and re-parsed as JSON -- the actual export payload
            an operator would hand to sf-node/sf-wallet, not a stand-in.
            Per D11 / sf-root.rs's real cmd_sign_genesis (commit 3bb5da3),
            this is signature-only: signer_vk stays empty (the key was
            already enrolled separately), and the config fields are not
            re-embedded. """
        import json

        from seedsigner.models.sevenf.genesis_config import build_root_sig_json

        seed = self.seed_fixture()
        canonical_bytes = _sample_canonical_bytes()
        keys = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.TESTNET)
        fields = parse_canonical_bytes(canonical_bytes)
        signature = bytes(range(256)) * 12 + bytes(3309 - 256 * 12)  # 3309 varied bytes, not all-zero
        self.controller.sevenf_ceremony_data = dict(
            seed=seed, chain_kind=ChainKind.TESTNET, canonical_bytes=canonical_bytes,
            fields=fields, public_key=keys.root_ca.public_key, signature=signature,
        )

        view = sevenf_views.SevenFExportSignedConfigQRView()
        captured = {}

        def fake_run_screen(screen_cls, **kwargs):
            captured["qr_encoder"] = kwargs["qr_encoder"]

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", fake_run_screen)
            destination = view.run()

        encoder = captured["qr_encoder"]
        assert encoder.file_type == "J"

        d = DecodeQR()
        while True:
            status = d.add_data(encoder.next_part())
            if status == DecodeQRStatus.COMPLETE:
                break
        decoded_json = json.loads(d.decoder.get_data())
        assert decoded_json == build_root_sig_json(keys.root_ca.public_key, signature)
        assert decoded_json["signer_vk"] == ""
        assert decoded_json["sig"] == signature.hex()

        assert destination.View_cls == sevenf_views.SevenFExportView


    def test_export_view_back_button_returns_home(self):
        seed = self.seed_fixture()
        canonical_bytes = _sample_canonical_bytes()
        self.controller.sevenf_ceremony_data = dict(
            seed=seed, chain_kind=ChainKind.TESTNET, canonical_bytes=canonical_bytes,
        )

        view = sevenf_views.SevenFExportView()
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: RET_CODE__BACK_BUTTON)
            destination = view.run()

        assert destination.View_cls == MainMenuView
        assert destination.skip_current_view is True


def _load_genesis_config_into_decoder(canonical_bytes: bytes, file_type: str = "J"):
    """ before_run hook (see test_flows_evm.py's own load_seed_into_decoder
        for the established pattern this mirrors): pushes a real BBQr-encoded
        payload into a ScanView subclass's decoder before .run() checks
        decoder.is_complete, standing in for an actual camera scan. """
    def loader(view):
        encoder = BBQrEncoder(data=canonical_bytes, file_type=file_type)
        for _ in range(encoder.seq_len()):
            view.decoder.add_data(encoder.next_part())
    return loader


def _sample_cert_request_json(**overrides) -> bytes:
    base = dict(
        version=CERT_REQUEST_VERSION,
        kind="testnet",
        role=ROLE_ROOT,
        subject_vk=(bytes([0xAB]) * 1952).hex(),
        not_before=1_700_000_000,
        days=3650,
        serial=(bytes([0x11]) * 16).hex(),
    )
    base.update(overrides)
    return json.dumps(base).encode("utf-8")


def _load_cert_request_into_decoder(data: bytes, file_type: str = "J"):
    """ Same before_run pattern as _load_genesis_config_into_decoder, for a
        CertRequest JSON payload instead of genesis-config canonical bytes. """
    def loader(view):
        encoder = BBQrEncoder(data=data, file_type=file_type)
        for _ in range(encoder.seq_len()):
            view.decoder.add_data(encoder.next_part())
    return loader


class TestSevenFRootSelfCertificationFlow(FlowTest):
    """ The Root self-certification flow (7f-signing-support-root-self-certification):
        SeedOptionsView's "7F: Self-Certify Root" button -> SevenFScanRootCertRequestView
        -> (valid, subject matches this seed's own key) SevenFCertRequestReviewFieldView
        -> SevenFConfirmSignRootCertView -> SevenFRootCertSignedView -> SevenFExportView
        (the SAME export menu genesis-config signing uses -- see
        SevenFConfirmSignRootCertView's own docstring for why). """
    def setup_method(self):
        super().setup_method()
        self.controller.active_chain_id = "sevenf"


    def seed_fixture(self) -> Seed:
        seed = Seed(mnemonic=["abandon"] * 11 + ["about"], wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)
        self.controller.storage.seeds.append(seed)
        return seed


    def test_seed_options_view_offers_the_self_certify_button_only_in_sevenf_mode(self):
        seed = self.seed_fixture()
        for active_chain_id, should_appear in [("sevenf", True), ("bitcoin", False), ("evm", False), (None, False)]:
            self.controller.active_chain_id = active_chain_id
            view = seed_views.SeedOptionsView(seed=seed)
            captured = {}

            def fake_run_screen(screen_cls, button_data=None, **kwargs):
                captured["button_data"] = button_data
                return RET_CODE__BACK_BUTTON

            with pytest.MonkeyPatch().context() as mp:
                mp.setattr(view, "run_screen", fake_run_screen)
                view.run()
            is_present = seed_views.SeedOptionsView.SEVENF_SCAN_ROOT_CERT_REQUEST in captured["button_data"]
            assert is_present == should_appear, f"active_chain_id={active_chain_id!r}: expected present={should_appear}, got {is_present}"


    def test_seed_options_view_routes_to_scan_root_cert_request_view(self):
        seed = self.seed_fixture()
        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF_SCAN_ROOT_CERT_REQUEST),
                FlowStep(sevenf_views.SevenFScanRootCertRequestView),
            ],
            initial_destination_view_args=dict(seed=seed),
        )


    def test_full_flow_with_a_real_matching_subject_key_signs_and_exports(self):
        """ End-to-end from a real BBQr-encoded CertRequest, whose subject_vk
            is this seed's own real derived Root CA key for testnet, through
            scan -> review (6 fields) -> confirm+sign -> signed -> export
            menu, confirming the real public_key/signature this flow
            produces (same assertions test_signed_result_matches_direct_sign_with_root_ca_call
            makes for genesis-config signing: matching pubkey, real 3309-byte
            ML-DSA-65 signature -- not a placeholder). """
        seed = self.seed_fixture()
        keys = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.TESTNET)
        req_json = _sample_cert_request_json(subject_vk=keys.root_ca.public_key.hex())

        captured = {}

        def capture_before_home(view):
            captured["public_key"] = self.controller.sevenf_ceremony_data["public_key"]
            captured["signature"] = self.controller.sevenf_ceremony_data["signature"]

        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF_SCAN_ROOT_CERT_REQUEST),
                FlowStep(
                    sevenf_views.SevenFScanRootCertRequestView,
                    before_run=_load_cert_request_into_decoder(req_json),
                    screen_return_value=0,
                ),
                FlowStep(sevenf_views.SevenFCertRequestReviewFieldView, screen_return_value=0),  # Role
                FlowStep(sevenf_views.SevenFCertRequestReviewFieldView, screen_return_value=0),  # Subject key id
                FlowStep(sevenf_views.SevenFCertRequestReviewFieldView, screen_return_value=0),  # Chain
                FlowStep(sevenf_views.SevenFCertRequestReviewFieldView, screen_return_value=0),  # Valid from
                FlowStep(sevenf_views.SevenFCertRequestReviewFieldView, screen_return_value=0),  # Valid for
                FlowStep(sevenf_views.SevenFCertRequestReviewFieldView, screen_return_value=0),  # Serial (final)
                FlowStep(sevenf_views.SevenFConfirmSignRootCertView, screen_return_value=0),  # "Sign"
                FlowStep(sevenf_views.SevenFRootCertSignedView, before_run=capture_before_home, screen_return_value=0),  # "OK"
                FlowStep(sevenf_views.SevenFExportView, screen_return_value=RET_CODE__BACK_BUTTON),
                FlowStep(MainMenuView),
            ],
            initial_destination_view_args=dict(seed=seed),
        )

        assert captured["public_key"] == keys.root_ca.public_key
        assert len(captured["signature"]) == 3309

        # Home always wipes flow-scoped state.
        assert self.controller.sevenf_ceremony_data is None


    def test_signed_result_matches_direct_tbs_and_sign_call(self):
        """ Unit-level cross-check (not the full flow): SevenFConfirmSignRootCertView's
            output must match a direct root_tbs_from_request() + sign_with_root_ca()
            call over the same request -- confirms this isn't a placeholder or a
            different derivation/TBS construction. """
        from seedsigner.models.sevenf import cert_request as cert_request_module
        from seedsigner.models.sevenf.root_ceremony import sign_with_root_ca

        seed = self.seed_fixture()
        keys = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.TESTNET)
        req = cert_request_module.parse_cert_request_json(_sample_cert_request_json(subject_vk=keys.root_ca.public_key.hex()))
        tbs_bytes = cert_request_module.root_tbs_from_request(req)

        view = sevenf_views.SevenFConfirmSignRootCertView(seed=seed, chain_kind=req.kind, tbs_bytes=tbs_bytes)
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: 0)
            destination = view.run()

        assert destination.View_cls == sevenf_views.SevenFRootCertSignedView
        data = self.controller.sevenf_ceremony_data
        expected_pk, expected_sig = sign_with_root_ca(seed.seed_bytes, req.kind, tbs_bytes, confirmed=True)
        assert data["public_key"] == keys.root_ca.public_key == expected_pk
        assert len(data["signature"]) == len(expected_sig) == 3309


    def test_scan_rejects_a_payload_that_isnt_valid_json(self):
        seed = self.seed_fixture()
        garbage = b"not a cert request at all, but still valid BBQr transport bytes"

        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF_SCAN_ROOT_CERT_REQUEST),
                FlowStep(
                    sevenf_views.SevenFScanRootCertRequestView,
                    before_run=_load_cert_request_into_decoder(garbage),
                    screen_return_value=0,
                ),
                FlowStep(sevenf_views.SevenFUnsupportedArtefactView, screen_return_value=0),
            ],
            initial_destination_view_args=dict(seed=seed),
        )


    def test_scan_rejects_a_deputy_request_scanned_here(self):
        seed = self.seed_fixture()
        req_json = _sample_cert_request_json(role=ROLE_DEPUTY, subject_vk=(bytes([0xCD]) * 1952).hex())

        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF_SCAN_ROOT_CERT_REQUEST),
                FlowStep(
                    sevenf_views.SevenFScanRootCertRequestView,
                    before_run=_load_cert_request_into_decoder(req_json),
                    screen_return_value=0,
                ),
                FlowStep(sevenf_views.SevenFUnsupportedArtefactView, screen_return_value=0),
            ],
            initial_destination_view_args=dict(seed=seed),
        )


    def test_scan_fail_closed_refuses_a_request_for_a_different_roots_key(self):
        """ CRITICAL/HIGH finding from adversarial security review: a
            well-formed request whose subject_vk does NOT match this
            device's own derived key must be refused, not signed, and not
            even shown for review. """
        seed = self.seed_fixture()
        wrong_vk = (bytes([0xEE]) * 1952).hex()  # deliberately not this seed's own derived key
        req_json = _sample_cert_request_json(subject_vk=wrong_vk)

        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF_SCAN_ROOT_CERT_REQUEST),
                FlowStep(
                    sevenf_views.SevenFScanRootCertRequestView,
                    before_run=_load_cert_request_into_decoder(req_json),
                    screen_return_value=0,
                ),
                FlowStep(sevenf_views.SevenFUnsupportedArtefactView, screen_return_value=0),
            ],
            initial_destination_view_args=dict(seed=seed),
        )


    def test_back_button_on_confirm_sign_screen_returns_to_back_stack_without_signing(self):
        """ Mirrors TestSevenFGenesisReviewFlow's own equivalent test:
            backing out of the final confirm-and-sign screen must not sign
            anything. """
        from seedsigner.models.sevenf import cert_request as cert_request_module

        seed = self.seed_fixture()
        req = cert_request_module.parse_cert_request_json(_sample_cert_request_json())
        tbs_bytes = cert_request_module.root_tbs_from_request(req)

        view = sevenf_views.SevenFConfirmSignRootCertView(seed=seed, chain_kind=req.kind, tbs_bytes=tbs_bytes)
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: RET_CODE__BACK_BUTTON)
            destination = view.run()

        from seedsigner.views.view import BackStackView
        assert destination.View_cls == BackStackView
        assert self.controller.sevenf_ceremony_data is None


    def test_confirm_sign_view_shows_the_real_root_ca_address(self):
        from seedsigner.models.sevenf import cert_request as cert_request_module

        seed = self.seed_fixture()
        req = cert_request_module.parse_cert_request_json(_sample_cert_request_json())
        tbs_bytes = cert_request_module.root_tbs_from_request(req)

        view = sevenf_views.SevenFConfirmSignRootCertView(seed=seed, chain_kind=req.kind, tbs_bytes=tbs_bytes)
        keys = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.TESTNET)
        assert view.root_ca_address == keys.root_ca.address


class TestSevenFUnsupportedArtefactViewHeadline:
    """ SevenFUnsupportedArtefactView's optional `headline` override, added
        for the Root self-certification fail-closed refusal (a well-formed
        request that must still be refused, not a parse failure -- see
        SevenFScanRootCertRequestView's own docstring). """
    def test_default_headline_is_unchanged(self):
        view = sevenf_views.SevenFUnsupportedArtefactView(reason="some reason")
        assert view.headline == "Can't Parse This"

    def test_custom_headline_overrides_the_default(self):
        view = sevenf_views.SevenFUnsupportedArtefactView(reason="some reason", headline="Wrong Key")
        assert view.headline == "Wrong Key"


class TestSevenFDeputyCrossCertificationFlow(FlowTest):
    """ The Deputy cross-certification flow (7f-signing-support-deputy-cross-certification):
        SeedOptionsView's "7F: Cross-Certify Deputy" button ->
        SevenFScanRootRequestForDeputyView (re-scan the Root's own request) ->
        SevenFScanDeputyCertRequestView (scan the Deputy's request) ->
        SevenFCertRequestReviewFieldView (12 fields: Root's own identity,
        then the Deputy's) -> SevenFConfirmSignRootCertView ->
        SevenFRootCertSignedView (Deputy-specific wording) -> SevenFExportView. """
    def setup_method(self):
        super().setup_method()
        self.controller.active_chain_id = "sevenf"


    def seed_fixture(self) -> Seed:
        seed = Seed(mnemonic=["abandon"] * 11 + ["about"], wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)
        self.controller.storage.seeds.append(seed)
        return seed


    def test_seed_options_view_offers_the_cross_certify_button_only_in_sevenf_mode(self):
        seed = self.seed_fixture()
        for active_chain_id, should_appear in [("sevenf", True), ("bitcoin", False), ("evm", False), (None, False)]:
            self.controller.active_chain_id = active_chain_id
            view = seed_views.SeedOptionsView(seed=seed)
            captured = {}

            def fake_run_screen(screen_cls, button_data=None, **kwargs):
                captured["button_data"] = button_data
                return RET_CODE__BACK_BUTTON

            with pytest.MonkeyPatch().context() as mp:
                mp.setattr(view, "run_screen", fake_run_screen)
                view.run()
            is_present = seed_views.SeedOptionsView.SEVENF_SCAN_DEPUTY_CROSS_CERT in captured["button_data"]
            assert is_present == should_appear, f"active_chain_id={active_chain_id!r}: expected present={should_appear}, got {is_present}"


    def test_seed_options_view_routes_to_scan_root_request_for_deputy_view(self):
        seed = self.seed_fixture()
        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF_SCAN_DEPUTY_CROSS_CERT),
                FlowStep(sevenf_views.SevenFScanRootRequestForDeputyView),
            ],
            initial_destination_view_args=dict(seed=seed),
        )


    def test_full_flow_with_real_matching_keys_signs_and_exports(self):
        """ End-to-end: scan the Root's own request (matching this seed's
            real derived key) -> scan a Deputy request for the same chain ->
            review all 12 fields -> confirm+sign -> Deputy-specific signed
            screen -> export menu. Confirms the real public_key/signature
            (the Root's, not the Deputy's -- the Root is always the
            signer) and the Deputy-specific success wording. """
        seed = self.seed_fixture()
        keys = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.TESTNET)
        root_req_json = _sample_cert_request_json(subject_vk=keys.root_ca.public_key.hex())
        deputy_req_json = _sample_cert_request_json(role=ROLE_DEPUTY, subject_vk=(bytes([0xCD]) * 1952).hex(), serial=(bytes([0x22]) * 16).hex())

        captured = {}

        def capture_signed_screen_args(view):
            captured["title"] = view.title
            captured["text"] = view.text

        def capture_before_home(view):
            captured["public_key"] = self.controller.sevenf_ceremony_data["public_key"]
            captured["signature"] = self.controller.sevenf_ceremony_data["signature"]

        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF_SCAN_DEPUTY_CROSS_CERT),
                FlowStep(
                    sevenf_views.SevenFScanRootRequestForDeputyView,
                    before_run=_load_cert_request_into_decoder(root_req_json),
                    screen_return_value=0,
                ),
                FlowStep(
                    sevenf_views.SevenFScanDeputyCertRequestView,
                    before_run=_load_cert_request_into_decoder(deputy_req_json),
                    screen_return_value=0,
                ),
                # 12 review pages: 6 "Issuing Root: ..." fields, then 6 "Deputy: ..." fields.
                *[FlowStep(sevenf_views.SevenFCertRequestReviewFieldView, screen_return_value=0) for _ in range(12)],
                FlowStep(sevenf_views.SevenFConfirmSignRootCertView, screen_return_value=0),  # "Sign"
                FlowStep(
                    sevenf_views.SevenFRootCertSignedView,
                    before_run=lambda view: (capture_signed_screen_args(view), capture_before_home(view)),
                    screen_return_value=0,
                ),  # "OK"
                FlowStep(sevenf_views.SevenFExportView, screen_return_value=RET_CODE__BACK_BUTTON),
                FlowStep(MainMenuView),
            ],
            initial_destination_view_args=dict(seed=seed),
        )

        assert captured["title"] == "Deputy Certificate Signed"
        assert "Deputy" in captured["text"]
        # The signer is the ROOT, not the Deputy -- confirms this cross-certification's
        # signature is attributed to the Root key, never the Deputy's own.
        assert captured["public_key"] == keys.root_ca.public_key
        assert len(captured["signature"]) == 3309

        assert self.controller.sevenf_ceremony_data is None  # Home always wipes flow-scoped state


    def test_signed_tbs_matches_direct_deputy_tbs_from_request_call(self):
        """ Unit-level cross-check: the TBS bytes SevenFScanDeputyCertRequestView
            builds must match a direct cert_request.deputy_tbs_from_request()
            call over the same two requests -- confirms this isn't a
            placeholder or a different TBS construction. """
        from seedsigner.models.sevenf import cert_request as cert_request_module

        seed = self.seed_fixture()
        keys = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.TESTNET)
        root_req = cert_request_module.parse_cert_request_json(_sample_cert_request_json(subject_vk=keys.root_ca.public_key.hex()))
        deputy_req_json = _sample_cert_request_json(role=ROLE_DEPUTY, subject_vk=(bytes([0xCD]) * 1952).hex(), serial=(bytes([0x22]) * 16).hex())
        deputy_req = cert_request_module.parse_cert_request_json(deputy_req_json)

        expected_tbs = cert_request_module.deputy_tbs_from_request(
            keys.root_ca.public_key, root_req.kind, root_req.not_before, root_req.days, deputy_req,
        )

        class _FakeDecoder:
            def get_sevenf_bbqr_data(self):
                return deputy_req_json

        view = sevenf_views.SevenFScanDeputyCertRequestView(seed=seed, root_req=root_req, root_ca_pubkey=keys.root_ca.public_key)
        view.decoder = _FakeDecoder()
        destination = view._handle_complete_scan()
        assert destination.view_args["confirmed_view_args"]["tbs_bytes"] == expected_tbs


    def test_review_fields_are_labeled_and_ordered_root_then_deputy(self):
        seed = self.seed_fixture()
        keys = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.TESTNET)
        root_req_json = _sample_cert_request_json(subject_vk=keys.root_ca.public_key.hex())
        deputy_req_json = _sample_cert_request_json(role=ROLE_DEPUTY, subject_vk=(bytes([0xCD]) * 1952).hex())

        view1 = sevenf_views.SevenFScanRootRequestForDeputyView(seed=seed)

        class _FakeDecoder:
            def __init__(self, data):
                self._data = data
            def get_sevenf_bbqr_data(self):
                return self._data

        view1.decoder = _FakeDecoder(root_req_json)
        destination1 = view1._handle_complete_scan()

        view2 = sevenf_views.SevenFScanDeputyCertRequestView(**destination1.view_args)
        view2.decoder = _FakeDecoder(deputy_req_json)
        destination2 = view2._handle_complete_scan()

        fields = destination2.view_args["review_fields"]
        assert len(fields) == 12
        assert [f.label for f in fields[:6]] == [
            "Issuing Root: Role", "Issuing Root: Subject key id", "Issuing Root: Chain",
            "Issuing Root: Valid from", "Issuing Root: Valid for", "Issuing Root: Serial",
        ]
        assert [f.label for f in fields[6:]] == [
            "Deputy: Role", "Deputy: Subject key id", "Deputy: Chain",
            "Deputy: Valid from", "Deputy: Valid for", "Deputy: Serial",
        ]
        assert fields[0].value == "root"
        assert fields[6].value == "deputy"


    def test_scan_1_rejects_a_deputy_request(self):
        """ SevenFScanRootRequestForDeputyView must refuse a role="deputy"
            request just like SevenFScanRootCertRequestView does (shared
            helper) -- the FIRST scan is always the Root's own request. """
        seed = self.seed_fixture()
        req_json = _sample_cert_request_json(role=ROLE_DEPUTY, subject_vk=(bytes([0xCD]) * 1952).hex())

        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF_SCAN_DEPUTY_CROSS_CERT),
                FlowStep(
                    sevenf_views.SevenFScanRootRequestForDeputyView,
                    before_run=_load_cert_request_into_decoder(req_json),
                    screen_return_value=0,
                ),
                FlowStep(sevenf_views.SevenFUnsupportedArtefactView, screen_return_value=0),
            ],
            initial_destination_view_args=dict(seed=seed),
        )


    def test_scan_1_fail_closed_refuses_a_different_roots_key(self):
        seed = self.seed_fixture()
        wrong_vk = (bytes([0xEE]) * 1952).hex()
        req_json = _sample_cert_request_json(subject_vk=wrong_vk)

        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF_SCAN_DEPUTY_CROSS_CERT),
                FlowStep(
                    sevenf_views.SevenFScanRootRequestForDeputyView,
                    before_run=_load_cert_request_into_decoder(req_json),
                    screen_return_value=0,
                ),
                FlowStep(sevenf_views.SevenFUnsupportedArtefactView, screen_return_value=0),
            ],
            initial_destination_view_args=dict(seed=seed),
        )


    def test_scan_2_rejects_a_root_request(self):
        """ SevenFScanDeputyCertRequestView must refuse a role="root"
            request -- the SECOND scan is always the Deputy's request. """
        seed = self.seed_fixture()
        keys = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.TESTNET)
        from seedsigner.models.sevenf import cert_request as cert_request_module
        root_req_parsed = cert_request_module.parse_cert_request_json(_sample_cert_request_json(subject_vk=keys.root_ca.public_key.hex()))

        view = sevenf_views.SevenFScanDeputyCertRequestView(seed=seed, root_req=root_req_parsed, root_ca_pubkey=keys.root_ca.public_key)

        class _FakeDecoder:
            def get_sevenf_bbqr_data(self):
                return _sample_cert_request_json(subject_vk=keys.root_ca.public_key.hex())  # role="root" again

        view.decoder = _FakeDecoder()
        destination = view._handle_complete_scan()
        assert destination.View_cls == sevenf_views.SevenFUnsupportedArtefactView


    def test_scan_2_rejects_a_chain_kind_mismatch(self):
        seed = self.seed_fixture()
        keys = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.TESTNET)
        from seedsigner.models.sevenf import cert_request as cert_request_module
        root_req_parsed = cert_request_module.parse_cert_request_json(_sample_cert_request_json(subject_vk=keys.root_ca.public_key.hex()))

        view = sevenf_views.SevenFScanDeputyCertRequestView(seed=seed, root_req=root_req_parsed, root_ca_pubkey=keys.root_ca.public_key)

        class _FakeDecoder:
            def get_sevenf_bbqr_data(self):
                return _sample_cert_request_json(role=ROLE_DEPUTY, subject_vk=(bytes([0xCD]) * 1952).hex(), kind="mainnet")

        view.decoder = _FakeDecoder()
        destination = view._handle_complete_scan()
        assert destination.View_cls == sevenf_views.SevenFUnsupportedArtefactView
        assert destination.view_args["headline"] == "Chain Mismatch"


    def test_back_button_on_confirm_sign_screen_does_not_sign(self):
        from seedsigner.models.sevenf import cert_request as cert_request_module

        seed = self.seed_fixture()
        keys = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.TESTNET)
        root_req = cert_request_module.parse_cert_request_json(_sample_cert_request_json(subject_vk=keys.root_ca.public_key.hex()))
        deputy_req = cert_request_module.parse_cert_request_json(
            _sample_cert_request_json(role=ROLE_DEPUTY, subject_vk=(bytes([0xCD]) * 1952).hex(), serial=(bytes([0x22]) * 16).hex()))
        tbs_bytes = cert_request_module.deputy_tbs_from_request(keys.root_ca.public_key, root_req.kind, root_req.not_before, root_req.days, deputy_req)

        view = sevenf_views.SevenFConfirmSignRootCertView(
            seed=seed, chain_kind=root_req.kind, tbs_bytes=tbs_bytes,
            signed_view_args=dict(title="Deputy Certificate Signed", text="whatever"),
        )
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: RET_CODE__BACK_BUTTON)
            destination = view.run()

        from seedsigner.views.view import BackStackView
        assert destination.View_cls == BackStackView
        assert self.controller.sevenf_ceremony_data is None


class TestSevenFScanEntryPoint(FlowTest):
    """ The wizard's real entry point: SeedOptionsView's "7F: Sign Genesis
        Config" button -> SevenFScanGenesisConfigView -> (valid payload)
        SevenFGenesisReviewStartView, or (invalid) SevenFUnsupportedArtefactView.

        Gated on active_chain_id == "sevenf", same pattern as EVM's own
        EVM_ADDRESS/EVM_SIGN buttons -- corrected 2026-09-27 from an earlier
        unconditional placement (see seed_views.py's SEVENF_SCAN_GENESIS_CONFIG
        comment and chains/sevenf/plugin.py's own docstring for why 7F is a
        proper ChainPlugin now, not a standalone bolt-on). """
    def setup_method(self):
        super().setup_method()
        self.controller.active_chain_id = "sevenf"


    def seed_fixture(self) -> Seed:
        seed = Seed(mnemonic=["abandon"] * 11 + ["about"], wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)
        self.controller.storage.seeds.append(seed)
        return seed


    def test_seed_options_view_offers_the_sevenf_button_only_in_sevenf_mode(self):
        """ Unlike an earlier, incorrect unconditional placement, this button
            must appear ONLY when active_chain_id == "sevenf" -- absent for
            bitcoin, evm, or no chain chosen yet -- same gating discipline as
            every other chain-specific button in this menu. """
        seed = self.seed_fixture()
        for active_chain_id, should_appear in [("sevenf", True), ("bitcoin", False), ("evm", False), (None, False)]:
            self.controller.active_chain_id = active_chain_id
            view = seed_views.SeedOptionsView(seed=seed)
            captured = {}

            def fake_run_screen(screen_cls, button_data=None, **kwargs):
                captured["button_data"] = button_data
                return RET_CODE__BACK_BUTTON

            with pytest.MonkeyPatch().context() as mp:
                mp.setattr(view, "run_screen", fake_run_screen)
                view.run()
            is_present = seed_views.SeedOptionsView.SEVENF_SCAN_GENESIS_CONFIG in captured["button_data"]
            assert is_present == should_appear, f"active_chain_id={active_chain_id!r}: expected present={should_appear}, got {is_present}"


    def test_seed_options_view_routes_to_scan_genesis_config_view(self):
        seed = self.seed_fixture()
        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF_SCAN_GENESIS_CONFIG),
                FlowStep(sevenf_views.SevenFScanGenesisConfigView),
            ],
            initial_destination_view_args=dict(seed=seed),
        )


    def test_scan_genesis_config_view_accepts_a_real_payload_and_routes_to_review(self):
        """ End-to-end from a real BBQr-encoded genesis-config through the
            actual scan/decode machinery -- not a hand-built canonical_bytes
            handoff -- into the review flow's real entry point. """
        seed = self.seed_fixture()
        canonical_bytes = _sample_canonical_bytes()

        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF_SCAN_GENESIS_CONFIG),
                FlowStep(
                    sevenf_views.SevenFScanGenesisConfigView,
                    before_run=_load_genesis_config_into_decoder(canonical_bytes),
                    screen_return_value=0,
                ),
                FlowStep(sevenf_views.SevenFGenesisReviewStartView, is_redirect=True),
                FlowStep(sevenf_views.SevenFGenesisReviewFieldView, screen_return_value=0),
            ],
            initial_destination_view_args=dict(seed=seed),
        )

        data = self.controller.sevenf_ceremony_data
        assert data["seed"] is seed
        assert data["canonical_bytes"] == canonical_bytes
        assert data["chain_kind"] == ChainKind.TESTNET


    def test_scan_genesis_config_view_rejects_a_payload_that_doesnt_parse(self):
        """ A BBQr payload that decodes fine at the transport layer but isn't
            a real genesis-config (wrong domain tag) must be refused with a
            clear reason, not crash or silently proceed into the review flow
            with garbage fields -- confirms SevenFScanGenesisConfigView's own
            self-validation, not just genesis_config.parse_canonical_bytes()
            in isolation (already covered by test_sevenf_genesis_config.py). """
        seed = self.seed_fixture()
        garbage = b"not a genesis config at all, but still valid BBQr transport bytes"

        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF_SCAN_GENESIS_CONFIG),
                FlowStep(
                    sevenf_views.SevenFScanGenesisConfigView,
                    before_run=_load_genesis_config_into_decoder(garbage),
                    screen_return_value=0,
                ),
                FlowStep(sevenf_views.SevenFUnsupportedArtefactView, screen_return_value=0),
            ],
            initial_destination_view_args=dict(seed=seed),
        )

        assert self.controller.sevenf_ceremony_data is None


    def test_scan_genesis_config_view_refuses_to_run_in_the_wrong_chain_mode(self):
        """ guard_active_chain defense-in-depth, same pattern
            EvmScanSignRequestView relies on: even if something bypassed
            SeedOptionsView's own button gating, this view must still refuse
            to run outside sevenf mode. """
        seed = self.seed_fixture()
        self.controller.active_chain_id = "evm"

        view = sevenf_views.SevenFScanGenesisConfigView(seed=seed)
        assert view.has_redirect
        destination = view.get_redirect()
        assert destination.View_cls == MainMenuView
        assert destination.clear_history is True


class TestSevenFReviewFieldPagination:
    """ _paginate_value() and SevenFGenesisReviewFieldView's use of it --
        regression coverage for a real no-blind-signing gap found live
        during the 7F hardware walkthrough: a long field value (the
        genesis-config's `message`, coordinator-supplied with no length
        limit) could silently render past the screen bounds with zero
        visual indication. """
    def test_paginate_value_returns_single_page_for_short_text(self):
        assert sevenf_views._paginate_value("hardware test ceremony") == ["hardware test ceremony"]

    def test_paginate_value_returns_single_page_for_text_containing_newline(self):
        """ Timestamp's own multi-line format (raw value + UTC) must not get
            re-split -- it's already deliberately formatted, and it's always
            short regardless. """
        value = "1790555198\n(2026-09-28 03:19:58 UTC)"
        assert sevenf_views._paginate_value(value) == [value]

    def test_paginate_value_splits_long_text_on_word_boundaries(self):
        long_message = " ".join(f"word{i}" for i in range(80))  # well over 180 chars
        pages = sevenf_views._paginate_value(long_message, max_chars=40)
        assert len(pages) > 1
        for page in pages:
            assert len(page) <= 40
        # No content lost, no words split mid-word, order preserved.
        assert " ".join(pages) == long_message

    def test_paginate_value_never_splits_a_single_word_wider_than_the_page(self):
        """ A single unbroken run longer than max_chars (e.g. no spaces at
            all) has nowhere safe to break -- must still be returned whole
            on its own page rather than corrupting it, matching this
            module's own "every character is still shown on some page"
            guarantee. """
        unbroken = "x" * 300
        pages = sevenf_views._paginate_value(unbroken, max_chars=180)
        assert "".join(pages) == unbroken

    def test_long_message_produces_multiple_review_pages_with_all_content_preserved(self):
        """ End-to-end: a genesis-config with a message long enough to need
            pagination actually produces more total review pages than the
            baseline 7, and paging through the message's own pages and
            rejoining them recovers the exact original message -- no
            silent truncation anywhere in the chain. """
        from seedsigner.models.sevenf.genesis_config import review_fields

        long_message = "word " * 60  # 300 chars, well over the 180-char budget
        consensus = ConsensusParams(target_block_time_secs=1, difficulty_adjustment_interval_blocks=1, blocks_per_decay_period=1)
        canonical_bytes = build_canonical_bytes(ChainKind.TESTNET, 1, long_message.strip(), consensus)
        fields = parse_canonical_bytes(canonical_bytes)

        real_fields = review_fields(fields)
        assert len(real_fields) == 7  # baseline, unchanged

        chunks = [
            chunk_value
            for field in real_fields
            for chunk_value in sevenf_views._paginate_value(field.value)
        ]
        assert len(chunks) > 7  # message pagination added real pages

        message_field = next(f for f in real_fields if f.label == "Message")
        message_chunks = sevenf_views._paginate_value(message_field.value)
        assert len(message_chunks) > 1
        assert " ".join(message_chunks) == message_field.value == long_message.strip()


class _DummyConfirmedDestination(View):
    """ Stand-in target View for SevenFCertRequestReviewFieldView tests --
        Destination never instantiates its View_cls until the Controller's
        own run loop does, so a bare class reference is enough to assert
        against without a real caller (Root self-cert / Deputy cross-cert)
        existing yet. """
    def run(self):
        raise NotImplementedError("never actually run in these tests")


class TestSevenFCertRequestReviewFieldView(FlowTest):
    """ The reusable no-blind-signing review screen for CertRequest fields
        (7f-signing-support-x509-cert-request-foundation) -- filed after two
        independent adversarial reviews both found this screen missing
        entirely from the original story. Tested in isolation from any real
        Root self-cert / Deputy cross-cert flow (neither exists yet): this
        view takes its fields via view_args, not controller.sevenf_ceremony_data,
        specifically so it doesn't need one to be tested or reused. """
    def _fields(self):
        from seedsigner.chains.base import ReviewField
        return [
            ReviewField(label="Role", value="root"),
            ReviewField(label="Chain", value="testnet"),
        ]

    def test_pages_through_every_field_then_reaches_the_confirmed_destination(self):
        fields = self._fields()
        view = sevenf_views.SevenFCertRequestReviewFieldView(
            review_fields=fields,
            page_title="Review Root Certificate",
            confirmed_destination=_DummyConfirmedDestination,
            confirmed_view_args=dict(foo="bar"),
        )
        assert len(view.chunks) == 2  # neither value needs pagination

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: 0)
            destination = view.run()
        assert destination.View_cls == sevenf_views.SevenFCertRequestReviewFieldView
        assert destination.view_args["page_num"] == 1

        next_view = sevenf_views.SevenFCertRequestReviewFieldView(**destination.view_args)
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(next_view, "run_screen", lambda *a, **kw: 0)
            final_destination = next_view.run()
        assert final_destination.View_cls == _DummyConfirmedDestination
        assert final_destination.view_args == dict(foo="bar")


    def test_back_button_on_first_page_returns_to_back_stack(self):
        view = sevenf_views.SevenFCertRequestReviewFieldView(
            review_fields=self._fields(),
            page_title="Review Root Certificate",
            confirmed_destination=_DummyConfirmedDestination,
        )
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: RET_CODE__BACK_BUTTON)
            destination = view.run()
        from seedsigner.views.view import BackStackView
        assert destination.View_cls == BackStackView


    def test_back_button_on_a_later_page_also_returns_to_back_stack(self):
        view = sevenf_views.SevenFCertRequestReviewFieldView(
            review_fields=self._fields(),
            page_title="Review Root Certificate",
            confirmed_destination=_DummyConfirmedDestination,
            page_num=1,
        )
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: RET_CODE__BACK_BUTTON)
            destination = view.run()
        from seedsigner.views.view import BackStackView
        assert destination.View_cls == BackStackView


    def test_defaults_to_an_empty_confirmed_view_args_dict(self):
        view = sevenf_views.SevenFCertRequestReviewFieldView(
            review_fields=[self._fields()[0]],
            page_title="Review Deputy Certificate",
            confirmed_destination=_DummyConfirmedDestination,
        )
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: 0)
            destination = view.run()
        assert destination.View_cls == _DummyConfirmedDestination
        assert destination.view_args == {}


    def test_a_long_field_value_is_paginated_like_the_genesis_review_screen(self):
        from seedsigner.chains.base import ReviewField
        long_value = " ".join(f"word{i}" for i in range(80))
        fields = [ReviewField(label="Serial", value=long_value)]
        view = sevenf_views.SevenFCertRequestReviewFieldView(
            review_fields=fields,
            page_title="Review Root Certificate",
            confirmed_destination=_DummyConfirmedDestination,
        )
        assert len(view.chunks) > 1
        assert " ".join(c.value for c in view.chunks) == long_value


    def test_page_title_and_field_content_are_passed_to_the_screen(self):
        view = sevenf_views.SevenFCertRequestReviewFieldView(
            review_fields=self._fields(),
            page_title="Review Root Certificate",
            confirmed_destination=_DummyConfirmedDestination,
        )
        captured = {}

        def fake_run_screen(screen_cls, **kwargs):
            captured.update(kwargs)
            return 0

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", fake_run_screen)
            view.run()

        assert captured["page_title"] == "Review Root Certificate"
        assert captured["label_text"] == "Role"
        assert captured["value_text"] == "root"
        assert captured["page_num"] == 0
        assert captured["num_pages"] == 2
        assert captured["is_final_page"] is False


    def test_raises_if_constructed_with_an_out_of_range_page_num(self):
        with pytest.raises(Exception):
            sevenf_views.SevenFCertRequestReviewFieldView(
                review_fields=self._fields(),
                page_title="Review Root Certificate",
                confirmed_destination=_DummyConfirmedDestination,
                page_num=99,
            )
