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

from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON, ButtonOption
from seedsigner.models.decode_qr import DecodeQR, DecodeQRStatus
from seedsigner.models.encode_qr import BBQrEncoder
from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants
from seedsigner.models.sevenf import mldsa
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


def _sample_genesis_config_json(chain_kind_str: str = "testnet", **overrides) -> bytes:
    """ The REAL coordinator artifact (sf-root prepare-genesis's JSON file,
        sf_core::genesis_config::GenesisConfig) -- what actually arrives
        over BBQr as of the genesis-wire-envelope fix, not raw
        canonical_bytes (see SevenFScanGenesisConfigView's own doc comment). """
    doc = dict(
        version=1,
        chain_kind=chain_kind_str,
        timestamp=1_790_555_198,
        message="cross-check fixture",
        derivation_scheme="7fchain.ml-dsa-keygen.v1",
        consensus={
            "target_block_time_secs": 420,
            "difficulty_adjustment_interval_blocks": 3500,
            "blocks_per_decay_period": 70_000,
        },
        signatures=[],
    )
    doc.update(overrides)
    return json.dumps(doc).encode("utf-8")


class TestSevenFGenesisReviewFlow(FlowTest):
    def seed_fixture(self) -> Seed:
        seed = Seed(mnemonic=["abandon"] * 11 + ["about"], wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)
        self.controller.storage.seeds.append(seed)
        return seed


    def _enter_review_flow(self, seed: Seed, canonical_bytes: bytes) -> "sevenf_views.SevenFGenesisCeremonyState":
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
            run_sequence harness, to sidestep that test-harness-only gap.

            Returns the SevenFGenesisCeremonyState the start view built, for
            callers to pass along as initial_destination_view_args
            (7f-review-ceremony-data-untyped-shared-dict: this flow's state
            is threaded through view_args now, not a controller global). """
        start_view = sevenf_views.SevenFGenesisReviewStartView(
            seed=seed, canonical_bytes=canonical_bytes,
        )
        destination = start_view.run()
        assert destination.View_cls == sevenf_views.SevenFGenesisReviewFieldView
        assert destination.view_args["page_num"] == 0
        return destination.view_args["state"]


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
        state = self._enter_review_flow(seed, canonical_bytes)

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
            initial_destination_view_args=dict(state=state, page_num=0),
        )


    def test_signed_result_matches_direct_sign_with_root_ca_call(self):
        """ The flow's actual output must be the real Root CA signature over
            the real canonical bytes -- not a placeholder -- confirmed by
            reaching into the signed SevenFGenesisCeremonyState threaded
            through to SevenFGenesisSignedView and comparing against an
            independent direct call. """
        seed = self.seed_fixture()
        canonical_bytes = _sample_canonical_bytes()
        state = self._enter_review_flow(seed, canonical_bytes)

        captured = {}

        def capture_before_home(view):
            captured["public_key"] = view.state.public_key
            captured["signature"] = view.state.signature

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
            initial_destination_view_args=dict(state=state, page_num=0),
        )

        keys = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.TESTNET)
        assert captured["public_key"] == keys.root_ca.public_key
        assert len(captured["signature"]) == 3309


    def test_back_button_on_first_review_page_abandons_flow(self):
        seed = self.seed_fixture()
        canonical_bytes = _sample_canonical_bytes()
        state = self._enter_review_flow(seed, canonical_bytes)

        self.run_sequence(
            [
                FlowStep(sevenf_views.SevenFGenesisReviewFieldView, screen_return_value=RET_CODE__BACK_BUTTON),
            ],
            initial_destination_view_args=dict(state=state, page_num=0),
        )


    def test_back_button_on_a_later_review_page_does_not_clear_state(self):
        """ Only page 0's back button abandons the whole flow -- backing up
            from a later page must return to the previous page's content,
            not disturb the state the operator has already been reviewing
            (see SevenFGenesisReviewFieldView.run()'s page_num == 0 guard).
            State is threaded through view_args, not a controller global
            (7f-review-ceremony-data-untyped-shared-dict), so there is
            nothing to "clear" any more -- this confirms the same state
            object survives a non-zero-page back button untouched. Direct
            unit-level check, not a full run_sequence: the Controller's
            back_stack semantics require a "current view" already pushed
            before a FlowStep sequence starts (true in real usage --
            MainMenuView et al. precede this flow -- but not reproducible by
            starting run_sequence fresh at page 1 without the not-yet-built
            wizard/menu chain in front of it). """
        seed = self.seed_fixture()
        canonical_bytes = _sample_canonical_bytes()
        state = self._enter_review_flow(seed, canonical_bytes)

        view = sevenf_views.SevenFGenesisReviewFieldView(state=state, page_num=1)
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: RET_CODE__BACK_BUTTON)
            destination = view.run()

        from seedsigner.views.view import BackStackView
        assert destination.View_cls == BackStackView
        assert view.state is state


    def test_back_button_on_confirm_sign_screen_returns_to_back_stack_without_signing(self):
        """ Backing out of the final confirm-and-sign screen must not sign
            anything -- confirms the "Sign" button click is genuinely the
            only path into root_ceremony.sign_with_root_ca(), not merely the
            expected one. """
        seed = self.seed_fixture()
        canonical_bytes = _sample_canonical_bytes()
        state = sevenf_views.SevenFGenesisCeremonyState(
            seed=seed, chain_kind=ChainKind.TESTNET, canonical_bytes=canonical_bytes, review_fields=[],
        )

        view = sevenf_views.SevenFConfirmSignView(state=state)
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: RET_CODE__BACK_BUTTON)
            destination = view.run()

        from seedsigner.views.view import BackStackView
        assert destination.View_cls == BackStackView
        assert view.state.public_key is None
        assert view.state.signature is None


    def test_confirm_sign_view_shows_the_real_root_ca_address_for_the_chain_kind(self):
        """ Unit-level check (not a full flow run): SevenFConfirmSignView must
            derive the address it displays from the same
            derive_root_ceremony_keys() path the rest of the ceremony uses --
            confirms it isn't a placeholder or a different derivation. """
        seed = self.seed_fixture()
        canonical_bytes = _sample_canonical_bytes()
        state = sevenf_views.SevenFGenesisCeremonyState(
            seed=seed, chain_kind=ChainKind.TESTNET, canonical_bytes=canonical_bytes, review_fields=[],
        )

        view = sevenf_views.SevenFConfirmSignView(state=state)
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

        view = sevenf_views.SevenFGenesisReviewStartView(seed=seed, canonical_bytes=canonical_bytes)
        assert view.state.chain_kind == ChainKind.TESTNET


    def test_export_pubkey_qr_view_encodes_the_real_root_ca_pubkey(self):
        """ Confirms the exported QR actually carries this ceremony's real
            Root CA public key (BBQr-encoded, file_type 'U'), round-tripped
            through the real BBQr encoder/decoder pair -- not a placeholder
            and not merely "some bytes got passed to some encoder". """
        seed = self.seed_fixture()
        canonical_bytes = _sample_canonical_bytes()
        keys = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.TESTNET)
        state = sevenf_views.SevenFGenesisCeremonyState(
            seed=seed, chain_kind=ChainKind.TESTNET, canonical_bytes=canonical_bytes,
            review_fields=[], public_key=keys.root_ca.public_key, signature=b"\x00" * 3309,
        )

        view = sevenf_views.SevenFExportPubkeyQRView(state=state)
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
        signature = bytes(range(256)) * 12 + bytes(3309 - 256 * 12)  # 3309 varied bytes, not all-zero
        state = sevenf_views.SevenFGenesisCeremonyState(
            seed=seed, chain_kind=ChainKind.TESTNET, canonical_bytes=canonical_bytes,
            review_fields=[], public_key=keys.root_ca.public_key, signature=signature,
        )

        view = sevenf_views.SevenFExportSignedConfigQRView(state=state)
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
        state = sevenf_views.SevenFGenesisCeremonyState(
            seed=seed, chain_kind=ChainKind.TESTNET, canonical_bytes=canonical_bytes, review_fields=[],
        )

        view = sevenf_views.SevenFExportView(state=state)
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


def _load_cert_request_into_decoder(data: bytes, file_type: str = "J"):
    """ Same before_run pattern as _load_genesis_config_into_decoder, for a
        CertRequest JSON payload instead of genesis-config canonical bytes. """
    def loader(view):
        encoder = BBQrEncoder(data=data, file_type=file_type)
        for _ in range(encoder.seq_len()):
            view.decoder.add_data(encoder.next_part())
    return loader


class TestSevenFRootSelfCertificationFlow(FlowTest):
    """ The Root self-certification flow's PKCS#10-era rework
        (7f-signing-support-root-self-certification-pkcs10-rework; see
        cert_request.py's own "ROOT SELF-CERT PKCS#10 REWORK" docstring
        note and docs/7f-integration/root-self-cert-pkcs10-rework-plan.md):
        SeedOptionsView's "7F: Self-Certify Root" button ->
        SevenFSelectChainKindForRootSelfCertView (no scan at all -- the
        device derives its own key, builds its own TBS with a fresh
        CSPRNG serial and the current wall-clock time, entirely locally) ->
        SevenFCertRequestReviewFieldView (5 fields) ->
        SevenFConfirmSignRootCertView -> SevenFRootCertSignedView ->
        SevenFExportRootCertQRView (exports the complete ASSEMBLED
        certificate, not a detached signature -- the plan's §3 fix for the
        detached-signature-export bug) -> MainMenuView. """
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


    def test_seed_options_view_routes_to_select_chain_kind_view(self):
        seed = self.seed_fixture()
        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF_SCAN_ROOT_CERT_REQUEST),
                FlowStep(sevenf_views.SevenFSelectChainKindForRootSelfCertView),
            ],
            initial_destination_view_args=dict(seed=seed),
        )


    def test_chain_kind_select_builds_a_real_tbs_and_routes_to_review(self):
        """ Unit-level: selecting a chain builds a real TBS embedding THIS
            seed's own derived key (confirmed by signing it for real and
            assembling -- assemble_root_cert_der's own binding check would
            refuse if the TBS named a different key), with a fresh serial
            each call, and routes to review with the export destination
            already wired to the certificate export (not the old
            signed-config menu). """
        from seedsigner.models.sevenf import cert_request as cert_request_module
        from seedsigner.models.sevenf.root_ceremony import sign_with_root_ca

        seed = self.seed_fixture()
        keys = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.TESTNET)

        view = sevenf_views.SevenFSelectChainKindForRootSelfCertView(seed=seed)
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: 1)  # index 1 == TESTNET (Mainnet=0, Testnet=1, Devnet=2)
            destination1 = view.run()
            destination2 = view.run()

        assert destination1.View_cls == sevenf_views.SevenFCertRequestReviewFieldView
        args1 = destination1.view_args
        assert len(args1["review_fields"]) == 5
        assert [f.label for f in args1["review_fields"]] == ["Subject key id", "Chain", "Valid from", "Valid until", "Serial"]
        confirmed_args = args1["confirmed_view_args"]
        assert confirmed_args["chain_kind"] == ChainKind.TESTNET
        assert confirmed_args["signed_view_args"] == dict(export_destination=sevenf_views.SevenFExportRootCertQRView)

        tbs_bytes = confirmed_args["tbs_bytes"]
        _, signature = sign_with_root_ca(seed.seed_bytes, ChainKind.TESTNET, tbs_bytes, confirmed=True)
        cert_der = cert_request_module.assemble_root_cert_der(tbs_bytes, signature, keys.root_ca.public_key)
        parsed = cert_request_module.parse_root_certificate_der(cert_der)
        assert parsed.subject_vk == keys.root_ca.public_key

        # Two separate runs must pick different serials -- not a fixed/stub value.
        assert tbs_bytes != destination2.view_args["confirmed_view_args"]["tbs_bytes"]


    def test_full_flow_builds_signs_assembles_and_exports(self):
        """ End-to-end: select testnet -> device builds+reviews+signs its
            own certificate entirely locally -> export. Confirms the real
            public_key/signature (matching 3309-byte ML-DSA-65 signature),
            and -- the actual fix this story ships -- that tbs_bytes
            survives into ceremony_data and the final exported bytes
            assemble into a certificate that parses back to the exact
            fields this ceremony run chose, not just "didn't raise". """
        seed = self.seed_fixture()
        keys = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.TESTNET)

        captured = {}

        def capture_before_export(view):
            certificate = view.certificate
            captured["public_key"] = certificate.public_key
            captured["signature"] = certificate.signature
            captured["tbs_bytes"] = certificate.tbs_bytes

        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF_SCAN_ROOT_CERT_REQUEST),
                FlowStep(sevenf_views.SevenFSelectChainKindForRootSelfCertView, button_data_selection=ButtonOption("testnet")),
                *[FlowStep(sevenf_views.SevenFCertRequestReviewFieldView, screen_return_value=0) for _ in range(5)],
                FlowStep(sevenf_views.SevenFConfirmSignRootCertView, screen_return_value=0),  # "Sign"
                FlowStep(sevenf_views.SevenFRootCertSignedView, before_run=capture_before_export, screen_return_value=0),  # "OK"
                FlowStep(sevenf_views.SevenFExportRootCertQRView, screen_return_value=0),
                FlowStep(MainMenuView),
            ],
            initial_destination_view_args=dict(seed=seed),
        )

        assert captured["public_key"] == keys.root_ca.public_key
        assert len(captured["signature"]) == 3309

        from seedsigner.models.sevenf import cert_request as cert_request_module
        cert_der = cert_request_module.assemble_root_cert_der(captured["tbs_bytes"], captured["signature"], captured["public_key"])
        parsed = cert_request_module.parse_root_certificate_der(cert_der)
        assert parsed.subject_vk == keys.root_ca.public_key
        assert parsed.chain_kind == ChainKind.TESTNET


    def test_export_root_cert_qr_view_encodes_a_real_assembled_certificate(self):
        """ Unit-level, mirroring test_export_pubkey_qr_view_encodes_the_real_
            root_ca_pubkey's own pattern: confirms the exported QR carries a
            genuine assembled certificate (BBQr-encoded, file_type 'B'),
            round-tripped through the real BBQr encoder/decoder pair and
            re-parsed back to the exact fields this ceremony chose -- not a
            placeholder and not merely "some bytes got passed to some
            encoder". Also confirms this routes to MainMenuView directly,
            NOT through SevenFExportView's old pubkey/signed-config menu. """
        seed = self.seed_fixture()
        keys = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.MAINNET)
        from seedsigner.models.sevenf import cert_request as cert_request_module
        from seedsigner.models.sevenf.root_ceremony import sign_with_root_ca

        serial = cert_request_module.generate_serial()
        not_before = 1_750_000_000
        tbs_bytes = cert_request_module.build_root_tbs(keys.root_ca.public_key, ChainKind.MAINNET, not_before, cert_request_module.ROOT_DAYS, serial)
        public_key, signature = sign_with_root_ca(seed.seed_bytes, ChainKind.MAINNET, tbs_bytes, confirmed=True)
        certificate = sevenf_views.SevenFSignedCertificate(public_key=public_key, signature=signature, tbs_bytes=tbs_bytes)

        view = sevenf_views.SevenFExportRootCertQRView(certificate=certificate)
        captured = {}

        def fake_run_screen(screen_cls, **kwargs):
            captured["qr_encoder"] = kwargs["qr_encoder"]

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", fake_run_screen)
            destination = view.run()

        encoder = captured["qr_encoder"]
        assert encoder.file_type == "B"

        d = DecodeQR()
        while True:
            status = d.add_data(encoder.next_part())
            if status == DecodeQRStatus.COMPLETE:
                break
        cert_der = d.decoder.get_data()
        parsed = cert_request_module.parse_root_certificate_der(cert_der)
        assert parsed.subject_vk == keys.root_ca.public_key
        assert parsed.chain_kind == ChainKind.MAINNET
        assert parsed.not_before == not_before

        assert destination.View_cls == MainMenuView


    def test_select_chain_kind_fails_closed_if_tbs_building_fails(self):
        """ build_root_tbs raising must route to the error view, not crash
            or silently proceed to review with a broken body. """
        from seedsigner.models.sevenf import cert_request as cert_request_module

        seed = self.seed_fixture()
        view = sevenf_views.SevenFSelectChainKindForRootSelfCertView(seed=seed)

        def fake_build_root_tbs(*a, **kw):
            raise cert_request_module.CertRequestError("simulated build failure")

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: 1)  # TESTNET
            mp.setattr(cert_request_module, "build_root_tbs", fake_build_root_tbs)
            destination = view.run()

        assert destination.View_cls == sevenf_views.SevenFUnsupportedArtefactView


    def test_back_button_on_confirm_sign_screen_returns_to_back_stack_without_signing(self):
        """ Mirrors TestSevenFGenesisReviewFlow's own equivalent test:
            backing out of the final confirm-and-sign screen must not sign
            anything. """
        from seedsigner.models.sevenf import cert_request as cert_request_module

        seed = self.seed_fixture()
        keys = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.TESTNET)
        tbs_bytes = cert_request_module.build_root_tbs(keys.root_ca.public_key, ChainKind.TESTNET, 1_700_000_000, cert_request_module.ROOT_DAYS, cert_request_module.generate_serial())

        view = sevenf_views.SevenFConfirmSignRootCertView(seed=seed, chain_kind=ChainKind.TESTNET, tbs_bytes=tbs_bytes)
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: RET_CODE__BACK_BUTTON)
            destination = view.run()

        from seedsigner.views.view import BackStackView
        assert destination.View_cls == BackStackView


    def test_confirm_sign_view_shows_the_real_root_ca_address(self):
        from seedsigner.models.sevenf import cert_request as cert_request_module

        seed = self.seed_fixture()
        keys = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.TESTNET)
        tbs_bytes = cert_request_module.build_root_tbs(keys.root_ca.public_key, ChainKind.TESTNET, 1_700_000_000, cert_request_module.ROOT_DAYS, cert_request_module.generate_serial())

        view = sevenf_views.SevenFConfirmSignRootCertView(seed=seed, chain_kind=ChainKind.TESTNET, tbs_bytes=tbs_bytes)
        assert view.root_ca_address == keys.root_ca.address


    def test_confirm_sign_view_stores_tbs_bytes_into_the_signed_certificate(self):
        """ The actual bug fix this story ships (plan's §3): tbs_bytes must
            survive into the SevenFSignedCertificate, not be discarded after
            signing. """
        from seedsigner.models.sevenf import cert_request as cert_request_module

        seed = self.seed_fixture()
        keys = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.TESTNET)
        tbs_bytes = cert_request_module.build_root_tbs(keys.root_ca.public_key, ChainKind.TESTNET, 1_700_000_000, cert_request_module.ROOT_DAYS, cert_request_module.generate_serial())

        view = sevenf_views.SevenFConfirmSignRootCertView(
            seed=seed, chain_kind=ChainKind.TESTNET, tbs_bytes=tbs_bytes,
            signed_view_args=dict(export_destination=sevenf_views.SevenFExportRootCertQRView),
        )
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: 0)
            destination = view.run()

        assert destination.view_args["certificate"].tbs_bytes == tbs_bytes


class TestSevenFUnsupportedArtefactViewHeadline:
    """ SevenFUnsupportedArtefactView's optional `headline` override, added
        for a well-formed artefact that must still be refused for a reason
        beyond a parse failure (originally the Root self-certification
        flow's own fail-closed "Wrong Key" refusal, before that flow's
        PKCS#10-era rework removed the scan it applied to -- now exercised
        by SevenFScanRootCertificateView's identically-named check). """
    def test_default_headline_is_unchanged(self):
        view = sevenf_views.SevenFUnsupportedArtefactView(reason="some reason")
        assert view.headline == "Can't Parse This"

    def test_custom_headline_overrides_the_default(self):
        view = sevenf_views.SevenFUnsupportedArtefactView(reason="some reason", headline="Wrong Key")
        assert view.headline == "Wrong Key"


class TestSevenFDeputyCrossCertificationFlow(FlowTest):
    """ The PKCS#10-based Deputy cross-certification flow
        (7f-signing-support-deputy-cross-certification-pkcs10-rework; see
        cert_request.py's own "PKCS#10 REWORK" docstring note and
        docs/7f-integration/deputy-cross-cert-pkcs10-rework-plan.md):
        SeedOptionsView's "7F: Cross-Certify Deputy" button ->
        SevenFSelectChainKindForDeputyCrossCertView (operator picks the
        chain explicitly -- a certificate carries no separate network
        signal of its own) -> SevenFScanRootCertificateView (scan the
        Root's own REAL signed certificate) -> SevenFScanDeputyCsrView
        (scan the Deputy's self-signed PKCS#10 CSR, verified on-device) ->
        SevenFCertRequestReviewFieldView (8 fields: the real Root
        certificate's identity/window, then the Deputy's) ->
        SevenFConfirmSignRootCertView -> SevenFRootCertSignedView
        (Deputy-specific wording) -> SevenFExportView.

        Uses the SAME real reference vectors as
        test_sevenf_cert_request.py (captured once from 7fchain's own
        x509_ceremony.rs, D12) -- cross-file import, same convention
        test_sevenf_interoperability_vectors.py already uses. """
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


    def test_seed_options_view_routes_to_select_chain_kind_view(self):
        seed = self.seed_fixture()
        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF_SCAN_DEPUTY_CROSS_CERT),
                FlowStep(sevenf_views.SevenFSelectChainKindForDeputyCrossCertView),
            ],
            initial_destination_view_args=dict(seed=seed),
        )


    def test_chain_kind_select_routes_to_scan_root_certificate_view(self):
        seed = self.seed_fixture()
        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF_SCAN_DEPUTY_CROSS_CERT),
                FlowStep(sevenf_views.SevenFSelectChainKindForDeputyCrossCertView, button_data_selection=ButtonOption("testnet")),
                FlowStep(sevenf_views.SevenFScanRootCertificateView),
            ],
            initial_destination_view_args=dict(seed=seed),
        )


    def test_full_flow_with_real_matching_keys_signs_and_exports(self):
        """ End-to-end: select testnet -> scan a Root certificate THIS
            seed's own derived key actually signed (built fresh here, via
            the same build+sign+assemble pipeline
            TestSevenFRootSelfCertificationFlow's own full-flow test uses --
            no mock of the Wrong-Key check is needed, since this cert is
            genuinely self-consistent for this seed, unlike the earlier
            version of this test which monkeypatched derive_root_ceremony_keys
            to paper over the fact that the real reference ROOT_CERT_DER's
            embedded key belongs to nobody this sandbox can sign for) ->
            scan the real reference Deputy CSR (self-signed by the real
            Deputy's own key, independent of which Root issues it) ->
            review all 8 fields -> confirm+sign -> Deputy-specific signed
            screen -> export (the complete assembled certificate, not the
            old pubkey/signed-config menu -- closes the Deputy half of
            7f-signing-support-detached-sig-export-unreconstructable).
            Confirms the real public_key/signature (the Root's, not the
            Deputy's -- the Root is always the signer), the Deputy-specific
            success wording, and that the final exported bytes assemble
            into a certificate parsing back to the Deputy's own subject key
            and chosen chain -- not just "didn't raise". """
        import time as time_module
        from test_sevenf_cert_request import DEPUTY_CSR_DER
        from seedsigner.models.sevenf import cert_request as cert_request_module
        from seedsigner.models.sevenf.root_ceremony import sign_with_root_ca

        seed = self.seed_fixture()
        real_root_ca_public_key = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.TESTNET).root_ca.public_key
        root_not_before = 1_800_000_000
        root_serial = cert_request_module.generate_serial()
        root_tbs = cert_request_module.build_root_tbs(
            real_root_ca_public_key, ChainKind.TESTNET, root_not_before, cert_request_module.ROOT_DAYS, root_serial,
        )
        _, root_signature = sign_with_root_ca(seed.seed_bytes, ChainKind.TESTNET, root_tbs, confirmed=True)
        root_cert_der = cert_request_module.assemble_root_cert_der(root_tbs, root_signature, real_root_ca_public_key)
        deputy_csr = cert_request_module.verify_and_parse_csr_der(DEPUTY_CSR_DER)

        captured = {}

        def capture_signed_screen_args(view):
            captured["title"] = view.title
            captured["text"] = view.text

        def capture_before_export(view):
            certificate = view.certificate
            captured["public_key"] = certificate.public_key
            captured["signature"] = certificate.signature
            captured["tbs_bytes"] = certificate.tbs_bytes
            captured["root_cert_der"] = certificate.root_cert_der

        with pytest.MonkeyPatch().context() as mp:
            # Same wall-clock fix as test_review_fields_are_labeled_and_ordered_root_then_deputy,
            # kept within this freshly-built Root cert's own validity window.
            mp.setattr(time_module, "time", lambda: root_not_before + 86400)
            self.run_sequence(
                [
                    FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF_SCAN_DEPUTY_CROSS_CERT),
                    FlowStep(sevenf_views.SevenFSelectChainKindForDeputyCrossCertView, button_data_selection=ButtonOption("testnet")),
                    FlowStep(
                        sevenf_views.SevenFScanRootCertificateView,
                        before_run=_load_cert_request_into_decoder(root_cert_der),
                        screen_return_value=0,
                    ),
                    FlowStep(
                        sevenf_views.SevenFScanDeputyCsrView,
                        before_run=_load_cert_request_into_decoder(DEPUTY_CSR_DER),
                        screen_return_value=0,
                    ),
                    # 9 review pages (deputy_cross_cert_v2_review_fields): 3 "Issuing
                    # Root: ..." fields, "Chain", then 5 "Deputy: ..." fields.
                    *[FlowStep(sevenf_views.SevenFCertRequestReviewFieldView, screen_return_value=0) for _ in range(9)],
                    FlowStep(sevenf_views.SevenFConfirmSignRootCertView, screen_return_value=0),  # "Sign"
                    FlowStep(
                        sevenf_views.SevenFRootCertSignedView,
                        before_run=lambda view: (capture_signed_screen_args(view), capture_before_export(view)),
                        screen_return_value=0,
                    ),  # "OK"
                    FlowStep(sevenf_views.SevenFExportDeputyCertQRView, screen_return_value=0),
                    FlowStep(MainMenuView),
                ],
                initial_destination_view_args=dict(seed=seed),
            )

        assert captured["title"] == "Deputy Certificate Signed"
        assert "Deputy" in captured["text"]
        # The signer is the ROOT, not the Deputy -- confirms this cross-certification's
        # signature is attributed to the Root key, never the Deputy's own.
        assert captured["public_key"] == real_root_ca_public_key
        assert len(captured["signature"]) == 3309

        cert_der = cert_request_module.assemble_deputy_cert_der(
            captured["tbs_bytes"], captured["signature"], captured["root_cert_der"],
        )
        parsed = cert_request_module.parse_root_certificate_der(cert_der)
        assert parsed.subject_vk == deputy_csr.subject_vk
        assert parsed.chain_kind == ChainKind.TESTNET


    def test_review_fields_are_labeled_and_ordered_root_then_deputy(self):
        """ SevenFScanDeputyCsrView needs no key-matching mock: the "Wrong
            Key" check already happened in the prior scan step, so this
            view can be exercised directly against the real root cert/CSR
            reference vectors. """
        import time as time_module
        from test_sevenf_cert_request import DEPUTY_CSR_DER, ROOT_CERT_DER, ROOT_CERT_NOT_BEFORE
        from seedsigner.models.sevenf import cert_request as cert_request_module

        seed = self.seed_fixture()
        root_cert = cert_request_module.parse_root_certificate_der(ROOT_CERT_DER)

        class _FakeDecoder:
            def get_sevenf_bbqr_data(self):
                return DEPUTY_CSR_DER

        view = sevenf_views.SevenFScanDeputyCsrView(
            seed=seed, chain_kind=ChainKind.TESTNET, root_cert_der=ROOT_CERT_DER, root_cert=root_cert,
        )
        view.decoder = _FakeDecoder()
        # The real reference Root certificate's validity window starts in
        # 2027 -- fix the wall clock inside its window rather than relying
        # on the sandbox's actual system time, which may be earlier.
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(time_module, "time", lambda: ROOT_CERT_NOT_BEFORE + 86400)
            destination = view._handle_complete_scan()

        fields = destination.view_args["review_fields"]
        assert [f.label for f in fields] == [
            "Issuing Root: Subject key id", "Issuing Root: Valid from", "Issuing Root: Valid until",
            "Chain", "Deputy: Subject key id", "Deputy: Valid from", "Deputy: Valid for",
            "Deputy: Valid until", "Deputy: Serial",
        ]
        assert fields[3].value == "testnet"


    def test_scan_root_certificate_rejects_a_chain_kind_mismatch(self):
        """ The real reference Root certificate's own embedded chain_kind is
            Testnet -- selecting Mainnet first must be refused. """
        from test_sevenf_cert_request import ROOT_CERT_DER

        seed = self.seed_fixture()

        class _FakeDecoder:
            def get_sevenf_bbqr_data(self):
                return ROOT_CERT_DER

        view = sevenf_views.SevenFScanRootCertificateView(seed=seed, chain_kind=ChainKind.MAINNET)
        view.decoder = _FakeDecoder()
        destination = view._handle_complete_scan()
        assert destination.View_cls == sevenf_views.SevenFUnsupportedArtefactView
        assert destination.view_args["headline"] == "Chain Mismatch"


    def test_scan_root_certificate_fail_closed_refuses_a_different_roots_key(self):
        """ The real reference vector's Root certificate was signed by an
            unrelated keypair (7fchain's own test fixture, not derivable
            from any accessible mnemonic) -- this is the natural, unmocked
            "Wrong Key" case; test_full_flow_with_real_matching_keys_signs_and_exports
            is what exercises the matching-key path instead. """
        from test_sevenf_cert_request import ROOT_CERT_DER

        seed = self.seed_fixture()

        class _FakeDecoder:
            def get_sevenf_bbqr_data(self):
                return ROOT_CERT_DER

        view = sevenf_views.SevenFScanRootCertificateView(seed=seed, chain_kind=ChainKind.TESTNET)
        view.decoder = _FakeDecoder()
        destination = view._handle_complete_scan()
        assert destination.View_cls == sevenf_views.SevenFUnsupportedArtefactView
        assert destination.view_args["headline"] == "Wrong Key"


    def test_scan_root_certificate_rejects_garbage_der(self):
        seed = self.seed_fixture()

        class _FakeDecoder:
            def get_sevenf_bbqr_data(self):
                return b"not a certificate at all" * 20

        view = sevenf_views.SevenFScanRootCertificateView(seed=seed, chain_kind=ChainKind.TESTNET)
        view.decoder = _FakeDecoder()
        destination = view._handle_complete_scan()
        assert destination.View_cls == sevenf_views.SevenFUnsupportedArtefactView


    def test_scan_deputy_csr_rejects_an_unverifiable_csr(self):
        """ A CSR that fails signature verification (not proof-of-possession)
            must be refused just like malformed DER -- this device's
            first-ever on-device verification over untrusted scanned input. """
        from test_sevenf_cert_request import ROOT_CERT_DER
        from seedsigner.models.sevenf import cert_request as cert_request_module

        seed = self.seed_fixture()
        root_cert = cert_request_module.parse_root_certificate_der(ROOT_CERT_DER)

        class _FakeDecoder:
            def get_sevenf_bbqr_data(self):
                return b"not a csr at all" * 20

        view = sevenf_views.SevenFScanDeputyCsrView(
            seed=seed, chain_kind=ChainKind.TESTNET, root_cert_der=ROOT_CERT_DER, root_cert=root_cert,
        )
        view.decoder = _FakeDecoder()
        destination = view._handle_complete_scan()
        assert destination.View_cls == sevenf_views.SevenFUnsupportedArtefactView


    def test_back_button_on_confirm_sign_screen_does_not_sign(self):
        """ Reuses the real build_deputy_tbs_v2 reference-vector output for
            tbs_bytes -- SevenFConfirmSignRootCertView never cross-checks
            tbs_bytes against its own derived address (that already
            happened upstream, in SevenFScanRootCertificateView), so no
            key-matching mock is needed here either. """
        from test_sevenf_cert_request import DEPUTY_CSR_DER, ROOT_CERT_DER, ROOT_CERT_NOT_BEFORE
        from seedsigner.models.sevenf import cert_request as cert_request_module

        seed = self.seed_fixture()
        serial = bytes([0x22]) * 16
        tbs_bytes = cert_request_module.build_deputy_tbs_v2(
            ROOT_CERT_DER, DEPUTY_CSR_DER, ChainKind.TESTNET, ROOT_CERT_NOT_BEFORE, cert_request_module.DEPUTY_DAYS, serial,
        )

        view = sevenf_views.SevenFConfirmSignRootCertView(
            seed=seed, chain_kind=ChainKind.TESTNET, tbs_bytes=tbs_bytes,
            signed_view_args=dict(title="Deputy Certificate Signed", text="whatever"),
        )
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: RET_CODE__BACK_BUTTON)
            destination = view.run()

        from seedsigner.views.view import BackStackView
        assert destination.View_cls == BackStackView


    def test_export_deputy_cert_qr_view_encodes_a_real_assembled_certificate(self):
        """ Unit-level, mirroring TestSevenFRootSelfCertificationFlow's own
            test_export_root_cert_qr_view_encodes_a_real_assembled_certificate:
            confirms the exported QR carries a genuine assembled Deputy
            certificate (BBQr-encoded, file_type 'B'), round-tripped through
            the real BBQr encoder/decoder pair and re-parsed back to the
            Deputy's own subject key (not the Root's -- the Root only ever
            signs) -- not a placeholder and not merely "some bytes got
            passed to some encoder". Also confirms this routes to
            MainMenuView directly, NOT through SevenFExportView's old
            pubkey/signed-config menu. """
        from test_sevenf_cert_request import DEPUTY_CSR_DER
        from seedsigner.models.sevenf import cert_request as cert_request_module
        from seedsigner.models.sevenf.root_ceremony import sign_with_root_ca

        # A Root certificate THIS seed's own derived key actually signed --
        # see test_full_flow_with_real_matching_keys_signs_and_exports's own
        # docstring for why the real reference ROOT_CERT_DER (nobody this
        # sandbox can sign for) no longer fits here now that
        # assemble_deputy_cert_der genuinely verifies against it.
        seed = self.seed_fixture()
        root_vk = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.TESTNET).root_ca.public_key
        root_not_before = 1_800_000_000
        root_tbs = cert_request_module.build_root_tbs(
            root_vk, ChainKind.TESTNET, root_not_before, cert_request_module.ROOT_DAYS, cert_request_module.generate_serial(),
        )
        _, root_signature = sign_with_root_ca(seed.seed_bytes, ChainKind.TESTNET, root_tbs, confirmed=True)
        root_cert_der = cert_request_module.assemble_root_cert_der(root_tbs, root_signature, root_vk)

        deputy_csr = cert_request_module.verify_and_parse_csr_der(DEPUTY_CSR_DER)
        serial = cert_request_module.generate_serial()
        now = root_not_before + 86_400
        days = cert_request_module.DEPUTY_DAYS
        tbs_bytes = cert_request_module.build_deputy_tbs_v2(root_cert_der, DEPUTY_CSR_DER, ChainKind.TESTNET, now, days, serial)

        public_key, signature = sign_with_root_ca(seed.seed_bytes, ChainKind.TESTNET, tbs_bytes, confirmed=True)

        certificate = sevenf_views.SevenFSignedCertificate(
            public_key=public_key, signature=signature, tbs_bytes=tbs_bytes, root_cert_der=root_cert_der,
        )

        view = sevenf_views.SevenFExportDeputyCertQRView(certificate=certificate)
        captured = {}

        def fake_run_screen(screen_cls, **kwargs):
            captured["qr_encoder"] = kwargs["qr_encoder"]

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", fake_run_screen)
            destination = view.run()

        encoder = captured["qr_encoder"]
        assert encoder.file_type == "B"

        d = DecodeQR()
        while True:
            status = d.add_data(encoder.next_part())
            if status == DecodeQRStatus.COMPLETE:
                break
        cert_der = d.decoder.get_data()
        parsed = cert_request_module.parse_root_certificate_der(cert_der)
        assert parsed.subject_vk == deputy_csr.subject_vk
        assert parsed.chain_kind == ChainKind.TESTNET
        assert parsed.not_before == now

        assert destination.View_cls == MainMenuView


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
        """ End-to-end from a real BBQr-encoded genesis-config JSON file --
            the actual coordinator artifact (sf-root prepare-genesis), not a
            hand-built canonical_bytes handoff -- through the actual
            scan/decode machinery into the review flow's real entry point.
            Confirms the view builds canonical_bytes from the scanned JSON
            internally and that those bytes match calling
            build_canonical_bytes() directly with the same fields. """
        seed = self.seed_fixture()
        genesis_json = _sample_genesis_config_json()
        expected_canonical_bytes = _sample_canonical_bytes()

        captured = {}

        def capture_state(view):
            captured["state"] = view.state

        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF_SCAN_GENESIS_CONFIG),
                FlowStep(
                    sevenf_views.SevenFScanGenesisConfigView,
                    before_run=_load_genesis_config_into_decoder(genesis_json),
                    screen_return_value=0,
                ),
                FlowStep(sevenf_views.SevenFGenesisReviewStartView, is_redirect=True),
                FlowStep(sevenf_views.SevenFGenesisReviewFieldView, before_run=capture_state, screen_return_value=0),
            ],
            initial_destination_view_args=dict(seed=seed),
        )

        state = captured["state"]
        assert state.seed is seed
        assert state.canonical_bytes == expected_canonical_bytes
        assert state.chain_kind == ChainKind.TESTNET


    def test_scan_genesis_config_view_rejects_raw_canonical_bytes_no_longer_accepted(self):
        """ Regression test for the genesis-wire-envelope fix: the OLD
            format this view used to accept directly (raw canonical_bytes,
            no JSON wrapper) must now be REFUSED, not silently accepted --
            confirms this is an intentional behavior change with real
            coverage, not just an untested assumption. """
        seed = self.seed_fixture()
        raw_canonical_bytes = _sample_canonical_bytes()

        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF_SCAN_GENESIS_CONFIG),
                FlowStep(
                    sevenf_views.SevenFScanGenesisConfigView,
                    before_run=_load_genesis_config_into_decoder(raw_canonical_bytes),
                    screen_return_value=0,
                ),
                FlowStep(sevenf_views.SevenFUnsupportedArtefactView, screen_return_value=0),
                FlowStep(MainMenuView),
            ],
            initial_destination_view_args=dict(seed=seed),
        )


    def test_scan_genesis_config_view_rejects_a_payload_that_doesnt_parse(self):
        """ A BBQr payload that decodes fine at the transport layer but isn't
            a real genesis-config (not valid JSON) must be refused with a
            clear reason, not crash or silently proceed into the review flow
            with garbage fields -- confirms SevenFScanGenesisConfigView's own
            self-validation, not just genesis_config.parse_genesis_config_json()
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
        view takes its fields via view_args, not a controller-global flow
        state, specifically so it doesn't need one to be tested or
        reused. """
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
        assert captured["is_warning"] is False
        assert captured["warning_detail"] == ""


    def test_a_warning_field_is_preserved_through_chunking_and_passed_to_the_screen(self):
        """ Regression test for 7f-review-enrollment-fingerprint-no-visual-
            distinction: the chunk-rebuilding loop used to drop
            is_warning/warning_detail entirely (it only copied label/value
            into a fresh ReviewField), which would have silently defeated
            the fix even after cert_request.py started setting the flag. """
        from seedsigner.chains.base import ReviewField
        fields = [
            ReviewField(
                label="Subject key id", value="abc123", is_warning=True,
                warning_detail="Compare this against your recorded enrollment fingerprint before continuing.",
            ),
            ReviewField(label="Chain", value="testnet"),
        ]
        view = sevenf_views.SevenFCertRequestReviewFieldView(
            review_fields=fields,
            page_title="Review Root Certificate",
            confirmed_destination=_DummyConfirmedDestination,
        )
        assert view.chunks[0].is_warning is True
        assert view.chunks[0].warning_detail == "Compare this against your recorded enrollment fingerprint before continuing."
        assert view.chunks[1].is_warning is False

        captured = {}

        def fake_run_screen(screen_cls, **kwargs):
            captured.update(kwargs)
            return 0

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", fake_run_screen)
            view.run()

        assert captured["is_warning"] is True
        assert captured["warning_detail"] == "Compare this against your recorded enrollment fingerprint before continuing."


    def test_raises_if_constructed_with_an_out_of_range_page_num(self):
        with pytest.raises(Exception):
            sevenf_views.SevenFCertRequestReviewFieldView(
                review_fields=self._fields(),
                page_title="Review Root Certificate",
                confirmed_destination=_DummyConfirmedDestination,
                page_num=99,
            )



def _sample_devfund_canonical_bytes() -> bytes:
    from seedsigner.models.sevenf.devfund_config import DevfundRecipient
    from seedsigner.models.sevenf.devfund_config import build_canonical_bytes as build_devfund_canonical_bytes
    recipient = DevfundRecipient(DevfundRecipient.ADDRESS, "t1devfundexampleaddress")
    return build_devfund_canonical_bytes(ChainKind.TESTNET, recipient, 12_345, 1_790_555_198)


class TestSevenFDevFundConfigSigningFlow(FlowTest):
    """ Mirrors TestSevenFGenesisReviewFlow's own shape exactly: scan ->
        no-blind-signing review -> confirm+sign -> export -> Home. Simpler
        than genesis: only one export artifact (the signature), no
        export-menu loop. """
    def setup_method(self):
        super().setup_method()
        self.controller.active_chain_id = "sevenf"


    def seed_fixture(self) -> Seed:
        seed = Seed(mnemonic=["abandon"] * 11 + ["about"], wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)
        self.controller.storage.seeds.append(seed)
        return seed


    def test_seed_options_view_offers_the_devfund_button_only_in_sevenf_mode(self):
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
            is_present = seed_views.SeedOptionsView.SEVENF_SCAN_DEVFUND_CONFIG in captured["button_data"]
            assert is_present == should_appear, f"active_chain_id={active_chain_id!r}: expected present={should_appear}, got {is_present}"


    def test_seed_options_view_routes_to_scan_devfund_config_view(self):
        seed = self.seed_fixture()
        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF_SCAN_DEVFUND_CONFIG),
                FlowStep(sevenf_views.SevenFScanDevFundConfigView),
            ],
            initial_destination_view_args=dict(seed=seed),
        )


    def test_full_flow_with_real_devfund_key_signs_and_exports(self):
        """ End-to-end from a real BBQr-encoded devfund-config, through
            scan -> review (5 fields, v2 schema) -> confirm+sign -> signed -> export
            -> Home. Confirms the real public_key/signature match a direct
            derive_root_ceremony_keys()/sign_with_devfund() call -- not a
            placeholder. BUG FIX, 2026-10-03 (R27): this used to also assert
            the devfund key differs from the Root key -- that was the bug
            (see root_ceremony.py's own BUG FIX note); devfund now signs
            with the SAME key as Root, confirmed against 7fchain's real
            sf-root.rs. """
        seed = self.seed_fixture()
        canonical_bytes = _sample_devfund_canonical_bytes()
        keys = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.TESTNET)

        captured = {}

        def capture_before_home(view):
            captured["public_key"] = view.artifact.public_key
            captured["signature"] = view.artifact.signature

        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF_SCAN_DEVFUND_CONFIG),
                FlowStep(
                    sevenf_views.SevenFScanDevFundConfigView,
                    before_run=_load_genesis_config_into_decoder(canonical_bytes),
                    screen_return_value=0,
                ),
                FlowStep(sevenf_views.SevenFCertRequestReviewFieldView, screen_return_value=0),  # Chain
                FlowStep(sevenf_views.SevenFCertRequestReviewFieldView, screen_return_value=0),  # Recipient kind
                FlowStep(sevenf_views.SevenFCertRequestReviewFieldView, screen_return_value=0),  # Recipient
                FlowStep(sevenf_views.SevenFCertRequestReviewFieldView, screen_return_value=0),  # Effective block
                FlowStep(sevenf_views.SevenFCertRequestReviewFieldView, screen_return_value=0),  # Timestamp (final)
                FlowStep(sevenf_views.SevenFConfirmSignDevFundView, screen_return_value=0),  # "Sign"
                FlowStep(sevenf_views.SevenFDevFundConfigSignedView, before_run=capture_before_home, screen_return_value=0),  # "OK"
                FlowStep(sevenf_views.SevenFExportSignedDevFundConfigQRView, screen_return_value=0),
                FlowStep(MainMenuView),
            ],
            initial_destination_view_args=dict(seed=seed),
        )

        assert captured["public_key"] == keys.devfund.public_key
        assert captured["public_key"] == keys.root_ca.public_key
        assert len(captured["signature"]) == 3309


    def test_signed_result_matches_direct_sign_with_devfund_call(self):
        """ Unit-level cross-check: SevenFConfirmSignDevFundView's output
            must match a direct devfund_config.parse_canonical_bytes() +
            sign_with_devfund() call over the same bytes. """
        from seedsigner.models.sevenf.devfund_config import parse_canonical_bytes as parse_devfund_canonical_bytes
        from seedsigner.models.sevenf.root_ceremony import sign_with_devfund

        seed = self.seed_fixture()
        canonical_bytes = _sample_devfund_canonical_bytes()
        fields = parse_devfund_canonical_bytes(canonical_bytes)

        view = sevenf_views.SevenFConfirmSignDevFundView(seed=seed, chain_kind=fields.network, tbs_bytes=canonical_bytes)
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: 0)
            destination = view.run()

        assert destination.View_cls == sevenf_views.SevenFDevFundConfigSignedView
        artifact = destination.view_args["artifact"]
        keys = derive_root_ceremony_keys(seed.seed_bytes, fields.network)
        expected_pk, expected_sig = sign_with_devfund(seed.seed_bytes, fields.network, canonical_bytes, confirmed=True)
        assert artifact.public_key == keys.devfund.public_key == expected_pk
        assert len(artifact.signature) == len(expected_sig) == 3309


    def test_confirm_sign_screen_labels_the_devfund_key_not_root_ca(self):
        """ Regression test for 7f-review-devfund-confirm-screen-wrong-label
            (found by the full-project adversarial review's UI/UX
            dimension, 2026-10-03): the confirm screen used to hardcode
            "signing as Root CA for" even when signing with the devfund key
            -- the one screen the hardware walkthrough singles out as the
            flagship wrong-key check (Step 6), undermined by its own label
            contradicting what it was checking for. """
        from seedsigner.models.sevenf.devfund_config import parse_canonical_bytes as parse_devfund_canonical_bytes

        seed = self.seed_fixture()
        canonical_bytes = _sample_devfund_canonical_bytes()
        fields = parse_devfund_canonical_bytes(canonical_bytes)

        view = sevenf_views.SevenFConfirmSignDevFundView(seed=seed, chain_kind=fields.network, tbs_bytes=canonical_bytes)
        captured = {}

        def fake_run_screen(screen_cls, **kwargs):
            captured["signing_role_label"] = kwargs.get("signing_role_label")
            return 0

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", fake_run_screen)
            view.run()

        assert captured["signing_role_label"] == "devfund key"


    def test_scan_rejects_a_payload_that_isnt_valid_devfund_config(self):
        seed = self.seed_fixture()
        garbage = b"not a devfund config at all, but still valid BBQr transport bytes"

        self.run_sequence(
            [
                FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.SEVENF_SCAN_DEVFUND_CONFIG),
                FlowStep(
                    sevenf_views.SevenFScanDevFundConfigView,
                    before_run=_load_genesis_config_into_decoder(garbage),
                    screen_return_value=0,
                ),
                FlowStep(sevenf_views.SevenFUnsupportedArtefactView, screen_return_value=0),
            ],
            initial_destination_view_args=dict(seed=seed),
        )


    def test_back_button_on_confirm_sign_screen_returns_to_back_stack_without_signing(self):
        seed = self.seed_fixture()
        canonical_bytes = _sample_devfund_canonical_bytes()
        from seedsigner.models.sevenf.devfund_config import parse_canonical_bytes as parse_devfund_canonical_bytes
        fields = parse_devfund_canonical_bytes(canonical_bytes)

        view = sevenf_views.SevenFConfirmSignDevFundView(seed=seed, chain_kind=fields.network, tbs_bytes=canonical_bytes)
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: RET_CODE__BACK_BUTTON)
            destination = view.run()

        from seedsigner.views.view import BackStackView
        assert destination.View_cls == BackStackView


    def test_confirm_sign_view_shows_the_real_devfund_address(self):
        """ BUG FIX, 2026-10-03 (R27): this used to also assert the shown
            address differs from the Root CA address -- that was the bug
            (see root_ceremony.py's own BUG FIX note); devfund is now the
            same key/address as Root CA. """
        from seedsigner.models.sevenf.devfund_config import parse_canonical_bytes as parse_devfund_canonical_bytes

        seed = self.seed_fixture()
        canonical_bytes = _sample_devfund_canonical_bytes()
        fields = parse_devfund_canonical_bytes(canonical_bytes)

        view = sevenf_views.SevenFConfirmSignDevFundView(seed=seed, chain_kind=fields.network, tbs_bytes=canonical_bytes)
        keys = derive_root_ceremony_keys(seed.seed_bytes, ChainKind.TESTNET)
        assert view.devfund_address == keys.devfund.address
        assert view.devfund_address == keys.root_ca.address
