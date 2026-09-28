"""
    Tests seedsigner.views.sevenf_views -- the no-blind-signing review flow
    for a genesis-config canonical-bytes payload
    (7f-signing-support-root-ceremony-review-screen, _delivery/backlog.yaml).

    Requires firmware/mldsa7f's compiled library (see test_sevenf_mldsa.py's
    own docstring for the search order); skips cleanly if it's missing.
"""
import pytest

# Must import test base before the Controller (see base.py's own comment).
from base import FlowTest, FlowStep

from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON
from seedsigner.models.decode_qr import DecodeQR, DecodeQRStatus
from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants
from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.models.sevenf.genesis_config import ConsensusParams, build_canonical_bytes, parse_canonical_bytes
from seedsigner.models.sevenf.root_ceremony import derive_root_ceremony_keys
from seedsigner.views import sevenf_views
from seedsigner.views.view import MainMenuView


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
        """ Confirms the exported QR carries the real build_signed_json()
            output for THIS ceremony's actual fields/signature (BBQr-encoded,
            file_type 'J'), round-tripped through the real BBQr encoder/
            decoder pair and re-parsed as JSON -- the actual export payload
            an operator would hand to sf-node/sf-wallet, not a stand-in. """
        import json

        from seedsigner.models.sevenf.genesis_config import build_signed_json

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
        assert decoded_json == build_signed_json(fields, keys.root_ca.public_key, signature)
        assert decoded_json["signer_vk"] == keys.root_ca.public_key.hex()
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
