"""
    Story port-sign-refusals (H1, H2, M2, plan-stage L-1): the device refuses
    what sf-wallet-gov refuses before it signs, in the same order, and its
    review shows what sf-wallet-gov's review shows.

    sf-wallet-gov sign_ops.rs (7fchain 06a47ba):
    - validate_genesis: version, scheme, timestamp (the parser refuses these),
      then "this Root has already signed this definition. Nothing to do",
      then non-default consensus unless --accept-nondefault-consensus.
    - validate_devfund: ... then "already signed". Another Root's signature,
      or a keyless record (signer_vk ""), never blocks.
    - The review prints "signatures so far N".
"""
import json

import pytest

# Must import test base before the Controller (see base.py's own comment).
from base import FlowTest

from seedsigner.models.seed import Seed
from seedsigner.models.sevenf import config_json, devfund_config, genesis_config
from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.models.sevenf.root_ceremony import derive_root_ceremony_keys, seed_for_7f
from seedsigner.views import sevenf_views
from seedsigner.views.view import BackStackView

ABANDON_ART = ["abandon"] * 23 + ["art"]
DEFAULTS = {"target_block_time_secs": 420, "difficulty_adjustment_interval_blocks": 1500, "blocks_per_decay_period": 70000}


def _root_vk_hex(index=0) -> str:
    return derive_root_ceremony_keys(seed_for_7f(Seed(ABANDON_ART)), ChainKind.TESTNET, index=index).root_ca.public_key.hex()


def _genesis(signatures=(), consensus=None) -> bytes:
    return json.dumps({
        "version": 1, "chain_kind": "testnet", "timestamp": 1791425505, "message": "m",
        "derivation_scheme": "7fchain.ml-dsa-keygen.v1", "consensus": consensus or DEFAULTS,
        "signatures": [{"signer_vk": vk, "sig": "00"} for vk in signatures],
    }).encode()


def _devfund(signatures=()) -> bytes:
    return json.dumps({
        "version": 2, "network": "testnet", "recipient": {"kind": "multisig", "commitment": "ab" * 64},
        "effective_block": 0, "timestamp": 1791425505,
        "signatures": [{"signer_vk": vk, "sig": "00"} for vk in signatures],
    }).encode()


# --- model -------------------------------------------------------------------------

@pytest.mark.parametrize("parse,doc", [
    (genesis_config.parse_genesis_config_json, _genesis),
    (devfund_config.parse_devfund_config_json, _devfund),
])
def test_already_signed_is_this_keys_vk_ignoring_case(parse, doc):
    mine = _root_vk_hex()
    for signatures, expected in [
        ((mine.upper(),), True),
        ((mine,), True),
        (("ddeeff",), False),          # another Root: the normal case
        (("",), False),                # a keyless record cannot be attributed
        ((), False),
    ]:
        fields = parse(doc(signatures))
        assert config_json.already_signed_by(fields.signer_vks, bytes.fromhex(mine)) is expected, signatures


def test_signer_vks_do_not_change_what_is_compared_or_signed():
    a = devfund_config.parse_devfund_config_json(_devfund(("ddeeff",)))
    b = devfund_config.parse_devfund_config_json(_devfund())
    assert a == b                       # the scan view compares JSON fields with the canonical parse
    assert a.signer_vks == ("ddeeff",)


def test_nondefault_consensus_lists_each_value_and_its_default():
    fields = genesis_config.parse_genesis_config_json(_genesis(consensus={**DEFAULTS, "target_block_time_secs": 30}))
    assert genesis_config.nondefault_consensus(fields) == [("Target block time", "30s", "420s")]   # with units, as the review
    assert genesis_config.nondefault_consensus(genesis_config.parse_genesis_config_json(_genesis())) == []


@pytest.mark.parametrize("module,doc", [(genesis_config, _genesis), (devfund_config, _devfund)])
def test_review_shows_signatures_so_far(module, doc):
    parse = module.parse_genesis_config_json if module is genesis_config else module.parse_devfund_config_json
    fields = parse(doc(("ddeeff", "")))
    shown = {f.label: f.value for f in module.review_fields(fields, signatures_so_far=len(fields.signer_vks))}
    assert shown["Signatures so far"] == "2"


# --- views: genesis ------------------------------------------------------------------

class TestGenesisRefusals(FlowTest):
    def setup_method(self):
        super().setup_method()
        self.controller.active_chain_id = "sevenf"
        self.seed = Seed(ABANDON_ART)
        self.controller.storage.seeds.append(self.seed)

    def _start(self, payload: bytes, **extra):
        fields = genesis_config.parse_genesis_config_json(payload)
        canonical = genesis_config.build_canonical_bytes(fields.chain_kind, fields.timestamp, fields.message, fields.consensus)
        return dict(seed=self.seed, canonical_bytes=canonical, key_index=0, signer_vks=fields.signer_vks, **extra)

    def test_already_signed_by_this_key_is_refused_before_review(self):
        view = sevenf_views.SevenFGenesisReviewStartView(**self._start(_genesis((_root_vk_hex().upper(),))))
        assert view.run().View_cls is sevenf_views.SevenFAlreadySignedView

    def test_signed_by_this_key_at_another_index_is_not_refused(self):
        view = sevenf_views.SevenFGenesisReviewStartView(**self._start(_genesis((_root_vk_hex(index=1),))))
        assert view.run().View_cls is sevenf_views.SevenFGenesisReviewFieldView

    def test_nondefault_consensus_is_refused_unless_accepted(self):
        odd = _genesis(consensus={**DEFAULTS, "blocks_per_decay_period": 5})
        destination = sevenf_views.SevenFGenesisReviewStartView(**self._start(odd)).run()
        assert destination.View_cls is sevenf_views.SevenFNonDefaultConsensusView
        accepted = sevenf_views.SevenFGenesisReviewStartView(**self._start(odd, accept_nondefault_consensus=True)).run()
        assert accepted.View_cls is sevenf_views.SevenFGenesisReviewFieldView

    def test_already_signed_comes_before_consensus(self):
        """ sf-wallet-gov's order: already-signed, then consensus. """
        both = _genesis((_root_vk_hex(),), consensus={**DEFAULTS, "blocks_per_decay_period": 5})
        assert sevenf_views.SevenFGenesisReviewStartView(**self._start(both)).run().View_cls is sevenf_views.SevenFAlreadySignedView

    def test_the_consensus_screen_defaults_to_refusing_and_names_each_value(self):
        odd = genesis_config.parse_genesis_config_json(_genesis(consensus={**DEFAULTS, "target_block_time_secs": 30}))
        view = sevenf_views.SevenFNonDefaultConsensusView(
            nondefault=genesis_config.nondefault_consensus(odd), review_start_args=self._start(_genesis()))
        captured = {}

        def fake_run_screen(screen_cls, **kwargs):
            captured.update(kwargs)
            return 0                                      # the first button

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", fake_run_screen)
            destination = view.run()
        assert "30" in captured["text"] and "420" in captured["text"]
        assert [b.button_label for b in captured["button_data"]][0] == "Don't sign"
        assert destination.View_cls is BackStackView

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda screen_cls, **kw: 1)   # "Sign anyway (coordinator asked)"
            destination = view.run()
        assert destination.View_cls is sevenf_views.SevenFGenesisReviewStartView
        assert destination.view_args["accept_nondefault_consensus"] is True

    def test_the_review_shows_signatures_so_far(self):
        view = sevenf_views.SevenFGenesisReviewStartView(**self._start(_genesis(("ddeeff", "aabb"))))
        assert {f.label: f.value for f in view.state.review_fields}["Signatures so far"] == "2"


# --- views: dev fund ---------------------------------------------------------------------

class TestDevfundRefusals(FlowTest):
    def setup_method(self):
        super().setup_method()
        self.controller.active_chain_id = "sevenf"
        self.seed = Seed(ABANDON_ART)

    def _start(self, payload: bytes):
        fields = devfund_config.parse_devfund_config_json(payload)
        canonical = devfund_config.build_canonical_bytes(fields.network, fields.recipient, fields.effective_block, fields.timestamp)
        return dict(seed=self.seed, chain_kind=fields.network, canonical_bytes=canonical,
                    review_fields=devfund_config.review_fields(fields, canonical_bytes=canonical, signatures_so_far=len(fields.signer_vks)),
                    key_index=0, signer_vks=fields.signer_vks)

    def test_already_signed_by_this_key_is_refused_before_review(self):
        view = sevenf_views.SevenFDevFundReviewStartView(**self._start(_devfund((_root_vk_hex(),))))
        assert view.run().View_cls is sevenf_views.SevenFAlreadySignedView

    def test_another_roots_signature_does_not_block(self):
        view = sevenf_views.SevenFDevFundReviewStartView(**self._start(_devfund(("ddeeff", ""))))
        assert view.run().View_cls is sevenf_views.SevenFCertRequestReviewFieldView


def test_the_already_signed_screen_says_nothing_to_do():
    view = sevenf_views.SevenFAlreadySignedView(what="genesis definition", subject_key_id="591c 5119")
    captured = {}
    with pytest.MonkeyPatch().context() as mp:
        mp.setattr(view, "run_screen", lambda screen_cls, **kw: captured.update(kw) or 0)
        destination = view.run()
    assert "already signed" in captured["text"] and "Nothing to do" in captured["text"]
    assert destination.View_cls is BackStackView


# --- views: leaving a refusal (execution-stage review 2026-10-08) -------------------
# Through the Controller's real back stack, from the seed menu: a refusal's OK
# (or "Don't sign") must lead back to the seed menu. It used to land on the
# review-start redirect, which showed the same refusal again, forever; on a
# non-default consensus the only way out was to sign.

from unittest.mock import MagicMock

from base import FlowStep
from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
from seedsigner.views import seed_views
from seedsigner.views.view import MainMenuView


class TestLeavingARefusal(FlowTest):
    def setup_method(self):
        super().setup_method()
        self.controller.active_chain_id = "sevenf"
        self.seed = Seed(ABANDON_ART)
        self.controller.storage.seeds.append(self.seed)

    def _scan_steps(self, payload: bytes, menu_option, scan_view):
        def fake_decoder(view):
            decoder = MagicMock(is_complete=True, is_sevenf_bbqr=True)
            decoder.get_sevenf_bbqr_data.return_value = payload
            view.decoder = decoder
        # From the main menu, so the seed menu is on the back stack (the test
        # harness never pushes the sequence's first view).
        return [
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SEEDS),
            FlowStep(seed_views.SeedsMenuView, screen_return_value=0),
            FlowStep(seed_views.SeedOptionsView, button_data_selection=menu_option),
            FlowStep(scan_view, before_run=fake_decoder, screen_return_value=0),
            FlowStep(sevenf_views.SevenFSelectKeyIndexView, screen_return_value=0),
        ]

    def _genesis_steps(self, payload: bytes):
        return self._scan_steps(payload, seed_views.SeedOptionsView.SEVENF_SCAN_GENESIS_CONFIG,
                                sevenf_views.SevenFScanGenesisConfigView) + [
            FlowStep(sevenf_views.SevenFGenesisReviewStartView, is_redirect=True)]

    def test_already_signed_ok_returns_to_the_seed_menu(self):
        self.run_sequence(self._genesis_steps(_genesis((_root_vk_hex(),))) + [
            FlowStep(sevenf_views.SevenFAlreadySignedView, screen_return_value=0),
            FlowStep(seed_views.SeedOptionsView),
        ]
        )

    def test_dont_sign_returns_to_the_seed_menu(self):
        odd = _genesis(consensus={**DEFAULTS, "blocks_per_decay_period": 5})
        self.run_sequence(self._genesis_steps(odd) + [
            FlowStep(sevenf_views.SevenFNonDefaultConsensusView, screen_return_value=0),   # Don't sign
            FlowStep(seed_views.SeedOptionsView),
        ]
        )

    def test_back_from_the_review_after_sign_anyway_returns_to_the_seed_menu(self):
        odd = _genesis(consensus={**DEFAULTS, "blocks_per_decay_period": 5})
        self.run_sequence(self._genesis_steps(odd) + [
            FlowStep(sevenf_views.SevenFNonDefaultConsensusView, screen_return_value=1),   # Sign anyway
            FlowStep(sevenf_views.SevenFGenesisReviewStartView, is_redirect=True),
            FlowStep(sevenf_views.SevenFGenesisReviewFieldView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(seed_views.SeedOptionsView),
        ]
        )

    def test_devfund_already_signed_ok_returns_to_the_seed_menu(self):
        self.run_sequence(self._scan_steps(_devfund((_root_vk_hex(),)), seed_views.SeedOptionsView.SEVENF_SCAN_DEVFUND_CONFIG,
                                           sevenf_views.SevenFScanDevFundConfigView) + [
            FlowStep(sevenf_views.SevenFDevFundReviewStartView, is_redirect=True),
            FlowStep(sevenf_views.SevenFAlreadySignedView, screen_return_value=0),
            FlowStep(seed_views.SeedOptionsView),
        ]
        )


# --- views: a failed signature is a refusal, not a crash (execution-stage review) --

def _confirm_views(seed):
    return [
        sevenf_views.SevenFConfirmSignRootCertView(seed=seed, chain_kind=ChainKind.TESTNET, tbs_bytes=b"x", key_index=0),
        sevenf_views.SevenFConfirmSignDevFundView(seed=seed, chain_kind=ChainKind.TESTNET, tbs_bytes=b"x", key_index=0),
        sevenf_views.SevenFConfirmSignView(state=sevenf_views.SevenFGenesisCeremonyState(
            seed=seed, chain_kind=ChainKind.TESTNET, canonical_bytes=b"x", review_fields=[], key_index=0)),
    ]


@pytest.mark.parametrize("which", range(3))
def test_a_signature_that_fails_its_self_check_is_refused_on_screen(which):
    from seedsigner.models.sevenf import root_ceremony
    from seedsigner.models.sevenf.mldsa import MlDsaError
    view = _confirm_views(Seed(ABANDON_ART))[which]

    def failing_sign(*a, **kw):
        raise MlDsaError(-28, "derive_and_sign")

    with pytest.MonkeyPatch().context() as mp:
        mp.setattr(view, "run_screen", lambda *a, **kw: 0)          # "Sign"
        mp.setattr(root_ceremony, "sign_with_root_ca", failing_sign)
        destination = view.run()
    assert destination.View_cls is sevenf_views.SevenFUnsupportedArtefactView
    assert "did not verify" in destination.view_args["reason"]
    assert "Nothing was exported" in destination.view_args["reason"]


def test_the_library_error_names_its_code():
    from seedsigner.models.sevenf.mldsa import MlDsaError
    assert "SIGNATURE_SELF_CHECK_FAILED" in str(MlDsaError(-28, "derive_and_sign"))
