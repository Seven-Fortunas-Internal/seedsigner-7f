"""
    Tests the encrypted seed-file backup/restore UI flow (requirements doc
    section 5.7). Backs 7f-signing-support-encrypted-seed-file-backup.

    Chain-agnostic by design (Gate-1 decision, 2026-09-29): lives in
    SeedBackupView/LoadSeedView like every other chain-agnostic seed
    backup/load option, not gated on active_chain_id.

    Requires firmware/mldsa7f's compiled library (the shared Argon2id+
    AES-256-GCM primitive goes through the real FFI boundary) -- skips
    cleanly if it's missing, same convention as test_sevenf_mldsa.py.
"""
import pytest

# Must import test base before the Controller
from base import FlowTest, FlowStep

from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON
from seedsigner.models.seed import ElectrumSeed, Seed
from seedsigner.models.settings import SettingsConstants
from seedsigner.models.sevenf import mldsa
from seedsigner.views.view import MainMenuView
from seedsigner.views import seed_views


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

from seedsigner.models import seed_backup  # noqa: E402


def _seed(passphrase: str = "") -> Seed:
    return Seed(mnemonic=["abandon"] * 11 + ["about"], passphrase=passphrase, wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)


class TestSeedBackupToSDFlow(FlowTest):
    @pytest.fixture(autouse=True)
    def _isolated_backup_path(self, tmp_path, monkeypatch):
        path = str(tmp_path / "seedsigner-seed-backup.enc")
        monkeypatch.setattr(seed_backup, "backup_path", lambda: path)
        self._backup_path = path


    def test_backup_button_hidden_for_electrum_seed(self):
        seed = ElectrumSeed(mnemonic="regular reject rare profit once math fringe chase until ketchup century escape".split())
        view = seed_views.SeedBackupView(seed=seed)
        captured = {}

        def fake_run_screen(screen_cls, button_data=None, **kwargs):
            captured["button_data"] = button_data
            return RET_CODE__BACK_BUTTON

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", fake_run_screen)
            view.run()
        assert seed_views.SeedBackupView.BACKUP_TO_SD not in captured["button_data"]


    def test_confirm_view_refuses_when_no_sd_card(self):
        """ Unit-level, like several other back-button tests in this
            codebase: asserts the routing decision itself
            (Destination(BackStackView)), not where BackStackView happens
            to resolve to -- that depends on back_stack depth accumulated
            before this View, which a from-scratch FlowTest sequence
            starting mid-flow does not have. """
        self.mock_microsd.is_inserted = False
        seed = _seed()
        view = seed_views.SeedBackupToSDConfirmView(seed=seed)
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: 0)
            destination = view.run()
        from seedsigner.views.view import BackStackView
        assert destination.View_cls == BackStackView
        assert not seed_backup.backup_exists()


    def test_confirm_view_back_button_writes_nothing(self):
        seed = _seed()
        view = seed_views.SeedBackupToSDConfirmView(seed=seed)
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: RET_CODE__BACK_BUTTON)
            destination = view.run()
        from seedsigner.views.view import BackStackView
        assert destination.View_cls == BackStackView
        assert not seed_backup.backup_exists()


    def test_full_flow_writes_a_real_decryptable_backup(self):
        seed = _seed()
        self.run_sequence(
            [
                FlowStep(seed_views.SeedBackupView, button_data_selection=seed_views.SeedBackupView.BACKUP_TO_SD),
                FlowStep(seed_views.SeedBackupToSDConfirmView, screen_return_value=0),
                FlowStep(seed_views.SeedBackupEnterPasswordView, screen_return_value=dict(passphrase="an independent password")),
                FlowStep(seed_views.SeedBackupEnterPasswordView, screen_return_value=dict(passphrase="an independent password")),
                FlowStep(seed_views.SeedBackupWrittenView, screen_return_value=0),
                FlowStep(seed_views.SeedOptionsView, screen_return_value=RET_CODE__BACK_BUTTON),
                FlowStep(MainMenuView),
            ],
            initial_destination_view_args=dict(seed=seed),
        )
        restored = seed_backup.read_backup("an independent password")
        assert restored.seed.mnemonic_list == seed.mnemonic_list


    def test_empty_password_requires_explicit_confirmation_before_proceeding(self):
        """ Unit-level: this one View.run() call makes two DIFFERENT
            run_screen calls (the password entry, then the "use empty
            password?" confirmation), which the FlowTest harness's
            one-return-value-per-step model can't represent -- tested
            directly instead, with a stateful mock returning each call's
            own value in order. """
        seed = _seed()
        view = seed_views.SeedBackupEnterPasswordView(seed=seed)
        responses = iter([dict(passphrase=""), 0])  # empty entry, then "Use empty password"
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: next(responses))
            destination = view.run()
        assert destination.View_cls == seed_views.SeedBackupEnterPasswordView
        assert destination.view_args.get("first_password") == ""


    def test_empty_password_go_back_does_not_proceed(self):
        seed = _seed()
        view = seed_views.SeedBackupEnterPasswordView(seed=seed)
        responses = iter([dict(passphrase=""), 1])  # empty entry, then "Go back"
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: next(responses))
            destination = view.run()
        assert destination.View_cls == seed_views.SeedBackupEnterPasswordView
        assert destination.view_args.get("first_password") is None


    def test_full_flow_with_confirmed_empty_password_writes_a_backup(self):
        seed = _seed()
        self.run_sequence(
            [
                FlowStep(seed_views.SeedBackupView, button_data_selection=seed_views.SeedBackupView.BACKUP_TO_SD),
                FlowStep(seed_views.SeedBackupToSDConfirmView, screen_return_value=0),
                # Skips straight to the confirm step -- the empty/confirm
                # transition itself is covered by the two unit tests above.
                FlowStep(seed_views.SeedBackupEnterPasswordView, screen_return_value=dict(passphrase=""), before_run=lambda v: setattr(v, "first_password", "")),
                FlowStep(seed_views.SeedBackupWrittenView, screen_return_value=0),
                FlowStep(seed_views.SeedOptionsView, screen_return_value=RET_CODE__BACK_BUTTON),
                FlowStep(MainMenuView),
            ],
            initial_destination_view_args=dict(seed=seed),
        )
        assert seed_backup.backup_exists()


    def test_mismatched_confirmation_password_retries(self):
        seed = _seed()
        self.run_sequence(
            [
                FlowStep(seed_views.SeedBackupView, button_data_selection=seed_views.SeedBackupView.BACKUP_TO_SD),
                FlowStep(seed_views.SeedBackupToSDConfirmView, screen_return_value=0),
                FlowStep(seed_views.SeedBackupEnterPasswordView, screen_return_value=dict(passphrase="password one")),
                # This step's own run() call shows the "Try Again" error
                # screen INLINE (same run_screen mock return, unused) before
                # returning to a fresh first-entry -- not a separate FlowStep.
                FlowStep(seed_views.SeedBackupEnterPasswordView, screen_return_value=dict(passphrase="password two")),
                FlowStep(seed_views.SeedBackupEnterPasswordView, screen_return_value=dict(passphrase="password one")),
                FlowStep(seed_views.SeedBackupEnterPasswordView, screen_return_value=dict(passphrase="password one")),
                FlowStep(seed_views.SeedBackupWrittenView, screen_return_value=0),
                FlowStep(seed_views.SeedOptionsView, screen_return_value=RET_CODE__BACK_BUTTON),
                FlowStep(MainMenuView),
            ],
            initial_destination_view_args=dict(seed=seed),
        )
        restored = seed_backup.read_backup("password one")
        assert restored.seed.mnemonic_list == seed.mnemonic_list


    def test_r5b_password_reusing_a_seed_word_is_rejected_then_retried(self):
        """ R5b, non-negotiable: enforced here at the UI layer too (defense
            in depth on top of write_backup()'s own internal check). """
        seed = _seed()  # "abandon" x11 + "about"
        self.run_sequence(
            [
                FlowStep(seed_views.SeedBackupView, button_data_selection=seed_views.SeedBackupView.BACKUP_TO_SD),
                FlowStep(seed_views.SeedBackupToSDConfirmView, screen_return_value=0),
                FlowStep(seed_views.SeedBackupEnterPasswordView, screen_return_value=dict(passphrase="abandon")),
                # This step's own run() call shows the "Try Again" error
                # screen INLINE before returning to a fresh first-entry.
                FlowStep(seed_views.SeedBackupEnterPasswordView, screen_return_value=dict(passphrase="abandon")),
                FlowStep(seed_views.SeedBackupEnterPasswordView, screen_return_value=dict(passphrase="a real independent password")),
                FlowStep(seed_views.SeedBackupEnterPasswordView, screen_return_value=dict(passphrase="a real independent password")),
                FlowStep(seed_views.SeedBackupWrittenView, screen_return_value=0),
                FlowStep(seed_views.SeedOptionsView, screen_return_value=RET_CODE__BACK_BUTTON),
                FlowStep(MainMenuView),
            ],
            initial_destination_view_args=dict(seed=seed),
        )


class TestSeedBackupDeleteAndRestoreFlow(FlowTest):
    @pytest.fixture(autouse=True)
    def _isolated_backup_path(self, tmp_path, monkeypatch):
        path = str(tmp_path / "seedsigner-seed-backup.enc")
        monkeypatch.setattr(seed_backup, "backup_path", lambda: path)
        self._backup_path = path


    def test_load_seed_view_hides_restore_and_delete_when_no_backup_exists(self):
        view = seed_views.LoadSeedView()
        captured = {}

        def fake_run_screen(screen_cls, button_data=None, **kwargs):
            captured["button_data"] = button_data
            return RET_CODE__BACK_BUTTON

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", fake_run_screen)
            view.run()
        assert seed_views.LoadSeedView.RESTORE_FROM_SD not in captured["button_data"]
        assert seed_views.LoadSeedView.DELETE_BACKUP not in captured["button_data"]


    def test_load_seed_view_shows_restore_and_delete_when_a_backup_exists(self):
        seed_backup.write_backup(_seed(), "an independent password")
        view = seed_views.LoadSeedView()
        captured = {}

        def fake_run_screen(screen_cls, button_data=None, **kwargs):
            captured["button_data"] = button_data
            return RET_CODE__BACK_BUTTON

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", fake_run_screen)
            view.run()
        assert seed_views.LoadSeedView.RESTORE_FROM_SD in captured["button_data"]
        assert seed_views.LoadSeedView.DELETE_BACKUP in captured["button_data"]


    def test_full_restore_flow_with_no_passphrase(self):
        seed = _seed()
        seed_backup.write_backup(seed, "an independent password")

        self.run_sequence(
            [
                FlowStep(seed_views.LoadSeedView, button_data_selection=seed_views.LoadSeedView.RESTORE_FROM_SD),
                FlowStep(seed_views.SeedRestoreFromSDEnterPasswordView, screen_return_value=dict(passphrase="an independent password")),
                FlowStep(seed_views.SeedFinalizeView, button_data_selection=seed_views.SeedFinalizeView.FINALIZE),
                FlowStep(seed_views.SeedOptionsView),
            ],
        )
        assert self.controller.storage.seeds[-1].mnemonic_list == seed.mnemonic_list


    def test_restore_with_wrong_password_shows_generic_error_and_retries(self):
        seed_backup.write_backup(_seed(), "the real password")

        self.run_sequence(
            [
                FlowStep(seed_views.LoadSeedView, button_data_selection=seed_views.LoadSeedView.RESTORE_FROM_SD),
                # This step's own run() call shows the generic error screen
                # INLINE (via read_backup()'s SeedBackupDecryptError) before
                # returning to a fresh password entry -- not a separate step.
                FlowStep(seed_views.SeedRestoreFromSDEnterPasswordView, screen_return_value=dict(passphrase="the wrong password")),
                FlowStep(seed_views.SeedRestoreFromSDEnterPasswordView, screen_return_value=dict(passphrase="the real password")),
                FlowStep(seed_views.SeedFinalizeView, button_data_selection=seed_views.SeedFinalizeView.FINALIZE),
                FlowStep(seed_views.SeedOptionsView),
            ],
        )


    def test_restore_with_no_backup_present_shows_a_specific_not_found_message(self):
        # No write_backup() call -- nothing on the card.
        view = seed_views.SeedRestoreFromSDEnterPasswordView()
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: dict(passphrase="whatever"))
            destination = view.run()
        assert destination.View_cls == seed_views.SeedRestoreFromSDEnterPasswordView


    def test_full_restore_flow_with_correct_passphrase_finalizes(self):
        seed = _seed(passphrase="my passphrase")
        seed_backup.write_backup(seed, "an independent password")

        self.run_sequence(
            [
                FlowStep(seed_views.LoadSeedView, button_data_selection=seed_views.LoadSeedView.RESTORE_FROM_SD),
                FlowStep(seed_views.SeedRestoreFromSDEnterPasswordView, screen_return_value=dict(passphrase="an independent password")),
                FlowStep(seed_views.SeedAddPassphraseView, screen_return_value=dict(passphrase="my passphrase")),
                FlowStep(seed_views.SeedReviewPassphraseView, button_data_selection=seed_views.SeedReviewPassphraseView.DONE),
                FlowStep(seed_views.SeedOptionsView),
            ],
        )
        assert self.controller.storage.seeds[-1].mnemonic_list == seed.mnemonic_list
        assert self.controller.storage.seeds[-1].passphrase == "my passphrase"


    def test_full_restore_flow_with_wrong_passphrase_hits_the_fingerprint_mismatch_gate(self):
        """ The core fail-closed property three independent adversarial
            reviews required: finalizing with the WRONG passphrase must
            never silently produce a different wallet. """
        seed = _seed(passphrase="the real passphrase")
        seed_backup.write_backup(seed, "an independent password")

        self.run_sequence(
            [
                FlowStep(seed_views.LoadSeedView, button_data_selection=seed_views.LoadSeedView.RESTORE_FROM_SD),
                FlowStep(seed_views.SeedRestoreFromSDEnterPasswordView, screen_return_value=dict(passphrase="an independent password")),
                FlowStep(seed_views.SeedAddPassphraseView, screen_return_value=dict(passphrase="the WRONG passphrase")),
                FlowStep(seed_views.SeedReviewPassphraseView, button_data_selection=seed_views.SeedReviewPassphraseView.DONE),
                FlowStep(seed_views.SeedRestoreFingerprintMismatchView, button_data_selection=seed_views.SeedRestoreFingerprintMismatchView.EDIT),
                FlowStep(seed_views.SeedAddPassphraseView, screen_return_value=dict(passphrase="the real passphrase")),
                FlowStep(seed_views.SeedReviewPassphraseView, button_data_selection=seed_views.SeedReviewPassphraseView.DONE),
                FlowStep(seed_views.SeedOptionsView),
            ],
        )
        assert self.controller.storage.seeds[-1].mnemonic_list == seed.mnemonic_list
        assert self.controller.storage.seeds[-1].passphrase == "the real passphrase"


    def test_restore_skipping_a_required_passphrase_also_hits_the_gate(self):
        """ The other exit path three reviews flagged: SeedFinalizeView's
            own FINALIZE branch (reached if the operator skips passphrase
            entry entirely) must ALSO be guarded, not just
            SeedReviewPassphraseView's DONE. """
        seed = _seed(passphrase="the real passphrase")
        seed_backup.write_backup(seed, "an independent password")

        self.run_sequence(
            [
                FlowStep(seed_views.LoadSeedView, button_data_selection=seed_views.LoadSeedView.RESTORE_FROM_SD),
                FlowStep(seed_views.SeedRestoreFromSDEnterPasswordView, screen_return_value=dict(passphrase="an independent password")),
                FlowStep(seed_views.SeedAddPassphraseView, screen_return_value=dict(passphrase="", is_back_button=True)),
                FlowStep(seed_views.SeedAddPassphraseExitDialogView, button_data_selection=seed_views.SeedAddPassphraseExitDialogView.SKIP),
                FlowStep(seed_views.SeedFinalizeView, button_data_selection=seed_views.SeedFinalizeView.FINALIZE),
                FlowStep(seed_views.SeedRestoreFingerprintMismatchView, button_data_selection=seed_views.SeedRestoreFingerprintMismatchView.EDIT),
                FlowStep(seed_views.SeedAddPassphraseView, screen_return_value=dict(passphrase="the real passphrase")),
                FlowStep(seed_views.SeedReviewPassphraseView, button_data_selection=seed_views.SeedReviewPassphraseView.DONE),
                FlowStep(seed_views.SeedOptionsView),
            ],
        )
        assert self.controller.storage.seeds[-1].passphrase == "the real passphrase"


    def test_restore_requiring_passphrase_when_device_setting_is_disabled_shows_notice(self):
        seed = _seed(passphrase="my passphrase")
        seed_backup.write_backup(seed, "an independent password")
        self.settings.set_value(SettingsConstants.SETTING__PASSPHRASE, SettingsConstants.OPTION__DISABLED)

        self.run_sequence(
            [
                FlowStep(seed_views.LoadSeedView, button_data_selection=seed_views.LoadSeedView.RESTORE_FROM_SD),
                FlowStep(seed_views.SeedRestoreFromSDEnterPasswordView, screen_return_value=dict(passphrase="an independent password")),
                FlowStep(seed_views.SeedRestorePassphraseRequiredNoticeView, screen_return_value=0),  # Continue
                FlowStep(seed_views.SeedAddPassphraseView, screen_return_value=dict(passphrase="my passphrase")),
                FlowStep(seed_views.SeedReviewPassphraseView, button_data_selection=seed_views.SeedReviewPassphraseView.DONE),
                FlowStep(seed_views.SeedOptionsView),
            ],
        )
        assert self.controller.storage.seeds[-1].passphrase == "my passphrase"


    def test_delete_backup_confirm_flow_removes_the_file(self):
        """ screen_return_value=1 (DELETE's index), not
            button_data_selection: this View.run() makes a SECOND
            run_screen call (the success message, button_data=[OK]) within
            the same step, which button_data_selection would incorrectly
            validate against too. """
        seed_backup.write_backup(_seed(), "an independent password")

        self.run_sequence(
            [
                FlowStep(seed_views.LoadSeedView, button_data_selection=seed_views.LoadSeedView.DELETE_BACKUP),
                FlowStep(seed_views.SeedDeleteBackupConfirmView, screen_return_value=1),
                FlowStep(seed_views.LoadSeedView),
            ],
        )
        assert not seed_backup.backup_exists()


    def test_delete_backup_keep_cancels_without_deleting(self):
        """ Unit-level for the KEEP/cancel branch, like several other
            back-button tests in this codebase: asserts the routing
            decision (Destination(BackStackView)) rather than where it
            resolves to, which depends on back_stack depth a from-scratch
            FlowTest sequence starting mid-flow doesn't have. """
        seed_backup.write_backup(_seed(), "an independent password")
        view = seed_views.SeedDeleteBackupConfirmView()
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(view, "run_screen", lambda *a, **kw: 0)  # KEEP is index 0
            destination = view.run()
        from seedsigner.views.view import BackStackView
        assert destination.View_cls == BackStackView
        assert seed_backup.backup_exists()
