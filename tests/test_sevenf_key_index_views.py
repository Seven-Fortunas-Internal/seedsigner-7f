"""
    The key index screens (7f-signing-support-key-index-selector,
    docs/7f-integration/root-key-index-selector-plan.md): a default button
    for index 0, a keypad for any other, a refusal for anything sf-wallet-gov
    would refuse, and a warning before a nonzero index is used.
"""
import pytest

# Must import test base before the Controller (see base.py's own comment).
from base import FlowTest  # noqa: F401

from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON
from seedsigner.models.sevenf.constants import MAX_KEY_INDEX, parse_key_index_entry
from seedsigner.views import sevenf_views
from seedsigner.views.view import BackStackView, View


class _Next(View):
    """ Stand-in for the step after the index, e.g. the Root VK screen. """
    def __init__(self, **kwargs):
        super().__init__()
        self.kwargs = kwargs


NEXT_ARGS = dict(chain_kind="testnet-marker", other="kept")


def _run(view, screen_return, captured=None):
    def fake_run_screen(screen_cls, **kwargs):
        if captured is not None:
            captured.update(kwargs, screen_cls=screen_cls)
        return screen_return

    with pytest.MonkeyPatch().context() as mp:
        mp.setattr(view, "run_screen", fake_run_screen)
        return view.run()


# --- parsing what the keypad returns -------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("0", 0), ("1", 1), ("007", 7), ("4294967295", MAX_KEY_INDEX),
])
def test_parse_key_index_entry_reads_canonical_values(text, expected):
    assert parse_key_index_entry(text) == expected


@pytest.mark.parametrize("text", ["", "4294967296", "99999999999999999999", "-1", "1.5", " 1", "１", "²", None])
def test_parse_key_index_entry_refuses_what_sf_wallet_gov_refuses(text):
    with pytest.raises((ValueError, TypeError)):
        parse_key_index_entry(text)


# --- the first screen: default or other ----------------------------------

class TestSelectKeyIndexView(FlowTest):
    def _view(self, role="root"):
        return sevenf_views.SevenFSelectKeyIndexView(role=role, next_destination=_Next, next_view_args=dict(NEXT_ARGS))

    def test_titles_name_the_key(self):
        captured = {}
        _run(self._view("root"), 0, captured)
        assert captured["title"] == "Root key index"
        assert [b.button_label for b in captured["button_data"]] == ["Index 0 (default)", "Other index"]

        _run(self._view("devfund"), 0, captured)
        assert captured["title"] == "Dev-fund key index"

    def test_default_button_continues_with_index_0(self):
        destination = _run(self._view(), 0)
        assert destination.View_cls is _Next
        assert destination.view_args == dict(NEXT_ARGS, key_index=0)

    def test_other_button_opens_the_keypad(self):
        destination = _run(self._view(), 1)
        assert destination.View_cls is sevenf_views.SevenFEnterKeyIndexView
        assert destination.view_args == dict(role="root", next_destination=_Next, next_view_args=NEXT_ARGS)

    def test_back_goes_back(self):
        assert _run(self._view(), RET_CODE__BACK_BUTTON).View_cls is BackStackView

    def test_unknown_role_is_refused(self):
        with pytest.raises(ValueError):
            sevenf_views.SevenFSelectKeyIndexView(role="deputy", next_destination=_Next, next_view_args={})


# --- the keypad ------------------------------------------------------------

class TestEnterKeyIndexView(FlowTest):
    def _view(self, role="root"):
        return sevenf_views.SevenFEnterKeyIndexView(role=role, next_destination=_Next, next_view_args=dict(NEXT_ARGS))

    def test_keypad_is_titled_for_the_key(self):
        from seedsigner.gui.screens.sevenf_screens import SevenFKeyIndexScreen
        captured = {}
        _run(self._view("devfund"), "3", captured)
        assert captured["screen_cls"] is SevenFKeyIndexScreen
        assert captured["title"] == "Dev-fund key index"

    def test_zero_continues_without_a_warning(self):
        destination = _run(self._view(), "0")
        assert destination.View_cls is _Next
        assert destination.view_args == dict(NEXT_ARGS, key_index=0)

    @pytest.mark.parametrize("text,index", [("2", 2), ("007", 7), ("4294967295", MAX_KEY_INDEX)])
    def test_nonzero_goes_to_the_warning_with_the_canonical_index(self, text, index):
        destination = _run(self._view(), text)
        assert destination.View_cls is sevenf_views.SevenFConfirmKeyIndexView
        assert destination.view_args == dict(role="root", key_index=index, next_destination=_Next, next_view_args=NEXT_ARGS)

    @pytest.mark.parametrize("text", ["", "4294967296"])
    def test_a_bad_entry_is_refused(self, text):
        destination = _run(self._view(), text)
        assert destination.View_cls is sevenf_views.SevenFInvalidKeyIndexView
        assert destination.view_args["next_view_args"] == NEXT_ARGS

    def test_back_goes_back(self):
        assert _run(self._view(), RET_CODE__BACK_BUTTON).View_cls is BackStackView


class TestInvalidKeyIndexView(FlowTest):
    def test_try_again_returns_to_the_keypad(self):
        view = sevenf_views.SevenFInvalidKeyIndexView(role="root", next_destination=_Next, next_view_args=dict(NEXT_ARGS))
        captured = {}
        destination = _run(view, 0, captured)
        assert "4294967295" in captured["text"]
        assert destination.View_cls is sevenf_views.SevenFEnterKeyIndexView
        assert destination.view_args == dict(role="root", next_destination=_Next, next_view_args=NEXT_ARGS)


# --- the warning before a nonzero index -----------------------------------

class TestConfirmKeyIndexView(FlowTest):
    def _view(self, index=2, role="root"):
        return sevenf_views.SevenFConfirmKeyIndexView(
            role=role, key_index=index, next_destination=_Next, next_view_args=dict(NEXT_ARGS))

    def test_warning_names_the_index(self):
        captured = {}
        _run(self._view(2), 0, captured)
        assert "2" in captured["status_headline"]
        assert [b.button_label for b in captured["button_data"]] == ["Use index 2"]

    def test_confirm_continues_with_the_index(self):
        destination = _run(self._view(2), 0)
        assert destination.View_cls is _Next
        assert destination.view_args == dict(NEXT_ARGS, key_index=2)

    def test_back_goes_back(self):
        assert _run(self._view(2), RET_CODE__BACK_BUTTON).View_cls is BackStackView

    def test_zero_or_out_of_range_is_a_bug(self):
        with pytest.raises(ValueError):
            self._view(0)
        with pytest.raises(ValueError):
            self._view(MAX_KEY_INDEX + 1)


def test_a_very_long_entry_is_refused_not_crashed():
    # int() refuses past ~4300 digits with its own ValueError; still a refusal.
    with pytest.raises(ValueError):
        parse_key_index_entry("9" * 5000)


class TestIndexStepsLeaveTheBackStack(FlowTest):
    """ Back from the screen after the index returns to whatever came before
        the index, not to the keypad or the warning. """
    def test_every_continue_skips_the_index_screen(self):
        select = sevenf_views.SevenFSelectKeyIndexView(role="root", next_destination=_Next, next_view_args={})
        assert _run(select, 0).skip_current_view is True

        enter = sevenf_views.SevenFEnterKeyIndexView(role="root", next_destination=_Next, next_view_args={})
        assert _run(enter, "0").skip_current_view is True
        assert _run(enter, "5").skip_current_view is True

        confirm = sevenf_views.SevenFConfirmKeyIndexView(role="root", key_index=5, next_destination=_Next, next_view_args={})
        assert _run(confirm, 0).skip_current_view is True
