"""
    Key handling of SevenFDateTimeEntryScreen, driven with scripted button
    presses (same harness as test_tools_screens.py). Drawing is stubbed out;
    tests/test_sevenf_ceremony_clock.py covers the field arithmetic.
"""
from unittest.mock import MagicMock, patch

from base import BaseTest

from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON
from seedsigner.models.sevenf.ceremony_clock import DateTimeFields


class K:
    """ Real values: tests/base.py replaces the hardware buttons module with a
        MagicMock, whose constants can't be compared or searched. """
    KEY_UP, KEY_DOWN, KEY_LEFT, KEY_RIGHT, KEY_PRESS, KEY1, KEY2, KEY3 = range(1, 9)
    KEYS__ANYCLICK = [KEY_PRESS, KEY1, KEY2, KEY3]
    ALL_KEYS = [KEY_UP, KEY_DOWN, KEY_LEFT, KEY_RIGHT, KEY_PRESS, KEY1, KEY2, KEY3]

START = DateTimeFields(2026, 10, 7, 21, 30)


class TestSevenFDateTimeEntryScreen(BaseTest):
    def run_keys(self, keys: list):
        from seedsigner.gui.renderer import Renderer
        from seedsigner.gui.screens import sevenf_screens
        from seedsigner.gui.screens.sevenf_screens import SevenFDateTimeEntryScreen

        renderer = MagicMock()
        renderer.canvas_width = 240
        renderer.canvas_height = 240
        with patch.object(Renderer, "get_instance", return_value=renderer):
            screen = SevenFDateTimeEntryScreen(fields=START)
        screen._render = lambda: None
        screen.top_nav.render_buttons = lambda: None
        screen.hw_inputs = MagicMock()
        screen.hw_inputs.wait_for.side_effect = list(keys)
        with patch.object(sevenf_screens, "HardwareButtonsConstants", K):
            return screen._run()


    def test_press_returns_the_prefilled_value_unchanged(self):
        assert self.run_keys([K.KEY_PRESS]) == START


    def test_starts_on_the_day_and_up_down_change_it(self):
        assert self.run_keys([K.KEY_UP, K.KEY_UP, K.KEY_DOWN, K.KEY_PRESS]) == DateTimeFields(2026, 10, 8, 21, 30)


    def test_right_moves_to_hour_then_minute_and_stops_at_the_last_field(self):
        out = self.run_keys([K.KEY_RIGHT, K.KEY_DOWN, K.KEY_RIGHT, K.KEY_RIGHT, K.KEY_RIGHT, K.KEY_UP, K.KEY_PRESS])
        assert out == DateTimeFields(2026, 10, 7, 20, 31)


    def test_left_moves_back_to_the_year(self):
        assert self.run_keys([K.KEY_LEFT, K.KEY_LEFT, K.KEY_UP, K.KEY_PRESS]) == DateTimeFields(2027, 10, 7, 21, 30)


    def test_left_from_the_year_reaches_back_and_press_leaves(self):
        assert self.run_keys([K.KEY_LEFT, K.KEY_LEFT, K.KEY_LEFT, K.KEY_PRESS]) == RET_CODE__BACK_BUTTON


    def test_down_from_back_returns_to_editing(self):
        out = self.run_keys([K.KEY_LEFT, K.KEY_LEFT, K.KEY_LEFT, K.KEY_DOWN, K.KEY_UP, K.KEY_PRESS])
        assert out == DateTimeFields(2027, 10, 7, 21, 30)


    def test_any_of_the_three_side_keys_also_confirms(self):
        for key in (K.KEY1, K.KEY2, K.KEY3):
            assert self.run_keys([K.KEY_UP, key]) == DateTimeFields(2026, 10, 8, 21, 30)
