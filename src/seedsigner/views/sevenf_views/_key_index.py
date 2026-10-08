"""
    The key index step shared by every Root and dev-fund flow
    (7f-signing-support-key-index-selector,
    docs/7f-integration/root-key-index-selector-plan.md).

    sf-wallet-gov takes `--index N` on every Root and dev-fund command; this
    asks for the same N, default 0. Each view is told which key it is asking
    about (`role`) and where to go next; the next view receives everything it
    was given plus `key_index`. Nothing here derives or signs.

    Every step of the choice leaves the back stack (skip_current_view), so
    Back from the screen after the index, or from the keypad or the warning,
    returns to whatever came before the index, by either path.
    tests/test_sevenf_key_index_flows.py checks the real back stack.
"""
from gettext import gettext as _

from seedsigner.gui.components import SeedSignerIconConstants
from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
from seedsigner.gui.screens.screen import ButtonOption, ButtonOptionWithoutTranslation
from seedsigner.models.sevenf.constants import MAX_KEY_INDEX, key_index_segment, parse_key_index_entry
from seedsigner.views.view import BackStackView, Destination, View


def _title(role: str) -> str:
    if role == "root":
        return _("Root key index")
    if role == "devfund":
        return _("Dev-fund key index")
    raise ValueError(f"no key index for role {role!r}")


class _KeyIndexStep(View):
    """ What every step of the index choice carries. """
    def __init__(self, role: str, next_destination: type, next_view_args: dict):
        super().__init__()
        self.title = _title(role)
        self.role = role
        self.next_destination = next_destination
        self.next_view_args = next_view_args


    def _step_args(self) -> dict:
        return dict(role=self.role, next_destination=self.next_destination, next_view_args=self.next_view_args)


    def _continue_with(self, key_index: int) -> Destination:
        return Destination(
            self.next_destination,
            view_args=dict(self.next_view_args, key_index=key_index),
            skip_current_view=True,
        )



class SevenFSelectKeyIndexView(_KeyIndexStep):
    """ Index 0 in one press; any other index through the keypad. """
    def run(self):
        from seedsigner.gui.screens.screen import ButtonListScreen
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=self.title,
            is_button_text_centered=True,
            button_data=[ButtonOption("Index 0 (default)"), ButtonOption("Other index")],
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        if selected_menu_num == 0:
            return self._continue_with(0)
        return Destination(SevenFEnterKeyIndexView, view_args=self._step_args(), skip_current_view=True)



class SevenFEnterKeyIndexView(_KeyIndexStep):
    def run(self):
        from seedsigner.gui.screens.sevenf_screens import SevenFKeyIndexScreen
        ret = self.run_screen(SevenFKeyIndexScreen, title=self.title)

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        try:
            key_index = parse_key_index_entry(ret)
        except (TypeError, ValueError):
            return Destination(SevenFInvalidKeyIndexView, view_args=self._step_args(), skip_current_view=True)

        if key_index == 0:
            return self._continue_with(0)
        return Destination(
            SevenFConfirmKeyIndexView,
            view_args=dict(self._step_args(), key_index=key_index),
            skip_current_view=True,
        )



class SevenFInvalidKeyIndexView(_KeyIndexStep):
    def run(self):
        from seedsigner.gui.screens import DireWarningScreen
        self.run_screen(
            DireWarningScreen,
            title=self.title,
            show_back_button=False,
            status_icon_name=SeedSignerIconConstants.ERROR,
            status_headline=_("Invalid index"),
            text=_("An index is a whole number from 0 to {}.").format(MAX_KEY_INDEX),
            button_data=[ButtonOption("Try again")],
        )
        return Destination(SevenFEnterKeyIndexView, view_args=self._step_args(), skip_current_view=True)



class SevenFConfirmKeyIndexView(_KeyIndexStep):
    """ One deliberate extra step before a nonzero index: our practice is one
        phrase per key at index 0 (7fchain#7), so a nonzero index should only
        ever be chosen on purpose. (The seed label stays the index-0 Root ski:
        it names the phrase. The operator guide says so; on this screen the
        sentence didn't fit at a long index.) """
    def __init__(self, role: str, key_index: int, next_destination: type, next_view_args: dict):
        super().__init__(role, next_destination, next_view_args)
        key_index_segment(key_index)
        if key_index == 0:
            raise ValueError("index 0 needs no confirmation")
        self.key_index = key_index


    def run(self):
        from seedsigner.gui.screens import WarningScreen
        selected_menu_num = self.run_screen(
            WarningScreen,
            title=self.title,
            status_headline=_("Index {}").format(self.key_index),
            text=_("Not the default. Use it only if this key was made at index {}.").format(self.key_index),
            button_data=[ButtonOptionWithoutTranslation(_("Use index {}").format(self.key_index))],
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        return self._continue_with(self.key_index)
