"""
    7F integration (Phase 1 UI-walkthrough demo).

    Screens for the SevenFortunas address-display and sign-request review/sign flows.
    All data shown by these screens is mocked/placeholder in Phase 1 — no real
    derivation or Falcon-512 signing happens here yet. See
    docs/7f-integration/README.md in the diy-seedsigner repo for the full design and
    phased rollout plan.

    Follows the same file-pairing convention as the rest of this codebase
    (seed_views.py <-> seed_screens.py, psbt_views.py <-> psbt_screens.py, etc.).
"""
from dataclasses import dataclass
from gettext import gettext as _

from seedsigner.gui.components import FormattedAddress, GUIConstants, IconTextLine, SeedSignerIconConstants

from .screen import ButtonListScreen, ButtonOption



@dataclass
class SevenFAddressScreen(ButtonListScreen):
    """
        Shows a derivation path + 7F address, same layout SeedSignMessageConfirmAddressScreen
        uses for a Bitcoin derivation path + address (a 49-char 7F address fits
        FormattedAddress's existing layout the same way a 62-char taproot address does).
    """
    derivation_path: str = None
    address: str = None

    def __post_init__(self):
        self.title = _("7F Address (DEMO)")
        self.is_bottom_list = True
        self.is_button_text_centered = True
        self.button_data = [ButtonOption("Export QR")]
        super().__post_init__()

        derivation_path_display = IconTextLine(
            icon_name=SeedSignerIconConstants.DERIVATION,
            icon_color=GUIConstants.INFO_COLOR,
            label_text=_("derivation path"),
            value_text=self.derivation_path,
            is_text_centered=True,
            screen_y=self.top_nav.height + GUIConstants.COMPONENT_PADDING,
        )
        self.components.append(derivation_path_display)

        address_display = FormattedAddress(
            address=self.address,
            max_lines=3,
            screen_y=derivation_path_display.screen_y + derivation_path_display.height + 2*GUIConstants.COMPONENT_PADDING,
        )
        self.components.append(address_display)



@dataclass
class SevenFReviewFieldScreen(ButtonListScreen):
    """
        Generic single-field review screen: one labeled value, one "Next" button.

        Used to page through a 7F sign-request's mandatory review fields (operation
        type, network/layer, amount/counterparty, ...) one concern per screen -- the
        same pattern PSBTOverviewScreen's detail screens and
        SeedSignMessageConfirmMessageScreen use, in service of this project's
        no-blind-signing principle: every field the operator must judge gets its own
        unhurried screen, never buried in a wall of text.
    """
    page_title: str = None
    label_text: str = None
    value_text: str = None
    page_num: int = 0
    num_pages: int = 1
    icon_name: str = SeedSignerIconConstants.INFO
    is_final_page: bool = False

    def __post_init__(self):
        if self.num_pages > 1:
            self.title = f"{self.page_title} ({self.page_num + 1}/{self.num_pages})"
        else:
            self.title = self.page_title
        self.is_bottom_list = True
        self.is_button_text_centered = True
        self.button_data = [ButtonOption("Next")] if not self.is_final_page else [ButtonOption("Continue")]
        super().__post_init__()

        value_display = IconTextLine(
            icon_name=self.icon_name,
            icon_color=GUIConstants.INFO_COLOR,
            label_text=self.label_text,
            value_text=self.value_text,
            is_text_centered=True,
            screen_y=self.top_nav.height + GUIConstants.COMPONENT_PADDING,
        )
        self.components.append(value_display)



@dataclass
class SevenFConfirmSignScreen(ButtonListScreen):
    """
        Final review step before "signing": derivation path + the address the demo
        signature would be attributed to. Deliberately labeled DEMO throughout so a
        mocked signature can never be mistaken for a real one.
    """
    derivation_path: str = None
    address: str = None

    def __post_init__(self):
        self.title = _("Confirm & Sign (DEMO)")
        self.is_bottom_list = True
        self.is_button_text_centered = True
        self.button_data = [ButtonOption("Sign (DEMO — not real)")]
        super().__post_init__()

        derivation_path_display = IconTextLine(
            icon_name=SeedSignerIconConstants.DERIVATION,
            icon_color=GUIConstants.INFO_COLOR,
            label_text=_("derivation path"),
            value_text=self.derivation_path,
            is_text_centered=True,
            screen_y=self.top_nav.height + GUIConstants.COMPONENT_PADDING,
        )
        self.components.append(derivation_path_display)

        address_display = FormattedAddress(
            address=self.address,
            max_lines=3,
            screen_y=derivation_path_display.screen_y + derivation_path_display.height + 2*GUIConstants.COMPONENT_PADDING,
        )
        self.components.append(address_display)
