"""
    Multi-chain (Phase 1 UI-walkthrough demo). Screens for the EVM address-display and
    sign-request review/sign flows. All data shown here is mocked/placeholder -- no
    real derivation or ECDSA signing happens yet. See docs/multi-chain/README.md in
    the diy-seedsigner repo for the full design and phased rollout plan.

    Follows the same file-pairing convention as the rest of this codebase
    (seed_views.py <-> seed_screens.py, psbt_views.py <-> psbt_screens.py, etc.).
"""
from dataclasses import dataclass
from gettext import gettext as _

from seedsigner.gui.components import FormattedAddress, GUIConstants, IconTextLine, SeedSignerIconConstants

from .screen import ButtonListScreen, ButtonOption


# Real-hardware finding from the 7F work (240x240 HAT, 2026-08-28, see
# docs/7f-integration/): IconTextLine's auto_line_break only ever breaks *between*
# words (on spaces) -- it can't break a single long unbroken run of characters.
# Derivation paths and addresses are exactly that. Left unwrapped, a long value both
# overflows the screen width and inflates IconTextLine's internal centering-offset
# math enough to go negative, which clips the *label* too. Duplicated here rather than
# imported because this branch has no dependency on the (paused) 7f/falcon-signing
# branch's code -- worth unifying into a shared gui/components.py helper if/when that
# work resumes.
_MAX_UNBROKEN_VALUE_CHARS = 24

def _wrap_long_value_for_display(text: str) -> str:
    def wrap_word(word: str) -> str:
        if len(word) <= _MAX_UNBROKEN_VALUE_CHARS:
            return word
        mid = len(word) // 2
        left_slash = word.rfind("/", 0, mid)
        right_slash = word.find("/", mid)
        if left_slash == -1 and right_slash == -1:
            break_at = mid
        elif left_slash == -1:
            break_at = right_slash
        elif right_slash == -1:
            break_at = left_slash + 1
        else:
            break_at = (left_slash + 1) if (mid - left_slash) <= (right_slash - mid) else right_slash
        return word[:break_at] + "\n" + word[break_at:]

    return " ".join(wrap_word(word) for word in text.split(" "))



@dataclass
class EvmAddressScreen(ButtonListScreen):
    """
        Shows a derivation path + EVM address. Real-hardware-style finding caught by
        rendering this screen with an actual varied-hex-digit address rather than a
        repeated-character placeholder (which would hide the bug): FormattedAddress's
        `max_lines=3` -- used successfully for a 49-char 7F address and stated in
        FormattedAddress's own docstring to fit a 62-char taproot address -- silently
        truncates this 42-char EVM address instead, because "0x" plus 40 hex digits
        needs 4 display lines at this font size, not 3. Deliberately not passing
        max_lines at all (component default: None, auto-sized) rather than bumping it
        to 4 -- a hardcoded line count that happens to work for one address length is
        the same class of bug, just with the truncation point moved.
    """
    derivation_path: str = None
    address: str = None
    network_name: str = None

    def __post_init__(self):
        # Network folds into the title rather than its own IconTextLine row -- a
        # 42-char EVM address needs 4 display lines (see class docstring), and vertical
        # space on a 240px screen is the binding constraint, not information to cut.
        # Still shown, still no-blind-signing-compliant, just more compact.
        self.title = f"{self.network_name} Address (DEMO)"
        self.is_bottom_list = True
        self.is_button_text_centered = True
        self.button_data = [ButtonOption("Export QR")]
        super().__post_init__()

        derivation_path_display = IconTextLine(
            icon_name=SeedSignerIconConstants.DERIVATION,
            icon_color=GUIConstants.INFO_COLOR,
            label_text=_("derivation path"),
            value_text=_wrap_long_value_for_display(self.derivation_path),
            is_text_centered=True,
            auto_line_break=True,
            screen_y=self.top_nav.height + GUIConstants.COMPONENT_PADDING,
        )
        self.components.append(derivation_path_display)

        address_display = FormattedAddress(
            address=self.address,
            screen_y=derivation_path_display.screen_y + derivation_path_display.height + 2*GUIConstants.COMPONENT_PADDING,
        )
        self.components.append(address_display)



@dataclass
class EvmReviewFieldScreen(ButtonListScreen):
    """
        Generic single-field review screen: one labeled value, one "Next" button --
        the no-blind-signing mechanism, one concern per screen (same pattern as the 7F
        work's SevenFReviewFieldScreen and, before that, PSBTOverviewScreen's detail
        screens). `is_warning` renders the field in the dire-warning color so a
        hard-stop item (an unlimited approval, an off-chain permit signature, a
        first-time address) is visually distinct from an ordinary informational field
        -- see docs/multi-chain/research/anti-scam-ux.md for why these specific fields
        get flagged.
    """
    page_title: str = None
    label_text: str = None
    value_text: str = None
    warning_detail: str = None
    page_num: int = 0
    num_pages: int = 1
    is_warning: bool = False
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

        icon_name = SeedSignerIconConstants.WARNING if self.is_warning else SeedSignerIconConstants.INFO
        icon_color = GUIConstants.DIRE_WARNING_COLOR if self.is_warning else GUIConstants.INFO_COLOR

        value_display = IconTextLine(
            icon_name=icon_name,
            icon_color=icon_color,
            label_text=self.label_text,
            value_text=_wrap_long_value_for_display(self.value_text),
            is_text_centered=True,
            auto_line_break=True,
            screen_y=self.top_nav.height + GUIConstants.COMPONENT_PADDING,
        )
        self.components.append(value_display)

        if self.is_warning and self.warning_detail:
            detail_display = IconTextLine(
                icon_color=GUIConstants.DIRE_WARNING_COLOR,
                value_text=self.warning_detail,
                is_text_centered=True,
                auto_line_break=True,
                screen_y=value_display.screen_y + value_display.height + GUIConstants.COMPONENT_PADDING,
            )
            self.components.append(detail_display)



@dataclass
class EvmConfirmSignScreen(ButtonListScreen):
    """ Final review step before "signing": derivation path + the address the demo
        signature would be attributed to. Deliberately labeled DEMO throughout so a
        mocked signature can never be mistaken for a real one. """
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
            value_text=_wrap_long_value_for_display(self.derivation_path),
            is_text_centered=True,
            auto_line_break=True,
            screen_y=self.top_nav.height + GUIConstants.COMPONENT_PADDING,
        )
        self.components.append(derivation_path_display)

        address_display = FormattedAddress(
            address=self.address,
            screen_y=derivation_path_display.screen_y + derivation_path_display.height + 2*GUIConstants.COMPONENT_PADDING,
        )
        self.components.append(address_display)
