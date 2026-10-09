"""
    Screens for the 7fchain root-key ceremony's no-blind-signing review flow
    (docs/7f-integration/root-key-ceremony-plan.md). Genesis-config only for
    now -- devfund-config review is a follow-up story once its own
    canonical-bytes support lands.

    Follows the same file-pairing convention as the rest of this codebase
    (seed_views.py <-> seed_screens.py, evm_views.py <-> evm_screens.py).
    SevenFReviewFieldScreen is a near-duplicate of evm_screens.py's own
    EvmReviewFieldScreen -- anticipated by name in that file's own docstring
    ("same pattern as the 7F work's SevenFReviewFieldScreen") -- rather than
    a shared base class, since forcing a shared base across two independent
    chain plugins' UI layers would be a speculative abstraction this
    project's own coding-style convention (YAGNI) argues against.

    `warning_detail`/`is_warning` (added 2026-10-04,
    7f-review-enrollment-fingerprint-no-visual-distinction, found by the
    full-project adversarial review's UI/UX dimension): mirrors
    EvmReviewFieldScreen's own mechanism exactly. Root self-cert's and
    Deputy cross-cert's "Subject key id" fields are the ENTIRE compensating
    control for the device-side Wrong-Key check the PKCS#10 rework removed
    (a federation-level decision, not a gap) -- "this comparison is now the
    operator's job," per cert_request.py's own docstring -- but used to
    render pixel-identical to every adjacent FYI field (same icon, same
    layout), giving a tired operator mid-ceremony no on-screen cue that this
    ONE field, unlike its neighbors, requires stopping to compare against
    something written down earlier. cert_request.py's
    root_self_cert_review_fields()/deputy_cross_cert_v2_review_fields() now
    flag their "Subject key id" fields this way.
"""
import re
from dataclasses import dataclass
from gettext import gettext as _

from seedsigner.gui.components import Fonts, GUIConstants, IconTextLine, SeedSignerIconConstants
from seedsigner.hardware.buttons import HardwareButtonsConstants
from seedsigner.models.sevenf.ceremony_clock import DateTimeFields

from seedsigner.gui.keyboard import Keyboard

from .screen import RET_CODE__BACK_BUTTON, BaseTopNavScreen, ButtonListScreen, ButtonOption, KeyboardScreen


# A visible_text escape (\\uXXXX, \\UXXXXXXXX, \\n, \\t, \\\\), or one character.
_ESCAPE_OR_CHAR = re.compile(r"\\u[0-9a-f]{4}|\\U[0-9a-f]{8}|\\[nt\\]|.", re.S)


def break_long_words(text: str, width: int, font) -> str:
    """ `text` with every word wider than `width` (as `font` measures it)
        broken onto lines at characters. The screen wraps only between words,
        so an unbroken run (a hex serial, an address, a long word in a
        coordinator's message) otherwise runs off both edges (found on the dev
        unit, 2026-10-08). Only line breaks are added: no character is added,
        dropped or changed. """
    lines = []
    for line in text.split("\n"):
        words = []
        for word in line.split(" "):
            if font.getlength(word) <= width:
                words.append(word)
                continue
            chunks, current = [], ""
            for unit in _ESCAPE_OR_CHAR.findall(word):     # never inside a visible_text escape
                if current and font.getlength(current + unit) > width:
                    chunks.append(current)
                    current = unit
                else:
                    current += unit
            chunks.append(current)
            words.append("\n".join(chunks))
        lines.append(" ".join(words))
    return "\n".join(lines)



def display_size() -> tuple[int, int]:
    """ The canvas (width, height) the Renderer uses for the configured display,
        without needing a live Renderer (the review pages are cut in the views). """
    from seedsigner.models.settings import Settings, SettingsConstants
    config = Settings.get_instance().get_value(SettingsConstants.SETTING__DISPLAY_CONFIGURATION, default_if_none=True)
    kind, dims = config.split("_")[:2]
    width, height = (int(x) for x in dims.split("x"))
    return (width, height) if kind == "st7789" else (height, width)   # the others are rotated (renderer.py)


def review_value_width(canvas_width: int) -> int:
    """ The width a review value is laid out in: after the icon and its spacer
        (rounded up, so never wider than the screen's). """
    return canvas_width - 2 * GUIConstants.EDGE_PADDING - GUIConstants.ICON_FONT_SIZE - GUIConstants.COMPONENT_PADDING


def review_value_lines(text: str, canvas_width: int) -> int:
    """ How many lines the review screen draws `text` on. """
    from seedsigner.gui.components import reflow_text_for_width
    width = review_value_width(canvas_width)
    font = Fonts.get_font(GUIConstants.get_body_font_name(), GUIConstants.get_body_font_size())
    return len(reflow_text_for_width(break_long_words(text, width, font), width))


def review_page_end(text: str, canvas_width: int, max_lines: int) -> int:
    """ The length of the longest prefix of `text`, ending at a word (or a
        broken-word piece), that the review screen draws on at most
        `max_lines` lines: all of `text` if it fits. One layout pass, mirroring
        break_long_words and reflow_text_for_width (which lays out each
        newline-separated line on its own, splitting words on whitespace).
        Callers check the page they cut with review_value_lines. """
    from seedsigner.gui.components import reflow_text_for_width
    width = review_value_width(canvas_width)
    font = Fonts.get_font(GUIConstants.get_body_font_name(), GUIConstants.get_body_font_size())
    used = 0
    offset = 0
    for original in text.split("\n"):
        # The layout lines of this text line, as reflow sees them: break_long_words
        # puts each later piece of a too-wide word on a line of its own.
        segments = [[]]                         # [(start, end)] word pieces per layout segment
        position = offset
        for word in original.split(" "):
            if word:
                pieces = break_long_words(word, width, font).split("\n")
                start = position
                for i, piece in enumerate(pieces):
                    if i:
                        segments.append([])
                    segments[-1].append((start, start + len(piece)))
                    start += len(piece)
            position += len(word) + 1
        for segment in segments:
            if not segment:
                lines = [[]]                    # a blank line
            else:
                laid = reflow_text_for_width(" ".join(text[a:b] for a, b in segment), width)
                lines, k = [], 0
                for line in laid:
                    n = len(line["text"].split())
                    lines.append(segment[k:k + n])
                    k += n
            for line in lines:
                if used == max_lines:
                    return line[0][0] if line else offset
                used += 1
        offset += len(original) + 1
    return len(text)


def review_lines_per_page(canvas_width: int, canvas_height: int, warning_detail: str = "") -> int:
    """ The most value lines that fit between the field label and the button,
        below the warning text if there is one. TextArea's own height formula
        (n lines: n * above-baseline + (n - 1) * spacing + below-baseline), with
        the font's full ascent and descent as the worst case. A page cut to this
        never draws signed text under the button (security review 2026-10-08:
        180-character pages hid their last lines). """
    from seedsigner.gui.components import reflow_text_for_width
    body = Fonts.get_font(GUIConstants.get_body_font_name(), GUIConstants.get_body_font_size())
    label = Fonts.get_font(GUIConstants.get_body_font_name(), GUIConstants.get_body_font_size() - 2)
    ascent, descent = body.getmetrics()
    spacing = GUIConstants.BODY_LINE_SPACING
    top = GUIConstants.TOP_NAV_HEIGHT + GUIConstants.COMPONENT_PADDING + sum(label.getmetrics()) + GUIConstants.COMPONENT_PADDING // 2
    bottom = canvas_height - GUIConstants.EDGE_PADDING - GUIConstants.BUTTON_HEIGHT - GUIConstants.COMPONENT_PADDING
    if warning_detail:
        detail_lines = len(reflow_text_for_width(warning_detail, canvas_width - 2 * GUIConstants.EDGE_PADDING))
        bottom -= GUIConstants.COMPONENT_PADDING + detail_lines * ascent + (detail_lines - 1) * spacing + descent
    return max(1, (bottom - top - descent + spacing) // (ascent + spacing))



@dataclass
class SevenFReviewFieldScreen(ButtonListScreen):
    """
        Generic single-field review screen: one labeled value, one "Next"
        button -- the no-blind-signing mechanism, one concern per screen.
        See this module's own docstring for why this isn't merged with
        evm_screens.py's EvmReviewFieldScreen.
    """
    page_title: str | None = None
    label_text: str | None = None
    value_text: str | None = None
    warning_detail: str = ""
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

        value_width = review_value_width(self.canvas_width)
        value_font = Fonts.get_font(GUIConstants.get_body_font_name(), GUIConstants.get_body_font_size())
        value_display = IconTextLine(
            icon_name=icon_name,
            icon_color=icon_color,
            label_text=self.label_text,
            value_text=break_long_words(self.value_text or "", value_width, value_font),
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
class SevenFConfirmSignScreen(ButtonListScreen):
    """ Final review step before signing: which chain, and the subject key id
        of the Root key that signs (sf-wallet-gov: "signing as root <ski>"),
        the signing-identity check after the per-field review
        (SevenFReviewFieldScreen). Same role as evm_screens.py's
        EvmConfirmSignScreen. The genesis- and devfund-configs and both
        certificates are all signed with the Root key; `signing_role_label`
        names it. """
    chain_kind_name: str | None = None
    subject_key_id: str | None = None
    signing_role_label: str = "Root key"

    def __post_init__(self):
        self.title = _("Confirm & Sign")
        self.is_bottom_list = True
        self.is_button_text_centered = True
        self.button_data = [ButtonOption("Sign")]
        super().__post_init__()

        chain_display = IconTextLine(
            icon_name=SeedSignerIconConstants.INFO,
            icon_color=GUIConstants.INFO_COLOR,
            label_text=_("signing as {} for").format(self.signing_role_label),
            value_text=self.chain_kind_name,
            is_text_centered=True,
            auto_line_break=True,
            screen_y=self.top_nav.height + GUIConstants.COMPONENT_PADDING,
        )
        self.components.append(chain_display)

        # The id holders know and report (sf-wallet-gov: "signing as root <ski>").
        self.components.append(IconTextLine(
            label_text=_("Subject key id"),
            value_text=self.subject_key_id,
            is_text_centered=True,
            auto_line_break=True,
            screen_y=chain_display.screen_y + chain_display.height + GUIConstants.COMPONENT_PADDING,
        ))



@dataclass
class SevenFDateTimeEntryScreen(BaseTopNavScreen):
    """
        One-screen UTC date/time editor for the certificate flows
        (models/sevenf/ceremony_clock.py has why). Up/down changes the
        highlighted field (holding repeats), left/right moves between fields
        (left from the year reaches Back), any press confirms. Shows the
        weekday live so a wrong day is easy to spot. Returns the edited
        DateTimeFields, or RET_CODE__BACK_BUTTON.
    """
    title: str = _("Date & time (UTC)")
    fields: DateTimeFields = None
    field_index: int = 2  # start on the day: usually the only thing that changes

    def __post_init__(self):
        super().__post_init__()
        self.value_font = Fonts.get_font(GUIConstants.FIXED_WIDTH_EMPHASIS_FONT_NAME, 30)
        self.small_font = Fonts.get_font(GUIConstants.get_body_font_name(), 16)


    def _render(self):
        super()._render()
        self._draw_editor()


    def _segments(self) -> list[list[tuple[str, int | None]]]:
        """ Two rows of (text, field index or None for separators). """
        f = self.fields
        return [
            [(f"{f.year:04d}", 0), ("-", None), (f"{f.month:02d}", 1), ("-", None), (f"{f.day:02d}", 2)],
            [(f"{f.hour:02d}", 3), (":", None), (f"{f.minute:02d}", 4)],
        ]


    def _draw_editor(self):
        draw = self.image_draw
        y = GUIConstants.TOP_NAV_HEIGHT + 14
        pad = 4
        for row in self._segments():
            widths = [draw.textlength(text, font=self.value_font) + (2 * pad if idx is not None else 2) for text, idx in row]
            x = (self.canvas_width - sum(widths)) // 2
            for (text, idx), w in zip(row, widths):
                selected = idx == self.field_index and not self.top_nav.is_selected
                if selected:
                    draw.rounded_rectangle((x, y - 2, x + w, y + 36), radius=6, fill=GUIConstants.ACCENT_COLOR)
                draw.text(
                    (x + w / 2, y + 17), text, anchor="mm", font=self.value_font,
                    fill=GUIConstants.BACKGROUND_COLOR if selected else GUIConstants.BODY_FONT_COLOR,
                )
                x += w
            y += 46

        weekday = self.fields.describe().split(" ", 1)[0]
        draw.text((self.canvas_width / 2, y + 6), weekday, anchor="mm", font=self.small_font, fill=GUIConstants.ACCENT_COLOR)
        for i, hint in enumerate((_("Up/down: change"), _("Left/right: next field"), _("Press: done"))):
            draw.text((self.canvas_width / 2, y + 30 + 19 * i), hint, anchor="mm", font=self.small_font, fill=GUIConstants.LABEL_FONT_COLOR)


    def _run(self):
        while True:
            user_input = self.hw_inputs.wait_for(HardwareButtonsConstants.ALL_KEYS)
            with self.renderer.lock:
                if self.top_nav.is_selected:
                    if user_input in HardwareButtonsConstants.KEYS__ANYCLICK:
                        return RET_CODE__BACK_BUTTON
                    if user_input in (HardwareButtonsConstants.KEY_DOWN, HardwareButtonsConstants.KEY_RIGHT):
                        self.top_nav.is_selected = False
                elif user_input == HardwareButtonsConstants.KEY_UP:
                    self.fields = self.fields.adjusted(self.field_index, +1)
                elif user_input == HardwareButtonsConstants.KEY_DOWN:
                    self.fields = self.fields.adjusted(self.field_index, -1)
                elif user_input == HardwareButtonsConstants.KEY_LEFT:
                    if self.field_index == 0:
                        self.top_nav.is_selected = True
                    else:
                        self.field_index -= 1
                elif user_input == HardwareButtonsConstants.KEY_RIGHT:
                    self.field_index = min(self.field_index + 1, len(DateTimeFields.FIELDS) - 1)
                elif user_input in HardwareButtonsConstants.KEYS__ANYCLICK:
                    return self.fields
                else:
                    continue
                self.top_nav.render_buttons()
                self._render()
                self.renderer.show_image()



@dataclass
class SevenFKeyIndexScreen(KeyboardScreen):
    """ Digits keypad for a Root or dev-fund key index
        (7f-signing-support-key-index-selector). Same shape as
        evm_screens.EvmSelectAddressIndexScreen; the caller passes the title
        ("Root key index" or "Dev-fund key index") and validates the result. """
    def __post_init__(self):
        self.user_input = ""
        self.rows = 3
        self.cols = 5
        self.keys_charset = "0123456789"
        self.show_save_button = True
        self.custom_additional_keys = [Keyboard.KEY_BACKSPACE_5]
        super().__post_init__()
