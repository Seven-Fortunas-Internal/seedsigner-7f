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
from dataclasses import dataclass
from gettext import gettext as _

from seedsigner.gui.components import FormattedAddress, GUIConstants, IconTextLine, SeedSignerIconConstants

from .screen import ButtonListScreen, ButtonOption


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

        value_display = IconTextLine(
            icon_name=icon_name,
            icon_color=icon_color,
            label_text=self.label_text,
            value_text=self.value_text,
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
    """ Final review step before signing: which chain and which key's
        address the signature will be attributed to -- the signing-identity
        check, distinct from the per-field genesis-config content review
        that already happened on the preceding pages (SevenFReviewFieldScreen).
        Same role as evm_screens.py's EvmConfirmSignScreen.

        `signing_role_label` names the actual key signing (default "Root CA"
        for genesis-config/Root self-cert/Deputy cross-cert, all signed by
        the Root CA key) -- added 2026-10-03
        (7f-review-devfund-confirm-screen-wrong-label, found by the
        full-project adversarial review's UI/UX dimension) after this screen
        was found hardcoding "signing as Root CA for" even when
        SevenFConfirmSignDevFundView used it to sign with the DEVFUND key, a
        different key from the same seed. That mislabeling directly
        undermined the one wrong-key check the hardware walkthrough singles
        out for this exact screen (docs/7f-integration/root-ceremony-
        hardware-walkthrough.md Step 6: "the confirm screen must show the
        devfund address... If the address shown here matches the Root CA
        address instead, that's a real regression") -- an operator primed to
        watch for that exact mismatch would have seen the words "Root CA" on
        the one screen that was supposed to prove it wasn't. """
    chain_kind_name: str | None = None
    address: str | None = None
    signing_role_label: str = "Root CA"

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

        address_display = FormattedAddress(
            address=self.address,
            screen_y=chain_display.screen_y + chain_display.height + 2*GUIConstants.COMPONENT_PADDING,
        )
        self.components.append(address_display)
