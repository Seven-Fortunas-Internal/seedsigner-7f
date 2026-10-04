"""
    Screens for the EVM address-display and sign-request review/sign flows. Real
    derivation and real ECDSA signing (see chains/evm/) for every scenario except
    `permit`, which stays a mocked signature deliberately -- its EIP-712 domain can't
    be self-validated offline (see chains/evm/plugin.py's module docstring). See
    docs/multi-chain/README.md and docs/multi-chain/evm-first-class-plan.md in the
    diy-seedsigner repo for the full design and what's still ahead.

    Follows the same file-pairing convention as the rest of this codebase
    (seed_views.py <-> seed_screens.py, psbt_views.py <-> psbt_screens.py, etc.).
"""
from dataclasses import dataclass
from gettext import gettext as _

from seedsigner.gui.components import FormattedAddress, GUIConstants, IconTextLine, SeedSignerIconConstants
from seedsigner.gui.keyboard import Keyboard

from .screen import ButtonListScreen, ButtonOption, KeyboardScreen


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
class EvmSelectAddressIndexScreen(KeyboardScreen):
    """ Same interaction pattern as SeedBIP85SelectChildIndexScreen (digits-only
        keypad, save-to-continue) -- not a shared base class, since the two screens'
        valid ranges/purposes differ, but no reason to invent a new pattern for the
        same shape of problem (picking a BIP-32 non-hardened child index, 0 to
        2**31-1, the same underlying constraint both features share). """
    def __post_init__(self):
        self.title = _("EVM Address Index")
        self.user_input = ""

        self.rows = 3
        self.cols = 5
        self.keys_charset = "0123456789"
        self.show_save_button = True
        self.custom_additional_keys = [Keyboard.KEY_BACKSPACE_5]

        super().__post_init__()



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

        FIXED 2026-10-04 (multi-chain-evm-address-screen-truncates): that first fix
        stopped the component's OWN max_lines truncation, but on real 240px hardware
        the address still only rendered 2 of its 4 needed lines -- FormattedAddress's
        line-count math has no concept of this screen's actual limited vertical space
        (title + derivation path + address + two buttons all competing for 240px), so
        it picked a line count that overflowed off-screen instead of one that never
        gets cut off cleanly. Jorge's explicit preference, matching his own wording:
        "make sure to take note to fix the seedsigner so it shows the full address -
        perhaps a scrolling vertically and/or horizontally. I'd prefer scrolling over
        smaller font." -- so this passes the real available height (computed from
        where the button row actually starts, not guessed) as `visible_height`, and
        FormattedAddress auto-scrolls through the full address when it doesn't fit,
        rather than shrinking the font or re-truncating.
    """
    derivation_path: str = None
    address: str = None
    network_name: str = None

    def __post_init__(self):
        # Network folds into the title rather than its own IconTextLine row -- a
        # 42-char EVM address needs 4 display lines (see class docstring), and vertical
        # space on a 240px screen is the binding constraint, not information to cut.
        # Still shown, still no-blind-signing-compliant, just more compact.
        self.title = f"{self.network_name} Address"
        self.is_bottom_list = True
        self.is_button_text_centered = True
        # Two export paths (plan Phase 2's merged Connect/Receive screen): the plain
        # address (today's GenericStaticQrEncoder, unchanged) for a counterparty who
        # just needs a destination to send to, and Connect (crypto-hdkey) for a
        # wallet app (MetaMask/Rabby/etc.) importing this device as a
        # Keystone-compatible signer -- see EvmAddressView.run()'s dispatch below and
        # models/encode_qr.py's UrEvmConnectQrEncoder.
        self.button_data = [ButtonOption("Export Address QR"), ButtonOption("Export Connect QR")]
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

        address_display_y = derivation_path_display.screen_y + derivation_path_display.height + 2*GUIConstants.COMPONENT_PADDING
        # self.buttons[0].screen_y is ButtonListScreen's own already-computed start of
        # the button row (is_bottom_list=True anchors it to the bottom) -- the real,
        # measured boundary of available space, not a guessed constant.
        available_height = self.buttons[0].screen_y - GUIConstants.COMPONENT_PADDING - address_display_y

        address_display = FormattedAddress(
            address=self.address,
            screen_y=address_display_y,
            visible_height=available_height,
        )
        # No explicit thread wiring needed: FormattedAddress propagates its own
        # scroll thread into self.threads, which BaseScreen.get_threads() picks up
        # automatically from every component in self.components.
        self.components.append(address_display)



@dataclass
class EvmAddressVerifyPromptScreen(ButtonListScreen):
    """ Shown after an address or Connect QR export, right before returning Home --
        closes multi-chain-ux-verify-after-address-export (filed 2026-09-26, Jorge,
        reviewing docs/multi-chain/user-journeys.md #2/#3): "On exporting address via
        QR - I think it needs a verification step after successful QR scan."

        Unlike the sign flow (a full device-scans-request / wallet-scans-signature
        round trip, verified by the review-field screens along the way), a plain
        address or Connect QR export has no round-trip at all -- the device has no
        way to know whether or when a remote wallet actually scanned it. This forces
        a deliberate final check (re-displaying the address, requiring an explicit
        acknowledgment button) rather than relying on memory or informal habit before
        the operator backs out.

        `address` is None for the Connect QR case: that export is an account-level
        extended public key (crypto-hdkey), not a single address, so there is no one
        address to re-display -- the prompt text is generic instead. Applies to
        Export Address QR and Export Connect QR only (per the story's own scope);
        does NOT apply to the sign flow, which already has real round-trip
        verification, or to any Bitcoin address-export flow (that would be a bigger,
        separate decision -- Bitcoin's own address-export UX is stock SeedSigner
        behavior, not something this EVM-scoped story should change unasked). """
    address: str = None

    def __post_init__(self):
        # Short deliberately -- "Verify Before Continuing" clipped at the right edge
        # of TopNav's title area on real rendering (confirmed via a screenshot).
        self.title = _("Please Confirm")
        self.is_bottom_list = True
        self.is_button_text_centered = True
        # Mirrors SevenFUnsupportedArtefactView's own "single acknowledgment, no
        # meaningful alternative path" convention -- the export already happened;
        # "back" would only return to a QR screen that's no longer useful to re-show.
        self.show_back_button = False
        self.button_data = [ButtonOption("I've Verified This")]
        super().__post_init__()

        if self.address:
            instruction_text = _("Confirm this matches what your wallet shows:")
        else:
            # Connect QR is account-level (crypto-hdkey), not tied to one network --
            # UrEvmConnectQrEncoder itself takes no network param -- so no network
            # name to reference here.
            instruction_text = _("Confirm your wallet successfully imported this account before continuing.")

        instruction_display = IconTextLine(
            icon_name=SeedSignerIconConstants.WARNING,
            icon_color=GUIConstants.WARNING_COLOR,
            value_text=instruction_text,
            is_text_centered=True,
            auto_line_break=True,
            screen_y=self.top_nav.height + GUIConstants.COMPONENT_PADDING,
        )
        self.components.append(instruction_display)

        if self.address:
            address_display_y = instruction_display.screen_y + instruction_display.height + GUIConstants.COMPONENT_PADDING
            available_height = self.buttons[0].screen_y - GUIConstants.COMPONENT_PADDING - address_display_y
            address_display = FormattedAddress(
                address=self.address,
                screen_y=address_display_y,
                visible_height=available_height,
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
            # FIXED 2026-10-04 (multi-chain-evm-review-warning-detail-truncates):
            # same root cause as EvmAddressScreen's address truncation --
            # warning_detail used to have no height constraint at all, so a long
            # anti-scam warning silently ran off the bottom of the screen instead
            # of being fully readable. Jorge's own instruction, matching his
            # address-screen preference: "I suggest to have scroll down to show
            # the rest of the message." This is the exact security-relevant copy
            # the no-blind-signing design depends on the operator reading in
            # full, so the fix matters more here than on the address screen.
            detail_display_y = value_display.screen_y + value_display.height + GUIConstants.COMPONENT_PADDING
            available_height = self.buttons[0].screen_y - GUIConstants.COMPONENT_PADDING - detail_display_y

            detail_display = IconTextLine(
                icon_color=GUIConstants.DIRE_WARNING_COLOR,
                value_text=self.warning_detail,
                is_text_centered=True,
                auto_line_break=True,
                screen_y=detail_display_y,
                height=available_height,
                is_vertical_scrolling_enabled=True,
            )
            # No explicit thread wiring needed here: IconTextLine already propagates
            # its value_textarea's scroll thread into its own self.threads (mirrors
            # TopNav's self.title.scroll_thread pattern), and BaseScreen.get_threads()
            # picks up every component's threads automatically.
            self.components.append(detail_display)



@dataclass
class EvmConfirmSignScreen(ButtonListScreen):
    """ Final review step before signing: derivation path + the address the signature
        will be attributed to. Shared across every scenario, including `permit`
        (still a mocked signature -- see module docstring) -- so this screen can't
        claim "real" or "not real" for all cases; the per-field review pages already
        flag permit's off-chain-signature nature explicitly (see EvmReviewFieldScreen
        usage in evm_views.py), which is the right place for that distinction. """
    derivation_path: str = None
    address: str = None

    def __post_init__(self):
        self.title = _("Confirm & Sign")
        self.is_bottom_list = True
        self.is_button_text_centered = True
        self.button_data = [ButtonOption("Sign")]
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

        # FIXED 2026-10-04 (adversarial review of multi-chain-evm-screens-layout-
        # untested): this screen had no visible_height/auto-scroll fallback at all,
        # unlike EvmAddressScreen and EvmAddressVerifyPromptScreen -- it only avoided
        # the same truncation bug those two were fixed for by a ~12px margin on
        # today's font/content, not by design. Same available-height computation as
        # those two screens.
        address_display_y = derivation_path_display.screen_y + derivation_path_display.height + 2*GUIConstants.COMPONENT_PADDING
        available_height = self.buttons[0].screen_y - GUIConstants.COMPONENT_PADDING - address_display_y

        address_display = FormattedAddress(
            address=self.address,
            screen_y=address_display_y,
            visible_height=available_height,
        )
        self.components.append(address_display)
