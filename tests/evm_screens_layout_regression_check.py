"""
    Real-rendering regression tests for gui/screens/evm_screens.py.

    Every test in tests/test_flows_evm.py patches view.run_screen() directly, so the
    actual Screen dataclasses -- and the layout math in their __post_init__ bodies --
    are never instantiated or rendered by anything that runs today. That is exactly
    how two real bugs (EvmAddressScreen silently truncating a 42-char address;
    EvmReviewFieldScreen's warning_detail running off the bottom of the screen) were
    found only by hand, via a one-off screenshot script, with no regression
    protection once fixed (multi-chain-evm-screens-layout-untested).

    This file closes that gap by using the project's own ScreenshotRenderer (real,
    non-mocked PIL rendering, the same utility tests/screenshot_generator/generator.py
    uses) to actually instantiate and render each EVM screen, then asserting on the
    concrete layout properties that those two bugs broke: scroll-engagement flags,
    computed available-height, and component structure.

    Like generator.py, this file must be run as its own, separate pytest invocation:

        pytest tests/evm_screens_layout_regression_check.py

    not swept into a broader `pytest tests/` run -- and, also like generator.py, its
    filename deliberately does NOT match pytest's default test_*.py/*_test.py
    discovery glob, specifically so a bare `pytest` or `pytest tests/` run does not
    auto-collect it. Confirmed by hand (2026-10-04): with a test_*.py name, a bare
    `pytest tests/` run genuinely breaks with "Mock object has no attribute
    'configure_instance'" -- tests/base.py (imported by most of this project's other
    test files) permanently replaces sys.modules['seedsigner.gui.renderer'] with a
    MagicMock as an import side effect, with no per-test teardown, so whichever file
    happens to import first inside one pytest process wins for the rest of that
    process. The non-matching filename sidesteps that the same way generator.py
    already does, rather than fighting it.
"""
import os
import sys
from unittest.mock import MagicMock

import pytest

REPO_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
SCREENSHOT_UTILS_DIR = os.path.join(os.path.dirname(__file__), "screenshot_generator")
sys.path.insert(0, REPO_SRC)
sys.path.insert(0, SCREENSHOT_UTILS_DIR)

sys.modules["seedsigner.hardware.displays.st7789_mpy"] = MagicMock()
sys.modules["seedsigner.hardware.displays.ili9341"] = MagicMock()
sys.modules["RPi"] = MagicMock()
sys.modules["RPi.GPIO"] = MagicMock()
sys.modules["seedsigner.hardware.camera.Camera"] = MagicMock()
sys.modules["seedsigner.hardware.microsd"] = MagicMock()

from seedsigner.gui.renderer import Renderer  # noqa: E402
from utils import ScreenshotComplete, ScreenshotRenderer  # noqa: E402

ScreenshotRenderer.configure_instance()
_screenshot_renderer: ScreenshotRenderer = ScreenshotRenderer.get_instance()
Renderer.configure_instance = lambda: None
Renderer.get_instance = classmethod(lambda cls: _screenshot_renderer)

from seedsigner.gui.screens.evm_screens import (  # noqa: E402
    EvmAddressScreen,
    EvmAddressVerifyPromptScreen,
    EvmConfirmSignScreen,
    EvmReviewFieldScreen,
    EvmSelectAddressIndexScreen,
)

REAL_ADDRESS = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"
LONG_WARNING = (
    "Not seen before on this device. Double-check this address carefully -- "
    "lookalike addresses in transaction history are a documented scam vector. "
    "If you are not expecting a new address here, stop and verify out of band "
    "before continuing."
)


def render_static(screen):
    """ Render a screen's initial static frame directly via _render(), bypassing
        display()'s thread-starting / blocking input loop (there is no real input
        device in this process). ScreenshotRenderer.show_image() raises
        ScreenshotComplete as its own normal control-flow exit after saving a PNG to
        disk -- irrelevant to these tests, so it is discarded. """
    _screenshot_renderer.set_screenshot_path("/tmp")
    _screenshot_renderer.set_screenshot_filename("_test_evm_screens_layout_scratch.png")
    try:
        screen._render()
    except ScreenshotComplete:
        pass
    return screen


def test_evm_select_address_index_screen_renders_without_crashing():
    screen = EvmSelectAddressIndexScreen()
    render_static(screen)


def test_evm_address_screen_scrolls_for_a_real_evm_address():
    # Regression check for multi-chain-evm-address-screen-truncates: a real 42-char
    # "0x" + 40-hex-digit address needs more vertical space than this screen has
    # available, so it must engage vertical auto-scroll rather than silently
    # truncating or rendering past the button row.
    screen = EvmAddressScreen(
        derivation_path="m/44'/60'/0'/0/0",
        address=REAL_ADDRESS,
        network_name="Ethereum",
    )
    render_static(screen)

    address_display = screen.components[-1]
    assert address_display.needs_vertical_scroll is True
    assert address_display.visible_height > 0


def test_evm_address_screen_available_height_is_derived_from_the_real_button_row():
    screen = EvmAddressScreen(
        derivation_path="m/44'/60'/0'/0/0",
        address=REAL_ADDRESS,
        network_name="Ethereum",
    )
    render_static(screen)

    address_display = screen.components[-1]
    # Regression check: available_height must come from the real, already-computed
    # button row position, not a guessed constant -- if a future change breaks that
    # computation (e.g. an off-by-one in a layout refactor), this would start
    # producing a non-positive height before anything else here would notice.
    expected = screen.buttons[0].screen_y - address_display.screen_y
    assert address_display.visible_height <= expected
    assert address_display.visible_height > 0


@pytest.mark.parametrize("address", [REAL_ADDRESS, None])
def test_evm_address_verify_prompt_screen_renders_for_both_variants(address):
    screen = EvmAddressVerifyPromptScreen(address=address)
    render_static(screen)

    if address:
        # TopNav + instruction line + address display
        assert len(screen.components) == 3
        address_display = screen.components[-1]
        assert address_display.address == address
    else:
        # Connect QR case: no single address to re-display. TopNav + instruction line.
        assert len(screen.components) == 2


def test_evm_review_field_screen_without_warning_has_no_detail_component():
    screen = EvmReviewFieldScreen(
        page_title="Review Request",
        label_text="Network",
        value_text="Ethereum Mainnet",
        is_warning=False,
        is_final_page=True,
    )
    render_static(screen)

    # TopNav + value display, no detail component at all.
    assert len(screen.components) == 2


def test_evm_review_field_screen_short_warning_does_not_need_scroll():
    screen = EvmReviewFieldScreen(
        page_title="Review Request",
        label_text="Amount",
        value_text="0.5 ETH",
        warning_detail="Short warning that fits fine.",
        is_warning=True,
        is_final_page=True,
    )
    render_static(screen)

    detail_display = screen.components[-1]
    assert detail_display.needs_vertical_scroll is False


def test_evm_review_field_screen_long_warning_needs_scroll_and_fits_on_screen():
    # Regression check for multi-chain-evm-review-warning-detail-truncates: a long
    # anti-scam warning must engage vertical auto-scroll rather than running off the
    # bottom of the screen -- this is the exact security-relevant copy the
    # no-blind-signing design depends on the operator reading in full.
    screen = EvmReviewFieldScreen(
        page_title="Review Request",
        label_text="To",
        value_text=REAL_ADDRESS,
        warning_detail=LONG_WARNING,
        is_warning=True,
        is_final_page=False,
    )
    render_static(screen)

    # TopNav + value display + detail display.
    assert len(screen.components) == 3
    detail_display = screen.components[-1]
    assert detail_display.needs_vertical_scroll is True


def test_evm_address_screen_wraps_a_long_unbroken_derivation_path():
    # Regression check for the module docstring's own real-hardware finding: a long
    # unbroken run of characters (no spaces for auto_line_break to split on) must get
    # an explicit \n from _wrap_long_value_for_display's slash-aware split, or it will
    # overflow the screen width and can push IconTextLine's centering math negative,
    # clipping the label too.
    long_path = "m/44'/60'/2147483647'/0/999999999"  # 34 chars, no spaces
    screen = EvmAddressScreen(
        derivation_path=long_path,
        address=REAL_ADDRESS,
        network_name="Ethereum",
    )
    render_static(screen)

    derivation_display = screen.components[1]
    assert "\n" in derivation_display.value_text


def test_evm_review_field_screen_shows_page_number_when_paginated():
    screen = EvmReviewFieldScreen(
        page_title="Review Request",
        label_text="Spender",
        value_text="0x0000000000000000000000000000000000dEaD",
        page_num=1,
        num_pages=3,
        is_warning=False,
        is_final_page=False,
    )
    render_static(screen)

    assert screen.title == "Review Request (2/3)"


def test_evm_confirm_sign_screen_has_a_scroll_safety_net_for_a_real_evm_address():
    # Regression check: this screen had no visible_height/auto-scroll fallback at
    # all until 2026-10-04, unlike EvmAddressScreen and EvmAddressVerifyPromptScreen
    # -- it only avoided the same truncation bug those two were fixed for by a
    # ~12px margin on today's font/content, not by design. With a single button
    # (vs. EvmAddressScreen's two), this screen's own available_height
    # comfortably fits a real 42-char address even now -- needs_vertical_scroll
    # correctly stays False -- but visible_height must be set (not None) so a
    # future longer address/font/locale falls back to scrolling instead of
    # silently overflowing again.
    screen = EvmConfirmSignScreen(
        derivation_path="m/44'/60'/0'/0/0",
        address=REAL_ADDRESS,
    )
    render_static(screen)
    # TopNav + derivation path display + address display.
    assert len(screen.components) == 3
    address_display = screen.components[-1]
    assert address_display.visible_height is not None
    assert address_display.visible_height > 0
    assert address_display.needs_vertical_scroll is False


def test_evm_confirm_sign_screen_scrolls_when_a_long_derivation_path_shrinks_available_height():
    # Confirms the safety net above actually engages, not just that it's wired: a
    # longer derivation path eats into this screen's available height (same
    # single-button budget as the test above) until even a real address no longer
    # fits, and auto-scroll must take over instead of overflowing again.
    screen = EvmConfirmSignScreen(
        derivation_path="m/44'/60'/2147483647'/999999999/999999999",
        address=REAL_ADDRESS,
    )
    render_static(screen)

    address_display = screen.components[-1]
    assert address_display.needs_vertical_scroll is True
