"""
    Real-rendering check of the 7F review pages: every page of a worst-case
    value draws all its text, and its warning, above the button (security and
    adversarial reviews 2026-10-08: 180-character pages hid their last lines
    under "Next"). Run on its own, like evm_screens_layout_regression_check.py
    (whose docstring says why the name does not match test_*.py):

        pytest tests/sevenf_review_layout_regression_check.py
"""
import os
import sys
from unittest.mock import MagicMock

import pytest

REPO_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, REPO_SRC)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "screenshot_generator"))
for module in ("seedsigner.hardware.displays.st7789_mpy", "seedsigner.hardware.displays.ili9341", "RPi", "RPi.GPIO",
               "seedsigner.hardware.camera.Camera", "seedsigner.hardware.microsd"):
    sys.modules[module] = MagicMock()

from seedsigner.gui.renderer import Renderer  # noqa: E402
from utils import ScreenshotComplete, ScreenshotRenderer  # noqa: E402

ScreenshotRenderer.configure_instance()
_renderer: ScreenshotRenderer = ScreenshotRenderer.get_instance()
Renderer.configure_instance = lambda: None
Renderer.get_instance = classmethod(lambda cls: _renderer)

from seedsigner.gui.screens.sevenf_screens import SevenFReviewFieldScreen  # noqa: E402
from seedsigner.models.review import ReviewField  # noqa: E402
from seedsigner.views.sevenf_views._common import _review_pages  # noqa: E402

WARNING = "This recipient receives the ENTIRE genesis reward."
VALUES = {
    "wide": "W" * 400,
    "hex": "a1" * 200,
    "words": "word " * 80,
    "caps": "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG " * 8,
    "escapes": "\\u0301\\u200b\\n" * 40,
    "grouped": " ".join(["4a3f"] * 64),
}


def _render(screen):
    _renderer.set_screenshot_path("/tmp")
    _renderer.set_screenshot_filename("_sevenf_review_layout_scratch.png")
    try:
        screen._render()
    except ScreenshotComplete:
        pass
    return screen


@pytest.mark.parametrize("name", sorted(VALUES))
@pytest.mark.parametrize("warning", ["", WARNING])
def test_every_page_draws_above_the_button(name, warning):
    pages = _review_pages([ReviewField(label="Message", value=VALUES[name], is_warning=bool(warning), warning_detail=warning)])
    assert "".join(p.value for p in pages) == VALUES[name]
    for i, page in enumerate(pages):
        screen = _render(SevenFReviewFieldScreen(
            page_title="Genesis", label_text=page.label, value_text=page.value, warning_detail=page.warning_detail,
            is_warning=page.is_warning, page_num=i, num_pages=len(pages), is_final_page=i == len(pages) - 1))
        button_top = screen.buttons[0].screen_y
        texts = [c for c in screen.components if type(c).__name__ == "IconTextLine"]
        for text in texts:
            assert text.screen_y + text.height <= button_top, (name, i, page.value)
