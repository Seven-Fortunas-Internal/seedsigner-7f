"""
    A review page never draws signed text under the screen's button (security
    and adversarial reviews 2026-10-08: 180-character pages hid their last
    lines). Pages are cut by the lines the screen draws; the pages joined are
    the value; paging a long value is fast. The real-renderer check is
    tests/sevenf_review_layout_regression_check.py.
"""
import random
import time

import pytest

from base import FlowTest  # noqa: F401  (mocks the hardware before the views import)
from seedsigner.gui.screens.sevenf_screens import review_lines_per_page, review_value_lines
from seedsigner.views.sevenf_views._common import _paginate_value, _review_pages
from seedsigner.models.review import ReviewField

WARNING = "This recipient receives the ENTIRE genesis reward."


def _random_text(rng: random.Random) -> str:
    pieces = []
    for _ in range(rng.randint(1, 60)):
        kind = rng.random()
        if kind < 0.6:
            pieces.append("".join(rng.choice("aeiouWMlnrst0123") for _ in range(rng.randint(1, 9))))
        elif kind < 0.8:
            pieces.append("W" * rng.randint(10, 60))
        else:
            pieces.append(rng.choice(["\\u0301", "7Fchain-testnet-genesis", "ab" * 20]))
    return " ".join(pieces)


@pytest.mark.parametrize("size", [(240, 240), (320, 240), (240, 320)])
@pytest.mark.parametrize("warning", ["", WARNING])
def test_every_page_fits_and_the_pages_are_the_value(monkeypatch, size, warning):
    from seedsigner.gui.screens import sevenf_screens
    monkeypatch.setattr(sevenf_screens, "display_size", lambda: size)
    rng = random.Random(f"{size}{warning}")
    max_lines = review_lines_per_page(*size, warning)
    for _ in range(40):
        text = _random_text(rng)
        pages = [p.value for p in _review_pages([ReviewField(label="Message", value=text, is_warning=bool(warning),
                                                              warning_detail=warning)])]
        assert "".join(pages) == text
        assert all(review_value_lines(p, size[0]) <= max_lines for p in pages), pages


def test_a_long_value_is_paged_in_one_layout_pass_per_page():
    """ About 16 ms a page on a desktop, measuring the real font. Ceremony
        values are under 1 KB (a few pages); a hostile multi-kilobyte message
        is slow but finite, and the operator can power off. """
    value = ("word " * 1_000) + ("W" * 1_000)
    start = time.monotonic()
    pages = _review_pages([ReviewField(label="Message", value=value)])
    assert "".join(p.value for p in pages) == value
    assert time.monotonic() - start < 15
