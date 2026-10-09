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


# --- what is signed is what is read (adversarial review 2026-10-08) -----------------

@pytest.mark.parametrize("a, b", [
    ("́", "\\u0301"),        # a real combining mark vs the six typed characters
    ("\n", "\\n"),                # a real newline vs a typed backslash-n
    ("a  b", "a b"),              # the screen collapses runs of spaces
    (" a", "a"), ("a ", "a"),     # and drops them at line ends
    ("pаy", "pay"),          # Cyrillic a, a look-alike
    ("中", "二"),         # two characters the font draws as the same box
])
def test_two_different_texts_never_look_the_same(a, b):
    from seedsigner.models.sevenf.review_format import visible_text
    assert visible_text(a) != visible_text(b)


def test_ordinary_text_and_latin_letters_are_shown_as_they_are():
    from seedsigner.models.sevenf.review_format import visible_text
    for text in ("No meme coins. No spam. No scams. Only utility.", "café naïve Ångström"):
        assert visible_text(text) == text


def test_a_long_word_is_never_broken_inside_an_escape():
    from seedsigner.gui.screens.sevenf_screens import break_long_words

    class TenPxFont:
        def getlength(self, text):
            return 10 * len(text)

    out = break_long_words("\\u0301" * 6 + "\\\\" * 3, width=100, font=TenPxFont())
    for line in out.split("\n"):
        assert not line.endswith("\\") or line.endswith("\\\\"), out
        assert "\\u" not in line or all(len(part) >= 4 for part in line.split("\\u")[1:]), out


def test_every_subject_key_id_is_one_page():
    """ A key id is read aloud and compared as a whole: its warning is kept
        to one line so the 10 groups fit one page (Jorge, 2026-10-09: the
        Deputy review split each ski over three pages). """
    from seedsigner.models.sevenf import cert_request
    from seedsigner.models.sevenf.cert_request import ParsedCsr, ParsedRootCertificate
    from seedsigner.models.sevenf.constants import ChainKind

    vk = bytes(range(256)) * 7 + bytes(160)
    root = ParsedRootCertificate(subject_vk=vk, not_before=1_790_000_000, not_after=2_400_000_000,
                                 chain_kind=ChainKind.TESTNET)
    fields = [f for f in cert_request.deputy_cross_cert_v2_review_fields(
                  root, ParsedCsr(subject_vk=vk[::-1]), ChainKind.TESTNET, 1_800_000_000, 3650, bytes(16))
              + cert_request.root_self_cert_review_fields(vk, ChainKind.TESTNET, 1_800_000_000, 2_400_000_000, bytes(16))
              + cert_request.root_certificate_review_fields(root)
              if "Subject key id" in f.label]
    assert len(fields) == 4
    for field in fields:
        pages = _review_pages([field])
        assert len(pages) == 1, (field.label, [p.value for p in pages])
        assert pages[0].value == field.value
