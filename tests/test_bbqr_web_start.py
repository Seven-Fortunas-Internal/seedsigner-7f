"""
    The 7F Signer page's Start view (Jorge, 2026-10-08): what opens at the bare
    URL, before either direction. It says when to use each tab and what to do
    there, and how the pin and the subject key id come from the key, so an
    operator can recompute them. Text checks only; no Node needed.
"""
from pathlib import Path

TOOL_DIR = Path(__file__).resolve().parent.parent / "tools" / "bbqr_web_scanner"


def _html() -> str:
    return (TOOL_DIR / "index.html").read_text()


def _section(section_id: str) -> str:
    html = _html()
    return html.split(f'<section id="{section_id}"', 1)[1].split("</section>", 1)[0]


def test_start_is_a_tab_and_the_default_view():
    html = _html()
    assert 'href="#start"' in html
    app = (TOOL_DIR / "app.js").read_text()
    assert '"start"' in app
    assert ': "start"' in app  # an unknown or empty hash falls back to Start


def test_the_camera_starts_only_on_from_device():
    """ Opening the page must not ask for the camera: Start stops both tabs. """
    app = (TOOL_DIR / "app.js").read_text()
    body = app.split("function showTab()", 1)[1]
    assert 'if (current === "from-device")' in body
    assert "window.ScanTab.stop();" in body and "window.SendTab.stop();" in body


def test_start_says_when_to_use_each_direction():
    start = _section("start")
    assert 'href="#from-device"' in start and 'href="#to-device"' in start
    for menu in ("7F: Enroll Root (export VK)", "7F: Enroll Dev-fund (export VK)", "7F: Self-Certify Root",
                 "7F: Sign Genesis Config", "7F: Sign Devfund Config", "7F: Cross-Certify Deputy"):
        assert menu in start, menu


def test_start_explains_how_pin_and_ski_are_derived():
    start = _section("start")
    assert "SHA-256" in start
    assert "first 20 bytes" in start and "first 40 hex" in start
    assert "RFC 7093" in start
    assert "xxd -r -p" in start and "sha256sum" in start   # recompute it yourself
    assert "by phone" in start or "aloud" in start          # the pin is a voice check


def test_start_explains_the_key_index():
    start = _section("start")
    assert "Index 0 (default)" in start
    assert "root/&lt;network&gt;/&lt;index&gt;/ml-dsa/v1" in start


def test_start_explains_to_device_checks():
    start = _section("start")
    assert "Canonical digest" in start           # the device, not the page, is the authority
    assert "Show QR to the device" in start
    assert "DER" in start


def test_start_keeps_the_page_policy():
    """ Same CSP rules as the rest of the page: no inline style or script. """
    html = _html()
    assert "style=" not in html and "<script>" not in html
