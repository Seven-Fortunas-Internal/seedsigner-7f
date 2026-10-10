"""
    Tests seedsigner.helpers.qr.QR.qrimage_io() -- specifically a real
    shell-injection/truncation bug found live during the 7F hardware
    walkthrough: the previous implementation built a `shell=True` command
    string by interpolating QR data directly inside double quotes. Any data
    containing a literal "$" (e.g. every BBQr segment, which starts with
    "B$" -- see models/encode_qr.py's BBQrEncoder) triggered shell variable
    expansion, silently truncating the data down to whatever preceded the
    "$" before it ever reached the qrencode binary. No prior data type in
    this codebase happened to contain a shell metacharacter this early in
    its content, so this was a latent bug until BBQr existed.

    Requires the `qrencode` binary to be installed (it is on both this dev
    machine and the real device) -- these tests exercise the real
    subprocess path, not a mock, since the bug was specifically in how that
    subprocess call was constructed.
"""
import shutil

import pytest
from pyzbar import pyzbar

from seedsigner.helpers.qr import QR

pytestmark = pytest.mark.skipif(
    shutil.which("qrencode") is None,
    reason="qrencode binary not installed -- these tests exercise the real subprocess path",
)


def _decode(image) -> bytes:
    results = pyzbar.decode(image.convert("L"))
    assert len(results) == 1, f"expected exactly one QR code in the image, got {len(results)}"
    return results[0].data


def test_qrimage_io_round_trips_data_containing_a_dollar_sign():
    """ Regression test for the exact bug: a real BBQr-shaped segment
        string, starting with "B$" like every BBQr segment does, must
        decode back to the exact original string -- not truncated to just
        "B" by shell variable expansion. """
    qr = QR()
    data = "B$ZU0C00SOMEBASE32PAYLOADCONTENT"
    image = qr.qrimage_io(data, width=300, height=300)
    assert _decode(image) == data.encode()


def test_qrimage_io_produces_different_images_for_different_dollar_prefixed_data():
    """ The actual observed symptom on real hardware: every BBQr segment of
        a multi-segment export rendered as the exact same image, because
        they all got silently collapsed to the same truncated "B" string.
        Confirms two genuinely different segments now render as genuinely
        different images. """
    qr = QR()
    image1 = qr.qrimage_io("B$ZU0C00SEGMENTONEDATA", width=200, height=200)
    image2 = qr.qrimage_io("B$ZU0C01SEGMENTTWODATA", width=200, height=200)
    assert image1.tobytes() != image2.tobytes()


def test_qrimage_io_round_trips_various_shell_metacharacters():
    """ "$" was the specific trigger found live, but the underlying fix
        (argv list, no shell) is general -- confirms other shell-special
        characters round-trip correctly too, not just "$". """
    qr = QR()
    for data in ["a`b`c", "a;b;c", "a|b|c", "a&b&c", "a$(b)c", "a$b$c"]:
        image = qr.qrimage_io(data, width=300, height=300)
        assert _decode(image) == data.encode(), f"failed to round-trip: {data!r}"


def test_qrimage_io_falls_back_to_pure_python_when_qrencode_binary_is_missing(monkeypatch):
    """ Regression test for a gap the fix itself could have introduced:
        removing shell=True means a missing `qrencode` binary now raises
        FileNotFoundError from subprocess.run() instead of the shell
        reporting a non-zero exit code -- confirms that's still caught and
        still falls back to the pure-Python qrimage() renderer, matching
        the pre-fix fallback behavior for this case. """
    import subprocess as subprocess_module

    def fake_run(cmd, *args, **kwargs):
        raise FileNotFoundError("qrencode: no such file or directory")

    qr = QR()
    with pytest.MonkeyPatch().context() as mp:
        mp.setattr(subprocess_module, "run", fake_run)
        image = qr.qrimage_io("some data", width=100, height=100)

    # The pure-Python fallback (qrimage()) must still produce a real, decodable image.
    assert _decode(image) == b"some data"


def _record_qrencode_argv(monkeypatch):
    """ Wraps subprocess.run so a test can see the qrencode argv while the
        real binary still runs. """
    import subprocess as subprocess_module
    seen = []
    real = subprocess_module.run

    def wrapper(cmd, *args, **kwargs):
        seen.append(list(cmd))
        return real(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess_module, "run", wrapper)
    return seen


def test_qrimage_io_writes_no_file(monkeypatch):
    """ The PNG comes back on stdout (-o -). A fixed /tmp/qrcode.png made
        concurrent renders collide (flaky tests) and left the last QR,
        possibly a SeedQR, on disk. """
    seen = _record_qrencode_argv(monkeypatch)
    image = QR().qrimage_io("no file please", width=200, height=200)
    assert _decode(image) == b"no file please"
    assert seen, "qrencode was not called"
    argv = seen[0]
    assert argv[argv.index("-o") + 1] == "-"


def test_qrimage_io_concurrent_renders_do_not_collide():
    """ Many renders at once each decode to their own data. """
    from concurrent.futures import ThreadPoolExecutor
    data = [f"render-{i}-" + "x" * i for i in range(24)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        images = list(pool.map(lambda d: QR().qrimage_io(d, width=240, height=240), data))
    assert [_decode(img) for img in images] == [d.encode() for d in data]


def test_qrimage_io_falls_back_when_qrencode_output_is_not_an_image(monkeypatch):
    """ A qrencode that exits 0 but prints no PNG must not crash the
        screen: the pure-Python renderer takes over. """
    import subprocess as subprocess_module

    def fake_run(cmd, *args, **kwargs):
        return subprocess_module.CompletedProcess(cmd, 0, stdout=b"not a png", stderr=b"")

    monkeypatch.setattr(subprocess_module, "run", fake_run)
    image = QR().qrimage_io("fallback data", width=200, height=200)
    assert _decode(image) == b"fallback data"


def test_qrimage_io_falls_back_when_qrencode_hangs(monkeypatch):
    """ A qrencode that never returns times out into the pure-Python
        renderer instead of freezing the screen. """
    import subprocess as subprocess_module

    def fake_run(cmd, *args, **kwargs):
        assert kwargs.get("timeout"), "qrencode must run with a timeout"
        raise subprocess_module.TimeoutExpired(cmd, kwargs["timeout"])

    monkeypatch.setattr(subprocess_module, "run", fake_run)
    image = QR().qrimage_io("hung qrencode", width=200, height=200)
    assert _decode(image) == b"hung qrencode"
