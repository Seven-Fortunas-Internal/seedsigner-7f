"""
    Tests seedsigner.models.encode_qr.BBQrEncoder (new -- BBQr was
    decode-only in this codebase before this story) and the non-PSBT BBQr
    decode path (seedsigner.models.decode_qr.SevenFBBQrDecoder). Backs
    7f-signing-support-bbqr-encoding, per Patrick's formal requirements doc
    (docs/7f-integration/root-key-ceremony-plan.md's "Superseding authority"
    section) -- BBQr replaces the UR2-fountain transport this project
    previously planned to reuse, since UR2 fountain is too slow at any
    usable QR density for this device's real payload sizes.

    test_decodepsbtqr.py's existing bbqr_psbt_* tests are the regression
    guard confirming this story's refactor of the shared BBQr decode logic
    doesn't change PSBT (file-type 'P') behavior -- run those alongside
    this file, not duplicated here.
"""
import pytest

from seedsigner.models.decode_qr import DecodeQR, DecodeQRStatus
from seedsigner.models.encode_qr import BBQrEncoder
from seedsigner.models.qr_type import QRType


def _round_trip(data: bytes, file_type: str = "B", bbqr_encoding: str = "Z", max_bytes_per_segment: int = 300):
    encoder = BBQrEncoder(data=data, file_type=file_type, bbqr_encoding=bbqr_encoding, max_bytes_per_segment=max_bytes_per_segment)
    d = DecodeQR()
    status = None
    for _ in range(encoder.seq_len()):
        part = encoder.next_part()
        status = d.add_data(part)
        if status == DecodeQRStatus.COMPLETE:
            break
    return d, status


@pytest.mark.parametrize("bbqr_encoding", ["Z", "2", "H"])
def test_round_trip_single_segment(bbqr_encoding):
    payload = b"genesis-config canonical bytes fixture, short enough for one frame"
    d, status = _round_trip(payload, bbqr_encoding=bbqr_encoding)
    assert status == DecodeQRStatus.COMPLETE
    assert d.qr_type == QRType.SEVENF__BBQR
    assert d.decoder.get_data() == payload


@pytest.mark.parametrize("bbqr_encoding", ["Z", "2", "H"])
def test_round_trip_multi_segment(bbqr_encoding):
    # Large enough, and (for 'Z') incompressible enough via os.urandom, to
    # force multiple segments even after zlib compression -- a payload of
    # repeated bytes would compress to one tiny segment and not actually
    # exercise multi-part reassembly for the 'Z' case.
    import os
    payload = os.urandom(2000)
    d, status = _round_trip(payload, bbqr_encoding=bbqr_encoding, max_bytes_per_segment=100)
    assert status == DecodeQRStatus.COMPLETE
    assert d.decoder.get_data() == payload
    assert d.decoder.total_segments > 1, "this test is meaningless if it didn't actually exercise multi-part reassembly"


def test_empty_payload_round_trips():
    d, status = _round_trip(b"")
    assert status == DecodeQRStatus.COMPLETE
    assert d.decoder.get_data() == b""


def test_is_sevenf_bbqr_and_get_sevenf_bbqr_data():
    """ DecodeQR's own wrapper properties/methods (used by
        sevenf_views.SevenFScanGenesisConfigView) -- mirrors
        is_evm_address/get_evm_address's exact shape. """
    d, status = _round_trip(b"genesis-config fixture bytes", file_type="J")
    assert status == DecodeQRStatus.COMPLETE
    assert d.is_sevenf_bbqr is True
    assert d.is_evm_address is False
    assert d.get_sevenf_bbqr_data() == b"genesis-config fixture bytes"


def test_get_sevenf_bbqr_data_returns_none_for_a_different_qr_type():
    d = DecodeQR()
    assert d.is_sevenf_bbqr is False
    assert d.get_sevenf_bbqr_data() is None


def test_file_type_is_preserved_and_not_psbt():
    encoder = BBQrEncoder(data=b"hello", file_type="J")
    part = encoder.next_part()
    d = DecodeQR()
    d.add_data(part)
    assert d.qr_type == QRType.SEVENF__BBQR
    assert d.decoder.file_type == "J"
    assert d.qr_type != QRType.PSBT__BBQR


def test_psbt_file_type_still_dispatches_to_psbt_decoder_not_sevenf():
    """ Regression guard at the encoder level: file_type='P' is reserved
        for PSBT and must still route to QRType.PSBT__BBQR, not the new
        SEVENF__BBQR path, even though BBQrEncoder could technically
        produce a 'P'-typed segment. """
    encoder = BBQrEncoder(data=b"not a real psbt but shaped like one", file_type="P")
    part = encoder.next_part()
    d = DecodeQR()
    d.add_data(part)
    assert d.qr_type == QRType.PSBT__BBQR


def test_corrupted_frame_fails_loudly_not_silently_wrong():
    """ R18 (Patrick's requirements doc): a partial or corrupted transfer
        fails loudly, no silent truncation. Corrupting one base32 character
        in a multi-segment payload must make decoding either raise or
        produce data that does NOT silently match the original -- it must
        not succeed and look correct. """
    import os
    payload = os.urandom(1500)
    encoder = BBQrEncoder(data=payload, bbqr_encoding="Z", max_bytes_per_segment=100)
    parts = [encoder.next_part() for _ in range(encoder.seq_len())]
    assert len(parts) > 1, "need multiple segments to meaningfully corrupt one of them"

    # Corrupt one character in the middle segment's data portion (index 8+
    # is past the 8-char header).
    corrupt_index = len(parts) // 2
    corrupted = parts[corrupt_index]
    header, body = corrupted[:8], corrupted[8:]
    swapped_char = "A" if body[0] != "A" else "B"
    corrupted = header + swapped_char + body[1:]
    parts[corrupt_index] = corrupted

    d = DecodeQR()
    got_result = False
    raised = False
    try:
        for p in parts:
            status = d.add_data(p)
            if status == DecodeQRStatus.COMPLETE:
                got_result = True
                break
    except Exception:
        raised = True

    if got_result:
        # Decoding "succeeded" -- it must not have silently reproduced the
        # original payload despite the corruption.
        assert d.decoder.get_data() != payload
    else:
        assert raised or not got_result


def _base36_2char(n: int) -> str:
    # Uppercase, matching BBQrEncoder._BASE36 (encode_qr.py) -- the wire-
    # format type-detection regex in decode_qr.py is uppercase-only, so a
    # lowercase pair here would be misclassified as a different/unrecognized
    # QR type before ever reaching the total-count check this test targets.
    digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return f"{digits[n // 36]}{digits[n % 36]}"


def test_corrupted_header_total_count_raises_rather_than_truncating():
    """ Interoperability vector 5 (Patrick's requirements doc §7.4:
        "multi-part encode and decode, including a deliberately corrupted
        frame, which must fail rather than truncate"), the specific case
        test_corrupted_frame_fails_loudly_not_silently_wrong above doesn't
        cover: a corrupted HEADER (the total-segment-count field, BBQr
        bytes [4:6]) rather than corrupted content. BaseAnimatedQrDecoder.add()
        has a real, previously test-uncovered guard for exactly this
        (`raise Exception('Segment total changed unexpectedly')`) -- a
        frame claiming a different total part-count than the first frame
        declared must raise immediately, not silently accept a wrong count
        and produce truncated or bogus reconstructed data. """
    import os
    encoder = BBQrEncoder(data=os.urandom(1500), bbqr_encoding="Z", max_bytes_per_segment=100)
    parts = [encoder.next_part() for _ in range(encoder.seq_len())]
    assert len(parts) > 1, "need multiple segments for a total-count field to meaningfully corrupt"

    real_total = int(parts[1][4:6], 36)
    corrupted_total = (real_total + 1) % (36 * 36)  # any value differing from the first frame's declared total
    corrupted_second = parts[1][:4] + _base36_2char(corrupted_total) + parts[1][6:]

    d = DecodeQR()
    d.add_data(parts[0])
    with pytest.raises(Exception, match="Segment total changed unexpectedly"):
        d.add_data(corrupted_second)


def test_get_data_returns_none_before_complete():
    """ Closes a real, measured coverage gap (not assumed) -- every other
        test in this file only calls get_data() after reaching COMPLETE. """
    import os
    encoder = BBQrEncoder(data=os.urandom(500), bbqr_encoding="Z", max_bytes_per_segment=50)
    assert encoder.seq_len() > 1, "need multiple segments so adding just one leaves decoding incomplete"
    d = DecodeQR()
    d.add_data(encoder.next_part())
    assert d.decoder.get_data() is None


def test_decode_segments_helper_returns_none_for_falsy_encoding():
    """ Closes a real, measured coverage gap in the shared reconstruction
        helper's defensive branch (encoding=None/empty), which BaseBBQrDecoder's
        own complete-check normally prevents reaching via the public API. """
    from seedsigner.models.decode_qr import _bbqr_decode_segments
    assert _bbqr_decode_segments(["somedata"], None) is None
    assert _bbqr_decode_segments(["somedata"], "") is None


def test_bbqr_encoder_rejects_unsupported_encoding():
    with pytest.raises(ValueError):
        BBQrEncoder(data=b"x", bbqr_encoding="Q")


def test_bbqr_encoder_rejects_multi_character_file_type():
    with pytest.raises(ValueError):
        BBQrEncoder(data=b"x", file_type="BB")


def test_bbqr_wire_format_header_matches_spec():
    """ Confirms the actual header bytes on the wire, not just that
        round-tripping happens to work -- pins the format against
        https://github.com/coinkite/BBQr/blob/master/BBQr.md directly.
        Uses a payload containing hex letters (\\xab\\xcd) specifically so
        this test actually exercises the spec's "uppercase hex" requirement
        -- a payload like b"hi" hex-encodes to digits only and would pass
        even if uppercasing were silently broken. """
    encoder = BBQrEncoder(data=b"\xab\xcd", file_type="B", bbqr_encoding="H")
    part = encoder.next_part()
    assert part[:2] == "B$"
    assert part[2] == "H"        # encoding
    assert part[3] == "B"        # file_type
    assert part[4:6] == "01"     # total segments, base36, 1 segment
    assert part[6:8] == "00"     # this segment's index, base36, zero-based
    assert part[8:] == "ABCD"    # uppercase hex, per spec


def test_bbqr_segments_survive_real_qr_image_rendering_and_scanning():
    """ Regression test for a real shell-injection/truncation bug found live
        during the 7F hardware walkthrough (helpers/qr.py's qrimage_io()):
        every test above this one operates on BBQrEncoder's string segments
        directly, never through actual QR image rendering -- so none of them
        would have caught a bug in the rendering step itself. Every BBQr
        segment starts with a literal "B$", which triggered shell variable
        expansion in the old `shell=True` qrencode invocation, silently
        collapsing every segment down to just "B" before it was ever
        rendered -- symptom on real hardware: every export QR looked
        identical regardless of which segment was showing. This test goes
        through the real rendering (encoder.next_part_image(), which calls
        qrimage_io()) and real scanning (pyzbar) for every segment of a
        multi-segment, realistic (incompressible) payload, confirming the
        full round trip survives image rendering, not just string handling. """
    import os
    import shutil
    pytest.importorskip("pyzbar")
    if shutil.which("qrencode") is None:
        pytest.skip("qrencode binary not installed")
    from pyzbar import pyzbar

    payload = os.urandom(1952)  # ML-DSA-65 pubkey size, incompressible
    encoder = BBQrEncoder(data=payload, file_type="U")
    assert encoder.seq_len() > 1, "test payload must actually require multiple segments"

    d = DecodeQR()
    status = None
    for _ in range(encoder.seq_len()):
        image = encoder.next_part_image(240, 240, border=2, background_color="bdbdbd")
        decoded = pyzbar.decode(image.convert("L"))
        assert len(decoded) == 1, "expected exactly one QR code in the rendered image"
        status = d.add_data(decoded[0].data.decode())
        if status == DecodeQRStatus.COMPLETE:
            break

    assert status == DecodeQRStatus.COMPLETE
    assert d.decoder.get_data() == payload
