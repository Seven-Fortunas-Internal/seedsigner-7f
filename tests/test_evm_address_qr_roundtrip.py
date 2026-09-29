"""
    Stage 1 of docs/multi-chain/evm-test-plan.md ("Confirm the QR-encoded address
    round-trips byte-for-byte") -- exercised for real: encode a real derived address
    exactly the way EvmAddressQRView does (GenericStaticQrEncoder.next_part_image(),
    the actual on-device path via the `qrencode` CLI, not just its pure-Python
    fallback), then decode the resulting image with pyzbar -- the same library the
    device uses to scan QR codes -- and confirm it comes back byte-identical.
    Existing flow tests (test_flows_evm.py) only confirm EvmAddressQRView is
    *reached*; this confirms the QR it renders actually decodes back to the right
    address, not just that the screen exists.

    qr.qrimage_io() (src/seedsigner/helpers/qr.py) silently falls back to the
    pure-Python `qrcode` library if the `qrencode` binary is missing or fails --
    with no exception. Without a guard, this test suite would happily pass while
    quietly testing the fallback encoder instead of the CLI path it claims to,
    exactly the failure mode a code-review pass caught (reproduced by simulating a
    missing binary: all tests still passed). REQUIRE_QRENCODE below turns that into
    a loud, immediate failure instead -- qrencode is installed in CI
    (.github/workflows/tests.yml) and confirmed present on the real Pi hardware, so
    its absence here means a real environment problem, not something to silently
    route around.
"""
import shutil

import pytest
from embit.bip39 import mnemonic_to_seed
from pyzbar.pyzbar import decode as zbar_decode

from seedsigner.chains.evm.crypto import derive_private_key, private_key_to_checksum_address
from seedsigner.models.encode_qr import GenericStaticQrEncoder

TEST_MNEMONIC = "test test test test test test test test test test test junk"

REQUIRE_QRENCODE = pytest.mark.skipif(
    shutil.which("qrencode") is None,
    reason="qrencode CLI not installed -- these tests exist specifically to exercise "
           "that path (see module docstring), not its pure-Python fallback. Install "
           "qrencode (apt-get install qrencode) rather than letting this silently "
           "skip.",
)


def _derive_real_address(path: str, passphrase: str = "") -> str:
    seed = mnemonic_to_seed(TEST_MNEMONIC, password=passphrase)
    private_key = derive_private_key(seed, path)
    return private_key_to_checksum_address(private_key)


def _encode_and_decode(address: str) -> str:
    """Same call path EvmAddressQRView -> QRDisplayScreen actually uses
    (part_to_image()/next_part_image(), border=2 -- see screen.py's QRDisplayThread),
    not a shortcut straight to the lower-level QR helper."""
    encoder = GenericStaticQrEncoder(data=address)
    image = encoder.next_part_image(240, 240, border=2, background_color="bdbdbd")
    decoded = zbar_decode(image)
    assert len(decoded) == 1, f"expected exactly one QR code in the image, got {len(decoded)}"
    return decoded[0].data.decode()


@REQUIRE_QRENCODE
def test_real_derived_address_qr_roundtrips():
    address = _derive_real_address("m/44'/60'/0'/0/0")
    assert _encode_and_decode(address) == address


@REQUIRE_QRENCODE
def test_qr_roundtrip_holds_across_account_indices():
    for path in ("m/44'/60'/0'/0/0", "m/44'/60'/0'/0/1", "m/44'/60'/1'/0/0"):
        address = _derive_real_address(path)
        assert _encode_and_decode(address) == address


@REQUIRE_QRENCODE
def test_qr_roundtrip_holds_with_passphrase():
    address = _derive_real_address("m/44'/60'/0'/0/0", passphrase="a-test-passphrase")
    assert _encode_and_decode(address) == address
