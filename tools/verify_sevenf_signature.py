#!/usr/bin/env python3
"""
Independently verify a real 7F ceremony signature (genesis-config or
devfund-config) -- for use after a hardware signing session, not as part
of the device's own code path.

Two hard rules, both driven by a real mistake made during the first live
hardware test (2026-09-29, see
tests/test_ml_dsa_65_nist_acvp_conformance.py's module docstring for the
full story):

1. The signed message is always read from the ORIGINAL scanned artifact
   image(s), never recomputed from scratch. Genesis-config's canonical
   bytes embed a timestamp; regenerating "the same" payload later produces
   a genuinely different message and a spurious verification failure that
   looks exactly like a real signing bug but isn't one.

2. Verification uses `dilithium-py`, a completely independent ML-DSA-65
   implementation -- never mldsa7f/fips204 itself, since verifying with the
   same code that signed only proves self-consistency. dilithium-py is
   trusted here only because it's separately validated against 15 official
   NIST ACVP vectors (tests/test_ml_dsa_65_nist_acvp_conformance.py) -- an
   independent library earns no trust just by being independent.

Usage:
    python tools/verify_sevenf_signature.py \\
        --original path/to/original_scanned_part*.png \\
        --signed path/to/exported_signature_part*.png \\
        --pubkey-hex <hex>

--original and --signed each accept one or more image files holding a
single- or multi-part BBQr sequence (shell-glob them, or pass every part
explicitly) -- part order is read from each QR's own BBQr header, not
filename order, so passing them out of order is harmless.

--pubkey-hex is REQUIRED and must come from an independently-trusted
source (the Root's own one-time enrollment export, a value you recorded
yourself off the device screen, etc.) -- never from the artifact being
verified. The signed export's own JSON may carry a `signer_vk` field, but
that field originates entirely from the file under test: trusting it as
the verification key would let a self-consistent forged export (attacker's
own keypair, attacker's own valid signature, attacker's own pubkey
embedded) report VALID, proving only that some keypair signed the message
-- not that the real enrolled Root did. Found in adversarial security
review, 2026-09-29 (HIGH). Pass --trust-embedded-signer-vk to opt into the
old, unsafe behavior anyway (loud warning printed, never the default).
"""
import argparse
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_SRC))

from seedsigner.models.decode_qr import DecodeQR  # noqa: E402
from seedsigner.models.sevenf.genesis_config import GenesisConfigError, parse_canonical_bytes as parse_genesis  # noqa: E402
from seedsigner.models.sevenf.devfund_config import DevFundConfigError, parse_canonical_bytes as parse_devfund  # noqa: E402


def _decode_bbqr_images(paths: list[Path]) -> bytes:
    """ Decode one or more image files holding a (possibly multi-part) BBQr
        sequence into the raw payload bytes, using this app's own real
        decode path -- never a hand-rolled parser. """
    from pyzbar.pyzbar import decode as qr_decode
    from PIL import Image

    decoder = DecodeQR()
    for path in paths:
        img = Image.open(path)
        results = qr_decode(img)
        if not results:
            raise ValueError(f"no QR code found in {path}")
        decoder.add_data(results[0].data.decode("ascii"))

    if not decoder.is_complete:
        raise ValueError(f"BBQr sequence incomplete after reading {len(paths)} image(s) -- missing a part?")
    if not decoder.is_sevenf_bbqr:
        raise ValueError("decoded QR data is not a 7F-ceremony BBQr artefact (wrong file-type byte)")
    return decoder.get_sevenf_bbqr_data()


def _identify_and_parse_message(data: bytes) -> tuple[str, bytes]:
    """ Self-validating, same doctrine as every on-device scan handler in
        this codebase: try each known artefact type and trust whichever one
        actually parses, never a file-type claim. Returns (kind, the exact
        bytes that were signed). """
    try:
        parse_genesis(data)
        return "genesis-config", data
    except GenesisConfigError:
        pass
    try:
        parse_devfund(data)
        return "devfund-config", data
    except DevFundConfigError:
        pass
    raise ValueError("original artefact did not parse as a genesis-config or devfund-config")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--original", nargs="+", required=True, type=Path,
                         help="image file(s) for the original scanned artefact's BBQr sequence")
    parser.add_argument("--signed", nargs="+", required=True, type=Path,
                         help="image file(s) for the exported signed-output BBQr sequence")
    parser.add_argument("--pubkey-hex", default=None,
                         help="signer's ML-DSA-65 public key, hex, from a trusted source -- REQUIRED (see module docstring for why)")
    parser.add_argument("--trust-embedded-signer-vk", action="store_true",
                         help="UNSAFE: fall back to the signed export's own embedded signer_vk when --pubkey-hex "
                              "is omitted. This trusts a value that originates entirely from the artifact under "
                              "test -- a forged export can embed any key it wants. Only use this for sanity-checking "
                              "your own test artifacts, never to verify a signature you don't already trust.")
    args = parser.parse_args()

    import json

    original_bytes = _decode_bbqr_images(args.original)
    kind, message = _identify_and_parse_message(original_bytes)
    print(f"Original artefact: {kind} ({len(message)} bytes)")

    signed_bytes = _decode_bbqr_images(args.signed)
    signed_obj = json.loads(signed_bytes)
    sig = bytes.fromhex(signed_obj["sig"])
    print(f"Signature: {len(sig)} bytes")

    embedded_vk = signed_obj.get("signer_vk") or ""
    if args.pubkey_hex and embedded_vk and args.pubkey_hex.lower() != embedded_vk.lower():
        print("WARNING: --pubkey-hex does not match the export's own embedded signer_vk. "
              "Proceeding with --pubkey-hex (the trusted source) -- but this mismatch itself "
              "is worth investigating before trusting this artifact.", file=sys.stderr)

    if args.pubkey_hex:
        pubkey_hex = args.pubkey_hex
    elif args.trust_embedded_signer_vk and embedded_vk:
        print("WARNING: verifying against the export's own embedded signer_vk -- this only proves "
              "internal self-consistency of the artifact (some keypair signed this message), NOT "
              "that the real enrolled Root/Deputy signed it. A forged export can embed any key it "
              "wants. Never treat this result as proof of authenticity.", file=sys.stderr)
        pubkey_hex = embedded_vk
    else:
        print("ERROR: --pubkey-hex is required. Get the signer's public key from a source you "
              "independently trust -- never from the artifact being verified. (Pass "
              "--trust-embedded-signer-vk only to sanity-check your own test artifacts.)", file=sys.stderr)
        sys.exit(2)
    pk = bytes.fromhex(pubkey_hex)
    print(f"Public key: {len(pk)} bytes")

    from dilithium_py.ml_dsa import ML_DSA_65
    result = ML_DSA_65.verify(pk, message, sig)

    print()
    if result:
        print(f"VALID -- the {kind} signature verifies against the actual signed message.")
    else:
        print(f"INVALID -- the {kind} signature does NOT verify. Do not trust this artefact.")
        sys.exit(1)


if __name__ == "__main__":
    main()
