#!/usr/bin/env python3
"""
Generate real, scannable BBQr test artifacts for hardware-testing the 7F
root-ceremony device flows (genesis-config signing, Root self-cert, Deputy
cross-cert, devfund-config signing).

Every payload here is built with this app's own production code paths --
the same mldsa7f ctypes bridge and canonical-bytes builders
(genesis_config.py, devfund_config.py, cert_request.py) and the same
BBQrEncoder (encode_qr.py) the device itself would use to export an
artifact -- so nothing about the wire format is guessed (D12). The only
thing "fake" about these artifacts is that a human, not a real sf-root/
sf-deputy coordinator, is standing in on the other end of the airgap.

See docs/7f-integration/root-ceremony-hardware-walkthrough.md for how to
point a device's camera at the output.

BUILD REQUIREMENT (2026-10-04, 7f-review-csr-tooling-ships-in-production-
cdylib): the Deputy CSR artifact this script generates uses
cert_request.csr_info_der/assemble_csr_der, whose firmware/mldsa7f FFI
entry points only exist in a library built with `cargo build --release
--features test-tooling` -- a plain `cargo build --release` (sufficient
for the device app itself and for every other artifact this script
builds) omits them, since nothing on the device needs to build a CSR.

TEST-ONLY SEEDS -- never use these for anything but this test flow. Both
are derived from the public, universally-known BIP-39 all-zero test vector
("abandon" x23 + "art"); the Deputy identity is the same mnemonic with a
distinguishing passphrase, not a second mnemonic to transcribe by hand.
Neither has ever protected real value.
"""
import argparse
from html import escape as htmlescape
import json
import sys
import time
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_SRC))

from seedsigner.models.seed import Seed  # noqa: E402
from seedsigner.models.encode_qr import BBQrEncoder, CompactSeedQrEncoder  # noqa: E402
from seedsigner.models.settings_definition import SettingsConstants  # noqa: E402
from seedsigner.models.sevenf.constants import ChainKind  # noqa: E402
from seedsigner.models.sevenf import cert_request, root_ceremony  # noqa: E402
from seedsigner.models.sevenf import genesis_config, devfund_config  # noqa: E402

ROOT_TEST_MNEMONIC = ["abandon"] * 23 + ["art"]
DEPUTY_TEST_PASSPHRASE = "sevenf-deputy-test"
CHAIN_KIND = ChainKind.TESTNET
# A multisig commitment from the 2026-10-07 end-to-end sandbox run (nine
# throwaway dev-fund keys, 6-of-9) -- test data, not a real ceremony's.
TEST_DEVFUND_COMMITMENT = (
    "11dab78bc023fa02f2d60db1e5deb9e702836ff2b609d30e74b1b808983d361a"
    "7a83b8583bae657e7aabe3fd3be4f01ca64caea839faa207c7a7da4253a41ddc"
)

QR_WIDTH = 480
QR_HEIGHT = 480
QR_BORDER = 4


def root_seed() -> Seed:
    return Seed(mnemonic=ROOT_TEST_MNEMONIC)


def deputy_seed() -> Seed:
    return Seed(mnemonic=ROOT_TEST_MNEMONIC, passphrase=DEPUTY_TEST_PASSPHRASE)


def build_root_cert_der(root_keys, root_seed: Seed) -> bytes:
    """ A real, complete, self-signed Root certificate DER -- the first of
        the two artifacts the real (PKCS#10-era) Deputy cross-certification
        flow scans, built with this app's own production code paths
        (cert_request.build_root_tbs + root_ceremony.sign_with_root_ca +
        cert_request.assemble_root_cert_der), not hand-guessed. Closes the
        Root-certificate half of
        7f-signing-support-hardware-test-tooling-pkcs10-staleness. """
    serial = cert_request.generate_serial()
    not_before = int(time.time())
    tbs = cert_request.build_root_tbs(root_keys.root_ca.public_key, CHAIN_KIND, not_before, cert_request.ROOT_DAYS, serial)
    _, signature = root_ceremony.sign_with_root_ca(root_seed.seed_bytes, CHAIN_KIND, tbs, confirmed=True, index=0)
    return cert_request.assemble_root_cert_der(tbs, signature, root_keys.root_ca.public_key)


def build_deputy_csr_der(deputy_keys, deputy_seed: Seed) -> bytes:
    """ A real, self-signed PKCS#10 CSR DER for the Deputy test identity --
        the second of the two artifacts the real Deputy cross-certification
        flow scans. Built via cert_request.csr_info_der/assemble_csr_der,
        the test/tooling-only CSR-building capability added to close
        7f-signing-support-hardware-test-tooling-pkcs10-staleness (no
        production device code builds a CSR -- verify_and_parse_csr_der's
        own docstring confirms the device only ever verifies one; the real
        one comes from 7fchain's own sf-deputy CLI). Signed with the
        Deputy's own derived key via root_ceremony.sign_with_root_ca -- a
        CSR is always self-signed (proof of possession), and this tool
        already reuses that same function/derivation path to derive the
        Deputy's test identity above (`deputy_keys`), it just signs a
        different artifact with it here. """
    info_der = cert_request.csr_info_der(deputy_keys.root_ca.public_key)
    _, signature = root_ceremony.sign_with_root_ca(deputy_seed.seed_bytes, CHAIN_KIND, info_der, confirmed=True, index=0)
    return cert_request.assemble_csr_der(info_der, signature)


def build_genesis_config() -> bytes:
    """ genesis-unsigned.json as `sf-root-coordinator prepare-genesis` writes it
        (7fchain 416f576), default consensus values -- the file a Root scans. """
    return json.dumps({
        "version": genesis_config.SCHEMA_VERSION,
        "chain_kind": CHAIN_KIND.name.lower(),
        "timestamp": int(time.time()),
        "message": "7F testnet genesis -- hardware test artifact, not a real launch",
        "derivation_scheme": genesis_config.DERIVATION_SCHEME_V1,
        "consensus": {
            "target_block_time_secs": 420,
            "difficulty_adjustment_interval_blocks": 1500,
            "blocks_per_decay_period": 70000,
        },
        "signatures": [],
    }, indent=2).encode()


def build_devfund_config() -> bytes:
    """ devfund-unsigned.json as `prepare-devfund --threshold 6 --vk ...` writes it. """
    return json.dumps({
        "version": devfund_config.DEVFUND_SCHEMA_VERSION,
        "network": CHAIN_KIND.name.lower(),
        "recipient": {"kind": "multisig", "commitment": TEST_DEVFUND_COMMITMENT},
        "effective_block": 0,
        "timestamp": int(time.time()),
        "signatures": [],
    }, indent=2).encode()


def render_seed_qr(name: str, mnemonic: list[str], out_dir: Path) -> Path:
    """ A plain (non-BBQr) CompactSeedQR for scanning the test mnemonic in via
        the device's camera instead of hand-typing 24 words -- Seeds > Enter
        24-word seed screen also offers "Scan a SeedQR". Same encoder the
        device's own export path uses (encode_qr.py's CompactSeedQrEncoder),
        so nothing about the format is guessed. """
    import qrcode
    encoder = CompactSeedQrEncoder(mnemonic=mnemonic, wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=20, border=4)
    qr.add_data(encoder.next_part())
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    path = out_dir / f"{name}.png"
    img.save(path)
    return path


def render_bbqr(name: str, payload: bytes, out_dir: Path, file_type: str = "B") -> list[Path]:
    encoder = BBQrEncoder(data=payload, file_type=file_type, bbqr_encoding="Z")
    total = encoder.seq_len()
    paths = []
    for i in range(total):
        img = encoder.next_part_image(width=QR_WIDTH, height=QR_HEIGHT, border=QR_BORDER)
        path = out_dir / f"{name}_part{i + 1:02d}of{total:02d}.png"
        img.save(path)
        paths.append(path)
    return paths


SLIDESHOW_HTML_TEMPLATE = """<!doctype html>
<title>7F test QR: {name}</title>
<style>
  body {{ background:#000; margin:0; height:100vh; display:flex; align-items:center;
         justify-content:center; flex-direction:column; }}
  img {{ max-width:90vw; max-height:80vh; image-rendering:pixelated; }}
  p {{ color:#0f0; font-family:monospace; font-size:1.2em; }}
</style>
<img id="f" src="{first}">
<p id="c"></p>
<script>
  const files = {files_json};
  let i = 0;
  const img = document.getElementById('f');
  const caption = document.getElementById('c');
  function show() {{
    img.src = files[i];
    caption.textContent = (i + 1) + ' / ' + files.length;
    i = (i + 1) % files.length;
  }}
  show();
  if (files.length > 1) setInterval(show, {interval_ms});
</script>
"""


def write_slideshow(name: str, image_paths: list[Path], out_dir: Path, interval_ms: int = 1200):
    files_json = json.dumps([p.name for p in image_paths])
    # Names can come from a coordinator-supplied file (file_to_bbqr.py):
    # escape for HTML, and keep "</" out of the inline script.
    html = SLIDESHOW_HTML_TEMPLATE.format(
        name=htmlescape(name), first=htmlescape(image_paths[0].name),
        files_json=files_json.replace("</", "<\\/"), interval_ms=interval_ms,
    )
    slideshow_path = out_dir / f"{name}_slideshow.html"
    slideshow_path.write_text(html)
    return slideshow_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", default=str(Path(__file__).resolve().parent / "test_artifacts"))
    args = parser.parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    root_keys = root_ceremony.derive_root_ceremony_keys(root_seed().seed_bytes, CHAIN_KIND, index=0)
    deputy_keys = root_ceremony.derive_root_ceremony_keys(deputy_seed().seed_bytes, CHAIN_KIND, index=0)

    artifacts = {
        # "root_cert_request" is gone (2026-10-03): Root self-certification's
        # PKCS#10-era rework removed the scanned CertRequest step entirely --
        # the device now derives its own key and builds its own TBS with no
        # external input at all. See docs/7f-integration/
        # root-self-cert-pkcs10-rework-plan.md. Nothing replaces it here; the
        # manifest's root_ca_address/root_ca_public_key_hex below are already
        # what an operator needs to cross-check against the device's own
        # review screen.
        #
        # "root_cert"/"deputy_csr" (2026-10-03, closes
        # 7f-signing-support-hardware-test-tooling-pkcs10-staleness): Deputy
        # cross-certification's own PKCS#10 rework replaced the old
        # "deputy_cert_request" JSON shape with a real signed Root
        # certificate + a real self-signed PKCS#10 CSR -- these are those
        # two artifacts, both built with this app's own production code
        # paths (see build_root_cert_der/build_deputy_csr_der's own
        # docstrings).
        "root_cert": build_root_cert_der(root_keys, root_seed()),
        "deputy_csr": build_deputy_csr_der(deputy_keys, deputy_seed()),
        "genesis_config": build_genesis_config(),
        "devfund_config": build_devfund_config(),
    }

    manifest = {
        "chain_kind": CHAIN_KIND.name.lower(),
        "root_test_mnemonic": " ".join(ROOT_TEST_MNEMONIC),
        "deputy_test_mnemonic": " ".join(ROOT_TEST_MNEMONIC) + f" (passphrase: {DEPUTY_TEST_PASSPHRASE})",
        "root_ca_address": root_keys.root_ca.address,
        "root_ca_public_key_hex": root_keys.root_ca.public_key.hex(),
        # The devfund-config is signed with the ROOT key (sf-wallet-gov
        # sign-devfund), so its confirm screen shows root_ca_address above.
        "deputy_public_key_hex": deputy_keys.root_ca.public_key.hex(),
        "artifacts": {},
    }

    for name, payload in artifacts.items():
        image_paths = render_bbqr(name, payload, out_dir)
        slideshow_path = write_slideshow(name, image_paths, out_dir)
        manifest["artifacts"][name] = {
            "payload_bytes": len(payload),
            "bbqr_parts": len(image_paths),
            "images": [p.name for p in image_paths],
            "slideshow": slideshow_path.name,
        }
        print(f"{name}: {len(payload)} bytes -> {len(image_paths)} QR part(s), {slideshow_path.name}")

    seed_qr_path = render_seed_qr("root_test_seed_qr", ROOT_TEST_MNEMONIC, out_dir)
    manifest["root_test_seed_qr"] = seed_qr_path.name
    print(f"root_test_seed_qr: {seed_qr_path.name} (scan at Seeds > Enter 24-word seed > Scan a SeedQR; "
          f"add the Deputy passphrase afterward for the Deputy identity)")

    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"\nWrote {manifest_path}")


if __name__ == "__main__":
    main()
