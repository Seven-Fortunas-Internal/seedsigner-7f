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

TEST-ONLY SEEDS -- never use these for anything but this test flow. Both
are derived from the public, universally-known BIP-39 all-zero test vector
("abandon" x23 + "art"); the Deputy identity is the same mnemonic with a
distinguishing passphrase, not a second mnemonic to transcribe by hand.
Neither has ever protected real value.
"""
import argparse
import json
import sys
import time
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_SRC))

from seedsigner.models.seed import Seed  # noqa: E402
from seedsigner.models.encode_qr import BBQrEncoder  # noqa: E402
from seedsigner.models.sevenf.constants import ChainKind  # noqa: E402
from seedsigner.models.sevenf import cert_request, root_ceremony  # noqa: E402
from seedsigner.models.sevenf.genesis_config import ConsensusParams  # noqa: E402
from seedsigner.models.sevenf import genesis_config, devfund_config  # noqa: E402

ROOT_TEST_MNEMONIC = ["abandon"] * 23 + ["art"]
DEPUTY_TEST_PASSPHRASE = "sevenf-deputy-test"
CHAIN_KIND = ChainKind.TESTNET
TEST_DEVFUND_ADDRESS = "t1testdevfundaddressxxxxxxxxxxxxxxxxxxxxxxx"

QR_WIDTH = 480
QR_HEIGHT = 480
QR_BORDER = 4


def root_seed() -> Seed:
    return Seed(mnemonic=ROOT_TEST_MNEMONIC)


def deputy_seed() -> Seed:
    return Seed(mnemonic=ROOT_TEST_MNEMONIC, passphrase=DEPUTY_TEST_PASSPHRASE)


def build_root_cert_request(subject_vk: bytes) -> bytes:
    req = {
        "version": cert_request.CERT_REQUEST_VERSION,
        "role": cert_request.ROLE_ROOT,
        "kind": CHAIN_KIND.name.lower(),
        "subject_vk": subject_vk.hex(),
        "not_before": int(time.time()),
        "days": 3650,
        "serial": b"\x01".hex(),
    }
    return json.dumps(req).encode("utf-8")


def build_deputy_cert_request(subject_vk: bytes) -> bytes:
    req = {
        "version": cert_request.CERT_REQUEST_VERSION,
        "role": cert_request.ROLE_DEPUTY,
        "kind": CHAIN_KIND.name.lower(),
        "subject_vk": subject_vk.hex(),
        "not_before": int(time.time()),
        "days": 365,
        "serial": b"\x02".hex(),
    }
    return json.dumps(req).encode("utf-8")


def build_genesis_config() -> bytes:
    return genesis_config.build_canonical_bytes(
        CHAIN_KIND,
        int(time.time()),
        "7F testnet genesis -- hardware test artifact, not a real launch",
        ConsensusParams(
            target_block_time_secs=30,
            difficulty_adjustment_interval_blocks=2016,
            blocks_per_decay_period=210000,
        ),
    )


def build_devfund_config() -> bytes:
    return devfund_config.build_canonical_bytes(
        CHAIN_KIND, TEST_DEVFUND_ADDRESS, 100, int(time.time()),
    )


def render_bbqr(name: str, payload: bytes, out_dir: Path) -> list[Path]:
    encoder = BBQrEncoder(data=payload, file_type="B", bbqr_encoding="Z")
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
    html = SLIDESHOW_HTML_TEMPLATE.format(
        name=name, first=image_paths[0].name, files_json=files_json, interval_ms=interval_ms,
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

    root_keys = root_ceremony.derive_root_ceremony_keys(root_seed().seed_bytes, CHAIN_KIND)
    deputy_keys = root_ceremony.derive_root_ceremony_keys(deputy_seed().seed_bytes, CHAIN_KIND)

    artifacts = {
        "root_cert_request": build_root_cert_request(root_keys.root_ca.public_key),
        "deputy_cert_request": build_deputy_cert_request(deputy_keys.root_ca.public_key),
        "genesis_config": build_genesis_config(),
        "devfund_config": build_devfund_config(),
    }

    manifest = {
        "chain_kind": CHAIN_KIND.name.lower(),
        "root_test_mnemonic": " ".join(ROOT_TEST_MNEMONIC),
        "deputy_test_mnemonic": " ".join(ROOT_TEST_MNEMONIC) + f" (passphrase: {DEPUTY_TEST_PASSPHRASE})",
        "root_ca_address": root_keys.root_ca.address,
        "root_ca_public_key_hex": root_keys.root_ca.public_key.hex(),
        "devfund_address_derived_from_root_seed": root_keys.devfund.address,
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

    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"\nWrote {manifest_path}")


if __name__ == "__main__":
    main()
