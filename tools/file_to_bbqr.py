"""
Show a ceremony file as the animated BBQr QR slideshow the SeedSigner scans --
the host-to-device half of the ceremony file transfer (the device-to-host
half is tools/bbqr_web_scanner).

    python3 tools/file_to_bbqr.py governance/root/inbox/genesis-unsigned.json
    python3 tools/file_to_bbqr.py governance/root/inbox/deputy-csr.pem

Accepts exactly the files a Root holder scans into the device:
  genesis-unsigned.json / devfund-unsigned.json  -> sent as JSON (BBQr 'J')
  root-<ski>.pem (CERTIFICATE)                   -> sent as DER  (BBQr 'B')
  a Deputy CSR .pem (CERTIFICATE REQUEST)        -> sent as DER  (BBQr 'B')
Anything else is refused. Writes <name>_bbqr/ under --out-dir and prints the
slideshow page to open full-screen in front of the device camera. Every file
here is public; nothing secret is ever shown.
"""
import argparse
import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from make_sevenf_test_qrs import render_bbqr, write_slideshow  # noqa: E402

_PEM_TYPES = ("CERTIFICATE", "CERTIFICATE REQUEST")


def payload_for(path: Path) -> tuple[bytes, str]:
    """ (bytes the device scans, BBQr file type) for one ceremony file. """
    data = path.read_bytes()
    text = data.decode("ascii") if data.isascii() else None
    if text is not None and text.lstrip().startswith("{"):
        json.loads(text)  # must at least be JSON; the device validates the rest
        return data, "J"
    if text is not None:
        stripped = text.strip()
        for label in _PEM_TYPES:
            begin, end = f"-----BEGIN {label}-----", f"-----END {label}-----"
            if stripped.startswith(begin) and stripped.endswith(end):
                body = "".join(stripped[len(begin):-len(end)].split())
                return base64.b64decode(body, validate=True), "B"
    raise ValueError(f"{path.name}: not a ceremony JSON file or a CERTIFICATE / CERTIFICATE REQUEST PEM")


def write_bbqr_slideshow(path: Path, out_dir: Path) -> Path:
    payload, file_type = payload_for(path)
    target = out_dir / f"{path.name}_bbqr"
    target.mkdir(parents=True, exist_ok=True)
    images = render_bbqr(path.name, payload, target, file_type=file_type)
    return write_slideshow(path.name, images, target)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("file", type=Path)
    parser.add_argument("--out-dir", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        slideshow = write_bbqr_slideshow(args.file, args.out_dir)
    except (ValueError, OSError) as e:
        sys.exit(f"refused: {e}")
    print(f"Open full-screen and point the device at it:\n  {slideshow.resolve()}")


if __name__ == "__main__":
    main()
