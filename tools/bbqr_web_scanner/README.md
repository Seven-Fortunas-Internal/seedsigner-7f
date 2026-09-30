# 7F BBQr web scanner

Browser-based multi-part BBQr scanner, built 2026-09-29 because no existing
mobile app or website could scan a multi-part (animated) BBQr sequence --
Nunchuk and Sparrow support BBQr but only as a Bitcoin-wallet feature
(PSBT file-type), not the generic binary/JSON file-types this project's 7F
ceremony artefacts use.

Decode logic (`bbqr-decode.js`) is ported directly from this project's own
real implementation (`src/seedsigner/models/decode_qr.py`'s
`_bbqr_decode_segments`/`BaseBBQrDecoder`), not reverse-engineered from the
spec -- verified byte-for-byte against real device-produced signatures
during the first live use, and covered by `tests/test_bbqr_web_scanner.py`
(requires Node; skips cleanly if absent, same as the mldsa7f-gated tests).

## Running it

```bash
cd tools/bbqr_web_scanner
python3 -m http.server 8901 --bind 127.0.0.1
```

Camera access requires a secure context (HTTPS or `localhost`) -- a plain
`http://<lan-ip>:8901` will NOT get camera permission from a phone browser.
To reach it from another device (a phone) on your own network, use
Tailscale Serve, which issues a real HTTPS cert for this machine's tailnet
hostname (no separate cert setup needed if your tailnet already has HTTPS
certificates enabled in the admin console):

```bash
tailscale serve --bg http://127.0.0.1:8901
tailscale serve status   # prints the https://<hostname>.<tailnet>.ts.net URL
```

Use `tailscale serve`, not `tailscale funnel` -- serve is tailnet-only
(any device already signed into your own tailnet), funnel exposes the page
to the public internet, which this tool has no reason to need.

## What it does

1. Requests camera access (`getUserMedia`), decodes each frame with
   `jsQR.min.js`.
2. Parses each decoded string's BBQr header (encoding / file-type / total
   parts / this part's index) and collects segments by index -- part order
   from the camera doesn't matter.
3. Once every part is collected, reassembles the payload exactly as
   `decode_qr.py` does (base32 or hex decode per segment, then `pako`'s
   raw-deflate inflate for the default `'Z'` encoding) and displays it
   (pretty-printed JSON for file-type `'J'`, plain text for `'U'`, hex for
   anything else).
4. Shows live progress: a numbered grid of parts, lit up as each is
   scanned, plus which indices are still missing.

## Files

| File | Purpose |
|---|---|
| `index.html` | The scanner page itself |
| `bbqr-decode.js` | Shared decode logic (used by both the browser and `decode_cli.js`) |
| `decode_cli.js` | Node CLI wrapper, for testing and manual command-line decoding |
| `jsQR.min.js` | Vendored QR decoder (jsQR 1.4.0) |
| `pako.min.js` | Vendored zlib inflate (pako 2.1.0), for `'Z'`-encoded BBQr payloads |

Nothing here is device-side code -- this never ships on the SeedSigner
itself, it's an operator-side tool for verifying what the device exports.
