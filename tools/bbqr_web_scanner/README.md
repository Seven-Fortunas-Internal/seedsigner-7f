# 7F BBQr web scanner

Browser page that scans the device's animated BBQr QR exports, checks them, and saves the files for the ceremony. It is an operator-side tool and never ships on the device.

Why a web page: no phone or wallet app scans multi-part BBQr with the 7F file types, so the page decodes in the browser (`bbqr-decode.js`, ported from the device's `decode_qr.py`).

## What it does

1. Reads camera frames (`getUserMedia`) and decodes each with `jsQR`.
2. Collects BBQr parts by index (order does not matter) and reassembles the payload.
3. Shows progress as a grid of parts.
4. For a 7F export (a JSON envelope `{"sf7_export", "kind", "file", "body"}`):
   - Checks the file name against the content. A key's name must be `<ski>.vk`, a certificate's `root-<ski>.pem` or `deputy-<issuer ski>.pem`, a signature's `<ski>.genesis` or `<ski>.devfund`. A mismatch shows **NOT SAVED** and does not save.
   - Shows the **subject key id** (ski), the **pin** (for keys), the role (root or dev-fund), and the folder the file belongs in. Root and dev-fund keys go to separate folders.
   - **Save** writes the exact `body` under `file`. **Save summary** writes `<ski>.txt` as a record.
5. Other payloads (not envelopes) are shown as text or hex, without saving.

## Saving

- **Desktop Chrome or Edge:** a folder picker. Choose the folder for the role.
- **iPhone Safari:** the share sheet ("Save to Files"). Not yet verified on a real iPhone for this flow; test it before relying on it.
- **Other browsers:** a plain download.

## Running it

The page is served by a systemd user unit and exposed to the tailnet with `tailscale serve`.

```bash
# 1. The unit: ~/.config/systemd/user/bbqr-scanner.service
#    runs python3 -m http.server 8901 --bind 127.0.0.1 in this directory.
systemctl --user daemon-reload
systemctl --user enable --now bbqr-scanner.service
# Optional, to survive logout: loginctl enable-linger "$USER"

# 2. HTTPS for the camera, tailnet only (not funnel):
tailscale serve --bg http://127.0.0.1:8901
tailscale serve status    # prints the https://<host>.<tailnet>.ts.net URL
```

The current URL is `https://bbqr.tail25f985.ts.net`. Camera access needs HTTPS or `localhost`; a plain `http://<lan-ip>` URL will not get camera permission from a phone.

**Pin a revision for a ceremony.** The unit serves this directory from the working tree, so any edit or checkout changes what the page does mid-ceremony. Before a ceremony, check out a known commit of `firmware/seedsigner-7f`, record its hash in the ceremony notes, and do not change the tree until the ceremony ends.

## Tests

`tests/test_bbqr_web_scanner.py` (requires Node; skipped if Node is absent).

## Files

| File | Purpose |
|---|---|
| `index.html` | The scanner page |
| `bbqr-decode.js` | Decoding and envelope checks (shared by the page and `decode_cli.js`) |
| `decode_cli.js` | Node command-line decoder for tests and manual checks |
| `jsQR.min.js` | Vendored QR decoder (jsQR 1.4.0) |
| `pako.min.js` | Vendored zlib inflate (pako 2.1.0) for `'Z'`-encoded BBQr |
