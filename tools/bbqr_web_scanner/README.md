# 7F Signer web page

Operator-side page that moves ceremony files between a host and the device by animated BBQr QR codes, in both directions. It runs entirely in the browser and never ships on the device.

- **Start** (`#start`, and the bare URL): the operator guide. When to use each tab and what to do there, which device menu goes with which file, how the pin and subject key id are derived (with a command to recompute them), the key index, and how files travel as QR. The camera is off on this tab.
- **From device** (`#from-device`): scans the device's exports, checks them, and saves the files.
- **To device** (`#to-device`): checks a file the device must scan and plays it as a full-screen QR.

Why a web page: no phone or wallet app handles multi-part BBQr with the 7F file types.

## From device

1. Reads camera frames (`getUserMedia`) and decodes each with `jsQR`.
2. Collects BBQr parts by index (order does not matter) and reassembles the payload.
3. Shows progress as a grid of parts.
4. For a 7F export (a JSON envelope `{"sf7_export", "kind", "file", "body"}`):
   - Checks the file name against the content. A key's name must be `<ski>.vk`, a certificate's `root-<ski>.pem` or `deputy-<issuer ski>.pem`, a signature's `<ski>.genesis` or `<ski>.devfund`. A mismatch shows **NOT SAVED** and does not save.
   - Shows the **subject key id** (ski), the **pin** (for keys), the role (root or dev-fund), and the folder the file belongs in. Root and dev-fund keys go to separate folders.
   - **Save** writes the exact `body` under `file`. **Save summary** writes `<ski>.txt` as a record.
5. Other payloads (not envelopes) are shown as text or hex, without saving.

## To device

Accepts exactly what `tools/file_to_bbqr.py` accepts, and produces the same QR parts (`bbqr-encode.js`, tested part-for-part against it):

| File | Sent as | Device menu |
|---|---|---|
| `genesis-unsigned.json` | JSON, BBQr `J` | 7F: Sign Genesis Config |
| `devfund-unsigned.json` | JSON, BBQr `J` | 7F: Sign Devfund Config |
| `root-<ski>.pem` (a Root self-certificate) | DER, BBQr `B` | 7F: Cross-Certify Deputy, first scan |
| Deputy CSR `.pem` | DER, BBQr `B` | 7F: Cross-Certify Deputy, second scan |

Anything else is refused, including a Deputy certificate offered as a Root certificate. Before playing, the page shows the fields to expect on the device (the dev-fund recipient, the Root or Deputy ski). The device remains the authority: check every field and the canonical digest on its screen.

**Show QR to the device** opens a full-screen player (1.2 s per part by default; pause, step, slower, faster). It keeps the screen awake where the browser allows.

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

## Publishing

Public copy: https://seven-fortunas.github.io/7f-signer/ (repo `Seven-Fortunas/7f-signer`, folder `html/`, deployed by `.github/workflows/pages.yml`). Push to that repo as `mateo-7f`.

```bash
git clone https://github.com/Seven-Fortunas/7f-signer.git /tmp/7f-signer
tools/bbqr_web_scanner/publish/publish.sh /tmp/7f-signer   # refuses uncommitted changes
# review, commit and push /tmp/7f-signer as mateo-7f
```

The script copies only the page's files (no README, CLIs or tests), stamps `version.js` with this repo's commit, and adds `LICENSES/` and the workflow. The footer shows that commit; compare it with the one you expect before a ceremony.

## Tests

`tests/test_bbqr_web_scanner.py` and `tests/test_bbqr_web_encoder.py` (require Node; skipped if Node is absent), and `tests/test_bbqr_web_start.py` (the Start tab's content; no Node).

## Files

| File | Purpose |
|---|---|
| `index.html`, `style.css` | The page (strict CSP: only its own scripts and styles) |
| `app.js` | Tab switching (Start by default); the camera runs only on the From device tab |
| `app-scan.js` | From device tab |
| `app-send.js` | To device tab and the QR player |
| `bbqr-decode.js` | Decoding and envelope checks (shared with `decode_cli.js`) |
| `bbqr-encode.js` | File checks and BBQr encoding (shared with `encode_cli.js`) |
| `decode_cli.js`, `encode_cli.js` | Node command-line wrappers for tests |
| `version.js` | The version shown in the footer (stamped by `publish/publish.sh`) |
| `LICENSES/` | Our MIT license and the bundled libraries' licenses |
| `publish/` | `publish.sh` and the Pages workflow for the public repo |
| `jsQR.min.js` | Vendored QR decoder (jsQR 1.4.0) |
| `pako.min.js` | Vendored zlib (pako 2.1.0) |
| `qrcode-generator.js` | Vendored QR encoder (qrcode-generator 2.0.4, MIT, npm tarball sha256 `02e2e18a…8159`) |
