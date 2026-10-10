# 7F SeedSigner guide

How to use a 7F SeedSigner for the 7F chain Root ceremony. The ceremony itself is defined by the 7fchain runbooks; if this guide and a runbook disagree, the runbook wins.

## What you need

- A SeedSigner: Raspberry Pi Zero 2 W, Waveshare 1.3" 240x240 LCD HAT, Pi Zero camera.
- A microSD card (8-32 GB).
- A computer or phone with a camera and a browser.
- Your 24-word governance phrase on paper. You need one phrase per Root key.

## 1. Install

1. Download the `.img` and its `.sha256` from the latest [release](https://github.com/Seven-Fortunas-Internal/seedsigner-7f/releases).
2. Check it: `sha256sum -c <image>.sha256` must print `OK`. If it doesn't, do not flash it.
3. Flash it with Raspberry Pi Imager, balenaEtcher or `dd`.
4. Boot once and confirm the device reaches the menu.

The image has no network, no Wi-Fi, no Bluetooth and no login. If the device ever shows a red **NETWORK DETECTED** screen, it has cleared the seeds and stopped. Unplug anything in the USB port and power off. If the screen shows again at boot, the card or image is wrong: reflash from a checked image.

## 2. Start

1. At boot, choose **7F Chain**.
2. Go to **Seeds > Load a seed > Enter 24-word seed**. Enter your phrase, and a passphrase only if your key was made with one.
3. The seed's label is the first 8 characters of your Root key's subject key id. Check it against the one you expect.

To reach the 7F actions, open **Seeds**, then your seed.

## 3. The 7F actions

| Action | When | You scan | The device gives you |
|---|---|---|---|
| **7F: Self-Certify Root** | Start of the ceremony | nothing | `root-<ski>.pem` (your Root certificate), then `<ski>.vk` (your Root key) |
| **7F: Enroll Dev-fund** | Start of the ceremony | nothing | `<ski>.vk` (your dev-fund key) |
| **7F: Sign Genesis Config** | When the coordinator sends it | `genesis-unsigned.json` | `<ski>.genesis` |
| **7F: Sign Devfund Config** | When the coordinator sends it | `devfund-unsigned.json` | `<ski>.devfund` |
| **7F: Cross-Certify Deputy** | When the Deputy sends a request | your `root-<ski>.pem`, then the Deputy's `deputy-<ski>-csr.pem` | `deputy-<root ski>.pem` |

**What the device asks:**
- **Date & time (UTC):** Self-Certify Root and Cross-Certify Deputy only. The device has no clock. Enter the real date and check the weekday it reads back.
- **Chain:** Self-Certify Root, Enroll Dev-fund and Cross-Certify Deputy. Choose **testnet**. The signing steps take the network from the file.
- **Key index:** every step. Choose **Index 0 (default)**, unless your key was made at another index.

**Review, then sign.** Every signed value is shown before you press **Sign**. If anything is not what you expect, press Back and call the coordinator.

## 4. Move files: the 7F Signer page

Open https://seven-fortunas.github.io/7f-signer/. It runs in your browser and uploads nothing. The **Start** tab explains each step.

- **From device:** point the camera at the device's QR. The page checks the file and saves it under its correct name.
- **To device:** choose a file. The page shows it as a QR for the device to scan.
- **To device > Another computer:** sends certificate and request files to a second computer running the page (CentCom and registrar).

Note the version in the page footer before a ceremony.

## Checks that matter

- **Read the subject key id and root pin aloud, by phone.** Never confirm them over the channel that carried the file.
- **The dev-fund key id must differ from your Root key id.** If they are the same, stop.
- **The "Canonical digest"** on Sign Genesis Config and Sign Devfund Config must match the coordinator's.
- **The dev-fund recipient** must be the one the coordinator told you to expect. It receives the entire genesis reward.

## If something goes wrong

| You see | Do this |
|---|---|
| Date refused | Enter the real UTC date. |
| "Not a 7F phrase" | Load the 24-word governance phrase. 12- and 18-word phrases are refused. |
| "Wrong Key ... at index N" | That certificate is not this phrase's key at that index. Check the phrase and the index. |
| "Wrong File" in Cross-Certify Deputy | Scan your `root-<ski>.pem` first. Then switch the page to the request and press **Scan request**. |
| "Already signed" | This key already signed this file. Nothing to do. |
| "Not the defaults" | The genesis values are not the network's defaults. Choose **Don't sign** and call the coordinator. |
| "Key Mismatch" after signing | Nothing was exported. Start the step again. If it repeats, report it. |
| Page says **NOT SAVED** | Scan again. Never rename a file by hand. |
| Digest, pin or recipient differs from what you were told | Stop and call the coordinator. |
