#!/usr/bin/env bash
# Copies the page into a checkout of the public repo (Seven-Fortunas/7f-signer)
# as html/, stamped with this repo's commit, plus the Pages workflow.
# Commit and push the public checkout yourself (as mateo-7f).
#   tools/bbqr_web_scanner/publish/publish.sh <public-repo-checkout>
set -euo pipefail
src="$(cd "$(dirname "$0")/.." && pwd)"
dest="${1:?usage: publish.sh <public-repo-checkout>}"
[ -d "$dest/.git" ] || { echo "not a git checkout: $dest" >&2; exit 1; }
if [ -n "$(git -C "$src" status --porcelain -- .)" ]; then
  echo "refused: uncommitted changes in $src; publish only committed code" >&2
  exit 1
fi
commit="$(git -C "$src" rev-parse --short HEAD)"
date="$(git -C "$src" log -1 --format=%cs)"
rm -rf "$dest/html"
mkdir -p "$dest/html/LICENSES" "$dest/.github/workflows"
for f in index.html style.css app.js app-scan.js app-send.js bbqr-decode.js bbqr-encode.js \
         jsQR.min.js pako.min.js qrcode-generator.js; do
  cp "$src/$f" "$dest/html/$f"
done
cp "$src"/LICENSES/* "$dest/html/LICENSES/"
printf 'window.SF7_TOOL_VERSION = "%s (%s)";\n' "$commit" "$date" > "$dest/html/version.js"
touch "$dest/html/.nojekyll"
cp "$src/publish/pages.yml" "$dest/.github/workflows/pages.yml"
echo "html/ now holds $commit ($date). Review with: git -C $dest status"
