#!/usr/bin/env node
/*
  CLI wrapper around bbqr-encode.js, for automated testing (see
  tests/test_bbqr_web_encoder.py).

  Usage: node encode_cli.js <file> [--matrix] [--to device|computer]
  Prints JSON: {error} for a refused file, else {kind, label, fileType,
  payloadHex, parts, fields} and, with --matrix, each part's QR module rows.
*/
const fs = require("fs");
const path = require("path");
const { prepareFile, qrMatrix } = require("./bbqr-encode.js");

const file = process.argv[2];
if (!file) {
  console.error("usage: node encode_cli.js <file> [--matrix]");
  process.exit(2);
}

const toAt = process.argv.indexOf("--to");
const target = toAt > 0 ? process.argv[toAt + 1] : "device";

prepareFile(path.basename(file), new Uint8Array(fs.readFileSync(file)), target).then((r) => {
  if (r.error) {
    process.stdout.write(JSON.stringify({ error: r.error }));
    return;
  }
  const out = {
    kind: r.kind, label: r.label, fileType: r.fileType, fields: r.fields, parts: r.parts,
    payloadHex: Buffer.from(r.payload).toString("hex"),
  };
  if (process.argv.includes("--matrix")) out.matrices = r.parts.map(qrMatrix);
  process.stdout.write(JSON.stringify(out));
});
