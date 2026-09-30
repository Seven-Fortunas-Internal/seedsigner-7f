#!/usr/bin/env node
/*
  CLI wrapper around bbqr-decode.js, for automated testing (see
  tests/test_bbqr_web_scanner.py) and for anyone who wants to decode a
  captured BBQr sequence from the command line without a browser.

  Usage: node decode_cli.js <segments.json>
  <segments.json>: a JSON array of BBQr segment strings, in any order
  (part ordering is read from each segment's own header, same as the
  browser page). Prints the decoded payload as hex to stdout.
*/
const fs = require("fs");
const { BBQrSession } = require("./bbqr-decode.js");

const path = process.argv[2];
if (!path) {
  console.error("usage: node decode_cli.js <segments.json>");
  process.exit(2);
}

const segments = JSON.parse(fs.readFileSync(path, "utf8"));
const session = new BBQrSession();
for (const text of segments) {
  session.addSegment(text);
}
if (!session.isComplete) {
  console.error(`incomplete: ${session.segments.size} / ${session.total} parts`);
  process.exit(1);
}
const bytes = session.decode();
process.stdout.write(Buffer.from(bytes).toString("hex"));
