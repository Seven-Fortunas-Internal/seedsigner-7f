/*
  Shared BBQr multi-part assembly/decode logic, used by both index.html
  (browser) and decode_cli.js (Node, for automated testing against this
  project's own real Python decoder). Ported directly from this project's
  own real implementation (src/seedsigner/models/decode_qr.py's
  _bbqr_decode_segments / BaseBBQrDecoder) -- not reverse-engineered from
  the spec, so it matches exactly what this device's BBQrEncoder produces.
  See https://github.com/coinkite/BBQr/blob/master/BBQr.md for the spec
  this mirrors.

  Works in both a <script> tag (globals) and Node (module.exports) without
  a bundler -- deliberately dependency-free except for the pako global,
  which both environments load separately (script tag / require).
*/
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("./pako.min.js"));
  } else {
    root.BBQrDecode = factory(root.pako);
  }
})(typeof self !== "undefined" ? self : this, function (pako) {

const BASE36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
function fromBase36Pair(pair) {
  return BASE36.indexOf(pair[0]) * 36 + BASE36.indexOf(pair[1]);
}

// ski(): the Subject Key Identifier -- SHA-256 of the RAW key bytes (not the
// hex string's own UTF-8 bytes), truncated to the first 20 bytes, hex-encoded
// (40 chars). Byte-for-byte port of 7fchain's x509::key_id() (RFC 7093
// method 1) / review_format.ski() (this device's own Python port): the id
// sf-wallet-gov prints and names every governance file by (7fchain ce04ae9). Uses the Web Crypto API (crypto.subtle),
// present natively in both browsers (secure context -- same requirement
// this page's camera access already has) and Node 19+, so no new
// dependency. Returns null for input that isn't well-formed hex.
async function ski(hexText) {
  const clean = String(hexText).trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(clean) || clean.length % 2 !== 0) return null;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest).slice(0, 20))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// RFC 4648 base32 decode, matching Python's base64.b32decode (uppercase
// alphabet, '=' padding). No built-in JS equivalent, so hand-rolled --
// this is the whole alphabet, nothing invented.
const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Decode(input) {
  const clean = input.replace(/=+$/, "");
  let bits = "";
  for (const ch of clean) {
    const idx = B32_ALPHABET.indexOf(ch.toUpperCase());
    if (idx === -1) throw new Error(`invalid base32 character: ${ch}`);
    bits += idx.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

function hexDecode(input) {
  const bytes = new Uint8Array(input.length / 2);
  for (let i = 0; i < input.length; i += 2) {
    bytes[i / 2] = parseInt(input.slice(i, i + 2), 16);
  }
  return bytes;
}

function concatBytes(chunks) {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

// Mirrors decode_qr.py's _bbqr_decode_segments() exactly: 'H' is hex per
// segment; otherwise base32 per segment, then (for 'Z') raw-deflate
// inflate of the concatenated bytes -- matching BBQrEncoder's own
// zlib.compressobj(level=9, wbits=-10) on the encode side.
function reconstructPayload(segmentsByIndex, encoding) {
  const ordered = [];
  for (let i = 0; i < segmentsByIndex.size; i++) {
    ordered.push(segmentsByIndex.get(i));
  }
  let raw;
  if (encoding === "H") {
    raw = concatBytes(ordered.map(hexDecode));
  } else {
    raw = concatBytes(ordered.map(base32Decode));
  }
  if (encoding === "Z") {
    return pako.inflateRaw(raw);
  }
  return raw;
}

class BBQrSession {
  constructor() {
    this.reset();
  }

  reset() {
    this.encoding = null;
    this.fileType = null;
    this.total = null;
    this.segments = new Map(); // 0-based index -> base32/hex payload string
  }

  // Returns a status object; throws on a malformed/inconsistent segment.
  addSegment(text) {
    if (!text.startsWith("B$") || text.length < 8) {
      return { kind: "not-bbqr" };
    }
    const encoding = text[2];
    const fileType = text[3];
    const total = fromBase36Pair(text.slice(4, 6));
    const index = fromBase36Pair(text.slice(6, 8));
    const payload = text.slice(8).trim();

    if (!"Z2H".includes(encoding)) {
      throw new Error(`unsupported BBQr encoding byte: ${encoding}`);
    }
    if (this.total !== null && (total !== this.total || encoding !== this.encoding || fileType !== this.fileType)) {
      throw new Error(
        `segment header changed mid-scan (was total=${this.total} enc=${this.encoding} type=${this.fileType}, ` +
        `got total=${total} enc=${encoding} type=${fileType}) -- reset and rescan from the start`
      );
    }
    this.encoding = encoding;
    this.fileType = fileType;
    this.total = total;
    const isNew = !this.segments.has(index);
    this.segments.set(index, payload);
    return { kind: "segment", index, total, isNew };
  }

  get isComplete() {
    return this.total !== null && this.segments.size === this.total;
  }

  missingIndices() {
    if (this.total === null) return [];
    const missing = [];
    for (let i = 0; i < this.total; i++) {
      if (!this.segments.has(i)) missing.push(i);
    }
    return missing;
  }

  decode() {
    return reconstructPayload(this.segments, this.encoding);
  }
}

return { fromBase36Pair, base32Decode, hexDecode, concatBytes, reconstructPayload, BBQrSession, ski };

});
