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
// sf-wallet-gov prints and names every governance file by (7fchain ce04ae9).
// Uses the Web Crypto API (crypto.subtle),
// present natively in both browsers (secure context -- same requirement
// this page's camera access already has) and Node 19+, so no new
// dependency. Returns null for input that isn't well-formed hex.
async function sha256OfHex(hexText) {
  const clean = String(hexText).trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(clean) || clean.length % 2 !== 0) return null;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function ski(hexText) {
  const digest = await sha256OfHex(hexText);
  return digest === null ? null : digest.slice(0, 40);  // 20 bytes
}

// pin(): the full SHA-256 of the raw key, 64 hex -- 7fchain's x509::vk_pin(),
// the "root pin" a federation member reports over a second channel
// (ceremony-federation-member.md Step 4). The ski is its first 40 hex.
async function pin(hexText) {
  return sha256OfHex(hexText);
}

// vkSummary(): a <ski>.txt record of one key for the holder -- the bundle
// above with a reminder that the pin is only a check when confirmed over a
// second channel (the .vk itself must stay bare hex for 7fchain's tools).
async function vkSummary(hexText) {
  const bundle = await vkBundle(hexText);
  if (bundle === null) return null;
  const id = bundle.split("\n")[0].slice("subject key id: ".length);
  return {
    name: `${id}.txt`,
    text: "# Record only. Send the .vk file; confirm the pin by phone -- a pin in a file proves nothing.\n" + bundle,
  };
}

// ─── Export envelopes from the device (models/sevenf/export_envelope.py) ───
// {"sf7_export": 1, "kind": ..., "file": ..., "body": <exact file contents>}.
// The page saves `body` verbatim under `file`, after checking `file` against
// `body` wherever the name can be derived from the content.

// No paths, no hidden files, no "..", bounded length.
const SAFE_FILE_NAME = /^(?!.*\.\.)[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const OID_ML_DSA_65 = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];  // 2.16.840.1.101.3.4.3.18

function bytesToHexStr(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function pemCertToDer(pem) {
  const m = /^-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)-----END CERTIFICATE-----\n?$/.exec(String(pem));
  if (!m) return null;
  try {
    const bin = atob(m[1].replace(/\n/g, ""));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch (e) {
    return null;  // malformed base64
  }
}

// PEM exactly as sf-wallet-gov (and the device's der_to_pem) writes it:
// 64-character lines and a trailing newline.
function derToPem(der) {
  let bin = "";
  for (const b of der) bin += String.fromCharCode(b);
  const b64 = btoa(bin);
  const lines = b64.match(/.{1,64}/g) || [];
  return ["-----BEGIN CERTIFICATE-----", ...lines, "-----END CERTIFICATE-----"].join("\n") + "\n";
}

// Minimal DER reader: {tag, off (of the tag), start, end} of the TLV at `off`.
function readTlv(b, off) {
  if (off + 2 > b.length) return null;
  const tag = b[off];
  let len = b[off + 1];
  let p = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 3 || p + n > b.length) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[p + i];
    p += n;
  }
  if (p + len > b.length) return null;
  return { tag, off, start: p, end: p + len };
}

function derChildren(b, tlv) {
  const out = [];
  for (let o = tlv.start; o < tlv.end;) {
    const t = readTlv(b, o);
    if (!t || t.end > tlv.end) return null;
    out.push(t);
    o = t.end;
  }
  return out;
}

// The certificate's subject key, found by walking the structure (RFC 5280:
// Certificate -> tbsCertificate -> [version] serial sigAlg issuer validity
// subject subjectPublicKeyInfo) -- not by searching for a byte pattern,
// which a decoy earlier in the certificate could satisfy. Null unless the
// key is ML-DSA-65 (OID 2.16.840.1.101.3.4.3.18) and 1952 bytes long.
function certSubjectVk(der) {
  const cert = readTlv(der, 0);
  if (!cert || cert.tag !== 0x30 || cert.end !== der.length) return null;
  const top = derChildren(der, cert);
  if (!top || top.length !== 3 || top[0].tag !== 0x30) return null;
  let tbs = derChildren(der, top[0]);
  if (!tbs) return null;
  if (tbs.length && tbs[0].tag === 0xa0) tbs = tbs.slice(1);  // explicit version
  if (tbs.length < 6) return null;
  const spki = tbs[5];
  if (spki.tag !== 0x30) return null;
  const parts = derChildren(der, spki);
  if (!parts || parts.length !== 2 || parts[0].tag !== 0x30 || parts[1].tag !== 0x03) return null;
  const alg = derChildren(der, parts[0]);
  if (!alg || alg.length < 1) return null;
  const oid = der.slice(alg[0].off, alg[0].end);
  if (oid.length !== OID_ML_DSA_65.length || !OID_ML_DSA_65.every((x, i) => oid[i] === x)) return null;
  const bits = parts[1];
  if (bits.end - bits.start !== 1953 || der[bits.start] !== 0x00) return null;
  return der.slice(bits.start + 1, bits.end);
}

async function inspectExport(jsonText) {
  let obj;
  try {
    obj = JSON.parse(jsonText);
  } catch (e) {
    return null;
  }
  if (!obj || typeof obj !== "object" || !("sf7_export" in obj)) return null;  // not an envelope

  const out = {
    kind: obj.kind,
    file: obj.file,
    body: typeof obj.body === "string" ? obj.body : JSON.stringify(obj.body),
    ski: null,
    pin: null,
    error: null,
  };
  const fail = (msg) => ({ ...out, error: msg });
  if (obj.sf7_export !== 1) return fail(`unsupported export version ${JSON.stringify(obj.sf7_export)}`);
  if (typeof obj.file !== "string" || !SAFE_FILE_NAME.test(obj.file)) return fail(`unsafe file name ${JSON.stringify(obj.file)}`);
  if (typeof obj.body !== "string") return fail("export has no body");

  if (obj.kind === "root-cert") {
    const der = pemCertToDer(obj.body);
    const vk = der && certSubjectVk(der);
    if (!vk) return fail("body is not an ML-DSA-65 certificate");
    if (derToPem(der) !== obj.body) return fail("body is not canonical PEM (64-character lines, trailing newline)");
    const vkHex = bytesToHexStr(vk);
    out.pin = await pin(vkHex);
    out.ski = out.pin.slice(0, 40);
    const expected = `root-${out.ski}.pem`;
    if (obj.file !== expected) return fail(`file name ${obj.file} does not match the certificate (expected ${expected})`);
    return out;
  }
  return fail(`unsupported export kind ${JSON.stringify(obj.kind)}`);
}

// saveMethod(): how the page saves a file under the name it computed.
// Desktop Chrome/Edge have a folder picker (save straight into
// governance/<role>/outbox); iPhone Safari has none but can share a named
// file (Save to Files, AirDrop, Mail); anything else gets a plain download.
function saveMethod({ hasSavePicker, canShareFiles }) {
  if (hasSavePicker) return "picker";
  if (canShareFiles) return "share";
  return "download";
}

// vkBundle(): everything a member hands the coordinator for one key, in one
// paste, labelled the way sf-wallet-gov prints it. null for non-hex input.
async function vkBundle(hexText) {
  const digest = await sha256OfHex(hexText);
  if (digest === null) return null;
  const id = digest.slice(0, 40);
  return `subject key id: ${id}\npin: ${digest}\nfile: ${id}.vk\nvk: ${String(hexText).trim().toLowerCase()}\n`;
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

return { fromBase36Pair, base32Decode, hexDecode, concatBytes, reconstructPayload, BBQrSession, ski, pin, vkBundle, vkSummary, saveMethod, inspectExport, certSubjectVk };

});
