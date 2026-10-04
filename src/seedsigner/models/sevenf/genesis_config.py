"""
    Python ctypes bridge to firmware/mldsa7f's genesis-config canonical-bytes
    build/parse functions (src/ffi.rs's mldsa7f_genesis_build_canonical_bytes /
    mldsa7f_genesis_parse_canonical_bytes, backed by src/genesis_config.rs).

    Reuses seedsigner.models.sevenf.mldsa's library loader (same compiled
    .so, same search order) rather than duplicating it -- see that module's
    own docstring for the search order.

    Deliberately does NOT expose a Rust-side "render to display lines"
    function: formatting parsed field values into review-screen text is
    plain UI-layer string formatting, not derivation or canonical-bytes
    logic, so duplicating it in Python (see genesis_config_review_lines()
    below) doesn't violate this project's own D12 principle ("No
    reimplementation of derivation or canonical bytes") -- it isn't either
    of those things.

    RESOLVED 2026-10-03 (closes 7f-signing-support-genesis-wire-envelope-
    undefined): the "open question" firmware/mldsa7f/src/genesis_config.rs's
    own doc comment flagged -- whether a BBQr-scanned payload is exactly
    canonical_bytes or something wraps it first -- is now answered by direct
    reading of 7fchain's real `sf-root prepare-genesis`/`sign-genesis`
    (crates/sf-keytree/src/bin/sf-root.rs): the coordinator produces and
    every Root consumes a JSON file (sf_core::genesis_config::GenesisConfig),
    never raw canonical bytes. `parse_genesis_config_json()` below parses
    that REAL artifact directly -- the same "port the real format, don't
    invent one" discipline as every other wire-format module in this
    package -- then calls build_canonical_bytes() to compute the exact same
    bytes `sf-root sign-genesis` would sign. Patrick's own tooling needs no
    change: it already produces this file today. parse_canonical_bytes()
    stays, both as the underlying primitive this module's own round trip
    uses and in case a future wire layer ever does carry bare canonical
    bytes directly.
"""
import ctypes
import hashlib
import json
from datetime import datetime, timezone

from seedsigner.models.review import ReviewField
from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf.constants import ChainKind

# Must match firmware/mldsa7f/src/genesis_config.rs's DERIVATION_SCHEME_V1
# exactly -- display-only here (parse_canonical_bytes already enforces the
# real check on the Rust side; a mismatch here would only mislabel the
# review screen, not weaken validation).
DERIVATION_SCHEME_V1 = "7fchain.ml-dsa-keygen.v1"

# Must match sf_core::genesis_config::SCHEMA_VERSION exactly -- confirmed
# directly against that real, current source 2026-10-03.
SCHEMA_VERSION = 1


class GenesisConfigError(Exception):
    """ Raised for any non-zero return from the genesis-config FFI
        functions. `code` is the exact ERR_* constant from
        firmware/mldsa7f/src/ffi.rs. """
    def __init__(self, code: int, operation: str):
        self.code = code
        self.operation = operation
        super().__init__(f"mldsa7f genesis-config {operation} failed with code {code}")


class GenesisConfigJsonError(Exception):
    """ Raised by parse_genesis_config_json() for anything structurally
        wrong with a scanned genesis-config JSON payload: not valid
        UTF-8/JSON, not an object, or a field that's missing, wrong-typed,
        or doesn't match the one value this device understands
        (version, derivation_scheme, chain_kind). Refuses rather than
        guesses -- same discipline as GenesisConfigError and every other
        wire-format parser in this package (path_lexicon.PathLexiconError,
        devfund_config.DevFundConfigError, cert_request.CertRequestError). """


class ConsensusParams:
    def __init__(self, target_block_time_secs: int, difficulty_adjustment_interval_blocks: int, blocks_per_decay_period: int):
        self.target_block_time_secs = target_block_time_secs
        self.difficulty_adjustment_interval_blocks = difficulty_adjustment_interval_blocks
        self.blocks_per_decay_period = blocks_per_decay_period

    def __eq__(self, other):
        return isinstance(other, ConsensusParams) and vars(self) == vars(other)


class GenesisConfigFields:
    def __init__(self, chain_kind: ChainKind, timestamp: int, message: str, consensus: ConsensusParams):
        self.chain_kind = chain_kind
        self.timestamp = timestamp
        self.message = message
        self.consensus = consensus

    def __eq__(self, other):
        return isinstance(other, GenesisConfigFields) and vars(self) == vars(other)


# Fixed overhead per firmware/mldsa7f/src/ffi.rs's GENESIS_FIXED_OVERHEAD
# constant (domain tag 14 + version 1 + chain_kind max 7 + timestamp 8 +
# derivation_scheme 24 + 3 x u64 24 = 78). Kept as a literal here (not read
# from the library) since ctypes has no clean way to read a Rust `pub
# const usize` at runtime; if that constant ever changes, the "+64 margin"
# below still covers it, and the FFI call itself would fail loudly with
# ERR_OUTPUT_BUFFER_TOO_SMALL rather than silently truncating either way.
_GENESIS_FIXED_OVERHEAD = 78


def _lib():
    lib = mldsa._lib_handle()
    if not hasattr(lib, "_sevenf_genesis_argtypes_registered"):
        lib.mldsa7f_genesis_build_canonical_bytes.argtypes = [
            ctypes.c_uint8,                       # chain_kind
            ctypes.c_uint64,                       # timestamp
            ctypes.c_char_p, ctypes.c_size_t,     # message
            ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64,  # consensus
            ctypes.c_char_p, ctypes.c_size_t,     # out
            ctypes.POINTER(ctypes.c_size_t),       # out_written
        ]
        lib.mldsa7f_genesis_build_canonical_bytes.restype = ctypes.c_int32

        lib.mldsa7f_genesis_parse_canonical_bytes.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,     # bytes
            ctypes.POINTER(ctypes.c_uint8),        # chain_kind_out
            ctypes.POINTER(ctypes.c_uint64),       # timestamp_out
            ctypes.c_char_p, ctypes.c_size_t,     # message_out
            ctypes.POINTER(ctypes.c_size_t),       # message_written_out
            ctypes.POINTER(ctypes.c_uint64),       # target_block_time_secs_out
            ctypes.POINTER(ctypes.c_uint64),       # difficulty_adjustment_interval_blocks_out
            ctypes.POINTER(ctypes.c_uint64),       # blocks_per_decay_period_out
        ]
        lib.mldsa7f_genesis_parse_canonical_bytes.restype = ctypes.c_int32
        lib._sevenf_genesis_argtypes_registered = True
    return lib


def build_canonical_bytes(chain_kind: ChainKind, timestamp: int, message: str, consensus: ConsensusParams) -> bytes:
    """ Build genesis-config canonical bytes -- the exact bytes to sign.
        Raises GenesisConfigError on any failure. """
    lib = _lib()
    message_bytes = message.encode("utf-8")
    out_len = _GENESIS_FIXED_OVERHEAD + len(message_bytes) + 64  # margin, see module-level comment
    out_buf = ctypes.create_string_buffer(out_len)
    written = ctypes.c_size_t(0)

    rc = lib.mldsa7f_genesis_build_canonical_bytes(
        int(chain_kind),
        timestamp,
        message_bytes, len(message_bytes),
        consensus.target_block_time_secs,
        consensus.difficulty_adjustment_interval_blocks,
        consensus.blocks_per_decay_period,
        out_buf, out_len,
        ctypes.byref(written),
    )
    if rc != 0:
        raise GenesisConfigError(rc, "build_canonical_bytes")

    return out_buf.raw[:written.value]


def parse_canonical_bytes(data: bytes, max_message_len: int = 4096) -> GenesisConfigFields:
    """ Parse genesis-config canonical bytes into fields, for on-device
        review. Raises GenesisConfigError on any failure (including an
        unrecognized/corrupted payload -- see
        firmware/mldsa7f/src/genesis_config.rs's own doc comment for this
        parser's stated limitations). """
    lib = _lib()
    chain_kind_out = ctypes.c_uint8(0)
    timestamp_out = ctypes.c_uint64(0)
    message_out = ctypes.create_string_buffer(max_message_len)
    message_written = ctypes.c_size_t(0)
    t1 = ctypes.c_uint64(0)
    t2 = ctypes.c_uint64(0)
    t3 = ctypes.c_uint64(0)

    rc = lib.mldsa7f_genesis_parse_canonical_bytes(
        data, len(data),
        ctypes.byref(chain_kind_out),
        ctypes.byref(timestamp_out),
        message_out, max_message_len,
        ctypes.byref(message_written),
        ctypes.byref(t1),
        ctypes.byref(t2),
        ctypes.byref(t3),
    )
    if rc != 0:
        raise GenesisConfigError(rc, "parse_canonical_bytes")

    return GenesisConfigFields(
        chain_kind=ChainKind(chain_kind_out.value),
        timestamp=timestamp_out.value,
        message=message_out.raw[:message_written.value].decode("utf-8"),
        consensus=ConsensusParams(t1.value, t2.value, t3.value),
    )


def _require_u64(obj: dict, key: str, where: str) -> int:
    value = obj.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or not (0 <= value <= 0xFFFFFFFFFFFFFFFF):
        raise GenesisConfigJsonError(f"{where}.{key} must be a non-negative 64-bit integer, got {value!r}")
    return value


def parse_genesis_config_json(data: bytes) -> GenesisConfigFields:
    """ Parse the REAL coordinator artifact: the genesis-config JSON file
        `sf-root prepare-genesis` writes and `sf-root sign-genesis` reads
        (sf_core::genesis_config::GenesisConfig), confirmed field-for-field
        against that real struct 2026-10-03 -- see this module's own
        "RESOLVED" docstring note. This is the actual scan-time entry point
        now; see SevenFScanGenesisConfigView (views/sevenf_views.py) and
        SevenFPlugin.parse_sign_request/sign (chains/sevenf/plugin.py).

        `signatures`, if present (the file may already carry other Roots'
        detached signatures -- canonical_bytes never covers them, so
        signing a partly assembled file produces the same signature as
        signing the bare one, confirmed against sf-root.rs's own
        cmd_sign_genesis doc comment), is read but not used: this device
        always exports its own detached signature-only artifact
        (build_root_sig_json), never re-embeds into this file.

        Raises GenesisConfigJsonError for anything structurally wrong --
        not valid UTF-8/JSON, not an object, or a field missing/wrong-typed/
        not matching the one value this device understands. Refuses rather
        than guesses, same as every other wire-format parser here. Does
        NOT call the Rust FFI at all; this is pure JSON decoding, the same
        "plain parsing, not canonical-bytes logic" reasoning this module's
        own docstring already applies to genesis_config_review_lines(). """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise GenesisConfigJsonError(f"payload is not valid UTF-8: {e}") from e

    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as e:
        # RecursionError: Python's json module is recursive-descent, so a
        # pathologically deeply-nested payload (e.g. ~100k levels of "[") --
        # untrusted, coordinator-supplied, BBQr-scanned bytes -- raises
        # RecursionError rather than JSONDecodeError. Caught here so it
        # still surfaces as a clean refusal (GenesisConfigJsonError, which
        # SevenFScanGenesisConfigView/SevenFPlugin actually catch), not an
        # unhandled exception that falls through to a generic/debug error
        # screen. Found by adversarial review, 2026-10-03.
        raise GenesisConfigJsonError(f"payload is not valid JSON: {e}") from e

    if not isinstance(obj, dict):
        raise GenesisConfigJsonError(f"expected a JSON object, got {type(obj).__name__}")

    version = obj.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version != SCHEMA_VERSION:
        raise GenesisConfigJsonError(f"genesis-config version is {version!r}, expected {SCHEMA_VERSION}")

    derivation_scheme = obj.get("derivation_scheme")
    if derivation_scheme != DERIVATION_SCHEME_V1:
        raise GenesisConfigJsonError(
            f"unrecognized derivation_scheme {derivation_scheme!r}, expected {DERIVATION_SCHEME_V1!r}"
        )

    # Exact, case-sensitive match -- the real side's #[serde(rename_all =
    # "lowercase")] on sf_crypto::address::ChainKind (confirmed directly
    # against that source 2026-10-03) deserializes only the exact lowercase
    # variant spelling, nothing case-insensitive. Matching more leniently
    # here would accept a payload the real binary itself would reject.
    chain_kind_str = obj.get("chain_kind")
    chain_kind = {
        "mainnet": ChainKind.MAINNET,
        "testnet": ChainKind.TESTNET,
        "devnet": ChainKind.DEVNET,
    }.get(chain_kind_str)
    if chain_kind is None:
        raise GenesisConfigJsonError(
            f"unrecognized chain_kind {chain_kind_str!r}, expected one of ['mainnet', 'testnet', 'devnet']"
        )

    timestamp = obj.get("timestamp")
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or not (0 <= timestamp <= 0xFFFFFFFFFFFFFFFF):
        raise GenesisConfigJsonError(f"timestamp must be a non-negative 64-bit integer, got {timestamp!r}")

    message = obj.get("message")
    if not isinstance(message, str):
        raise GenesisConfigJsonError(f"message must be a string, got {type(message).__name__}")

    consensus_obj = obj.get("consensus")
    if not isinstance(consensus_obj, dict):
        raise GenesisConfigJsonError(f"consensus must be an object, got {type(consensus_obj).__name__}")
    consensus = ConsensusParams(
        target_block_time_secs=_require_u64(consensus_obj, "target_block_time_secs", "consensus"),
        difficulty_adjustment_interval_blocks=_require_u64(
            consensus_obj, "difficulty_adjustment_interval_blocks", "consensus"
        ),
        blocks_per_decay_period=_require_u64(consensus_obj, "blocks_per_decay_period", "consensus"),
    )

    # Optional (#[serde(default)] on the real struct), and never read for
    # its content here (canonical_bytes never covers it, this device always
    # exports its own detached signature). Still shape-validated, not just
    # ignored outright: the real GenesisConfig fails to deserialize AT ALL
    # if `signatures` is present but any entry doesn't match RootSig's
    # shape (both fields required strings) -- found by adversarial review,
    # 2026-10-03, confirmed by direct testing against the real struct. This
    # device should refuse a file the real tooling would never have
    # produced, the same "refuse rather than guess" reasoning applied to
    # every other field above.
    signatures_obj = obj.get("signatures", [])
    if not isinstance(signatures_obj, list):
        raise GenesisConfigJsonError(f"signatures must be an array, got {type(signatures_obj).__name__}")
    for i, entry in enumerate(signatures_obj):
        if not isinstance(entry, dict):
            raise GenesisConfigJsonError(f"signatures[{i}] must be an object, got {type(entry).__name__}")
        for key in ("signer_vk", "sig"):
            if not isinstance(entry.get(key), str):
                raise GenesisConfigJsonError(f"signatures[{i}].{key} must be a string")

    return GenesisConfigFields(
        chain_kind=chain_kind,
        timestamp=timestamp,
        message=message,
        consensus=consensus,
    )


def _format_timestamp(timestamp: int) -> str:
    """ Shows both the raw signed value (exactly what's inside the bytes
        being signed -- an operator cross-checking against the coordinator's
        own display must see the identical number) and its UTC
        interpretation, so the operator can actually evaluate whether the
        date is sane -- a bare Unix epoch integer isn't independently
        reviewable by a human. Found live 2026-09-27 (7F hardware
        walkthrough). `timestamp` is coordinator-supplied, unvalidated data
        (u64, so it can be far outside any real calendar date) -- refuse to
        let an out-of-range value crash the whole review screen; show the
        raw value alone with a clear note instead ("refuse rather than
        guess" for the interpretation, not for the raw value itself, which
        is always shown). """
    try:
        utc_str = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, OverflowError, ValueError):
        return f"{timestamp} (not a valid calendar date)"
    return f"{timestamp}\n({utc_str})"


def _labeled_values(fields: GenesisConfigFields) -> list[tuple[str, str]]:
    """ Single source of truth for both genesis_config_review_lines() and
        review_fields() below, so the two can't drift out of sync with each
        other the way genesis_config_review_lines() previously drifted from
        firmware/mldsa7f/src/genesis_config.rs's render_lines() (silently
        missing the "Derivation scheme" line -- caught only when building
        review_fields() and comparing against the real Rust function this
        was supposed to mirror). Order/content matches render_lines()
        exactly: chain_kind, timestamp, message, derivation_scheme, then the
        three consensus fields -- sf-core's own GenesisConfig field order. """
    return [
        ("Chain", fields.chain_kind.name.lower()),
        ("Timestamp", _format_timestamp(fields.timestamp)),
        ("Message", fields.message),
        ("Derivation scheme", DERIVATION_SCHEME_V1),
        ("Target block time", f"{fields.consensus.target_block_time_secs}s"),
        ("Difficulty adjustment interval", f"{fields.consensus.difficulty_adjustment_interval_blocks} blocks"),
        ("Blocks per decay period", str(fields.consensus.blocks_per_decay_period)),
    ]


def genesis_config_review_lines(fields: GenesisConfigFields) -> list[str]:
    """ Human-readable lines for the review screen -- plain UI formatting,
        not derivation/canonical-bytes logic (see this module's own
        docstring for why this is safe to implement in Python rather than
        calling into Rust for it). Mirrors
        firmware/mldsa7f/src/genesis_config.rs's render_lines() field
        order/content for consistency, but is not required to call it. """
    return [f"{label}: {value}" for label, value in _labeled_values(fields)]


def review_fields(fields: GenesisConfigFields) -> list[ReviewField]:
    """ The no-blind-signing field list for the on-device review screen, one
        ReviewField per field carried in the signed canonical bytes
        (sf-core::GenesisConfig). derivation_scheme is included even though
        it has exactly one valid value today -- a wrong one would already
        have made parse_canonical_bytes() raise, so it can never reach here
        with a different value -- because no-blind-signing means every
        signed field is shown to the operator, not only the ones that could
        vary. Reuses models.review.ReviewField (the same generic no-blind-
        signing field type the EVM chain plugin's review screens consume,
        via chains.base's re-export) rather than inventing a parallel type
        for this one flow. """
    return [ReviewField(label=label, value=value) for label, value in _labeled_values(fields)]


def root_id(vk_hex: str) -> str:
    """ Ports 7fchain's crates/sf-core/src/genesis_config.rs::root_id()
        exactly: `hex::encode(&Sha256::digest(&vk)[..10])` -- SHA-256 of the
        raw key, truncated to 10 bytes, hex-encoded (20 characters).
        Re-confirmed directly against that real, current source 2026-09-30
        after finding this function's PREVIOUS implementation here
        (`vk_hex[:20].lower()`, a bare string truncation with no hashing at
        all) computed a value with zero relationship to the real one --
        found via a 7fchain sync, not by this module's own test suite,
        since that suite's own fixture values encoded the same wrong
        assumption rather than a real reference vector. Used to name a
        signature file the same way sf-root.rs's own outbox does
        (`<id>.genesis`, `<id>.rootcert`, `<id>.deputy`) and to show the
        operator a verifiable identity fingerprint on the review screen
        before signing (D11) -- both uses depend on this matching the real
        function exactly, not just being *a* fingerprint. """
    vk = bytes.fromhex(vk_hex)
    return hashlib.sha256(vk).digest()[:10].hex()


def build_root_sig_json(signer_vk: bytes, sig: bytes, *, with_vk: bool = False) -> dict:
    """ The real, on-wire signature-export shape this device actually
        produces -- 7fchain's crates/sf-core/src/genesis_config.rs's RootSig
        struct, confirmed field-for-field against that real source (not
        guessed) and against crates/sf-keytree/src/bin/sf-root.rs's own
        `cmd_sign_genesis` (its output is exactly `RootSig{signer_vk, sig}`,
        nothing else -- no header, no re-embedded config).

        Only the signature leaves the device per ceremony (D11: a Root's
        verification key is enrolled once and never sent again). `signer_vk`
        therefore defaults to the empty string, mirroring sf-root.rs's own
        `--with-vk` flag defaulting to false; the Root CA pubkey has its own
        one-time enrollment export (SevenFExportPubkeyQRView) and does not
        need to travel again inside every signature.

        `sig` is hex-encoded the same way sf-root.rs's own `hex::encode(...)`
        calls produce it -- Python's bytes.hex() matches that byte-for-byte
        (lowercase, no separators, no prefix). """
    return {
        "signer_vk": signer_vk.hex() if with_vk else "",
        "sig": sig.hex(),
    }


def root_sig_filename(signer_vk: bytes) -> str:
    """ Matches 7fchain's own sf-root binary filename convention exactly
        (crates/sf-keytree/src/bin/sf-root.rs's `cmd_sign_genesis`:
        `{id}.genesis` where `id = root_id(vk_hex)`) -- confirmed against
        that real, current source, not guessed. Display-only here (this
        device exports over QR per R16, not to a filesystem) but kept so an
        operator naming a manually-saved copy on the receiving end uses the
        same convention sf-root itself would have. """
    return f"{root_id(signer_vk.hex())}.genesis"
