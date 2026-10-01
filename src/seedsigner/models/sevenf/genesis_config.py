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
"""
import ctypes
import hashlib
from datetime import datetime, timezone

from seedsigner.chains.base import ReviewField
from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf.constants import ChainKind

# Must match firmware/mldsa7f/src/genesis_config.rs's DERIVATION_SCHEME_V1
# exactly -- display-only here (parse_canonical_bytes already enforces the
# real check on the Rust side; a mismatch here would only mislabel the
# review screen, not weaken validation).
DERIVATION_SCHEME_V1 = "7fchain.ml-dsa-keygen.v1"


class GenesisConfigError(Exception):
    """ Raised for any non-zero return from the genesis-config FFI
        functions. `code` is the exact ERR_* constant from
        firmware/mldsa7f/src/ffi.rs. """
    def __init__(self, code: int, operation: str):
        self.code = code
        self.operation = operation
        super().__init__(f"mldsa7f genesis-config {operation} failed with code {code}")


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
        vary. Reuses chains.base.ReviewField (the same generic no-blind-
        signing field type the EVM chain plugin's review screens consume)
        rather than inventing a parallel type for this one flow. """
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
