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

from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf.constants import ChainKind


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


def genesis_config_review_lines(fields: GenesisConfigFields) -> list[str]:
    """ Human-readable lines for the review screen -- plain UI formatting,
        not derivation/canonical-bytes logic (see this module's own
        docstring for why this is safe to implement in Python rather than
        calling into Rust for it). Mirrors
        firmware/mldsa7f/src/genesis_config.rs's render_lines() field
        order/content for consistency, but is not required to call it. """
    return [
        f"Chain: {fields.chain_kind.name.lower()}",
        f"Timestamp: {fields.timestamp}",
        f"Message: {fields.message}",
        f"Target block time: {fields.consensus.target_block_time_secs}s",
        f"Difficulty adjustment interval: {fields.consensus.difficulty_adjustment_interval_blocks} blocks",
        f"Blocks per decay period: {fields.consensus.blocks_per_decay_period}",
    ]
