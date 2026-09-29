"""
    Python ctypes bridge to firmware/mldsa7f's devfund-config canonical-bytes
    build/parse functions (src/ffi.rs's mldsa7f_devfund_build_canonical_bytes /
    mldsa7f_devfund_parse_canonical_bytes, backed by src/devfund_config.rs).

    Reuses seedsigner.models.sevenf.mldsa's library loader (same compiled
    .so, same search order) rather than duplicating it. Mirrors
    genesis_config.py's own structure exactly -- see that module's docstring
    for the "why Python formatting here doesn't violate D12" reasoning,
    which applies identically here.
"""
import ctypes

from seedsigner.chains.base import ReviewField
from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf.constants import ChainKind


class DevFundConfigError(Exception):
    """ Raised for any non-zero return from the devfund-config FFI
        functions. `code` is the exact ERR_* constant from
        firmware/mldsa7f/src/ffi.rs. """
    def __init__(self, code: int, operation: str):
        self.code = code
        self.operation = operation
        super().__init__(f"mldsa7f devfund-config {operation} failed with code {code}")


class DevFundConfigFields:
    def __init__(self, network: ChainKind, devfund_address: str, effective_block: int, timestamp: int):
        self.network = network
        self.devfund_address = devfund_address
        self.effective_block = effective_block
        self.timestamp = timestamp

    def __eq__(self, other):
        return isinstance(other, DevFundConfigFields) and vars(self) == vars(other)


# Fixed overhead per firmware/mldsa7f/src/ffi.rs's DEVFUND_FIXED_OVERHEAD
# constant (domain tag 14 + version 1 + network max 7 + effective_block 8 +
# timestamp 8 = 38). Kept as a literal here for the same reason
# genesis_config.py's _GENESIS_FIXED_OVERHEAD is -- the FFI call itself
# fails loudly with ERR_OUTPUT_BUFFER_TOO_SMALL rather than silently
# truncating either way, so this is a sizing convenience, not a security
# boundary.
_DEVFUND_FIXED_OVERHEAD = 38


def _lib():
    lib = mldsa._lib_handle()
    if not hasattr(lib, "_sevenf_devfund_argtypes_registered"):
        lib.mldsa7f_devfund_build_canonical_bytes.argtypes = [
            ctypes.c_uint8,                        # network
            ctypes.c_char_p, ctypes.c_size_t,      # devfund_address
            ctypes.c_uint64, ctypes.c_uint64,      # effective_block, timestamp
            ctypes.c_char_p, ctypes.c_size_t,      # out
            ctypes.POINTER(ctypes.c_size_t),       # out_written
        ]
        lib.mldsa7f_devfund_build_canonical_bytes.restype = ctypes.c_int32

        lib.mldsa7f_devfund_parse_canonical_bytes.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,      # bytes
            ctypes.POINTER(ctypes.c_uint8),        # network_out
            ctypes.c_char_p, ctypes.c_size_t,      # devfund_address_out
            ctypes.POINTER(ctypes.c_size_t),       # devfund_address_written_out
            ctypes.POINTER(ctypes.c_uint64),       # effective_block_out
            ctypes.POINTER(ctypes.c_uint64),       # timestamp_out
        ]
        lib.mldsa7f_devfund_parse_canonical_bytes.restype = ctypes.c_int32
        lib._sevenf_devfund_argtypes_registered = True
    return lib


def build_canonical_bytes(network: ChainKind, devfund_address: str, effective_block: int, timestamp: int) -> bytes:
    """ Build devfund-config canonical bytes -- the exact bytes to sign.
        Raises DevFundConfigError on any failure. """
    lib = _lib()
    address_bytes = devfund_address.encode("utf-8")
    out_len = _DEVFUND_FIXED_OVERHEAD + len(address_bytes) + 64  # margin, see module-level comment
    out_buf = ctypes.create_string_buffer(out_len)
    written = ctypes.c_size_t(0)

    rc = lib.mldsa7f_devfund_build_canonical_bytes(
        int(network),
        address_bytes, len(address_bytes),
        effective_block, timestamp,
        out_buf, out_len,
        ctypes.byref(written),
    )
    if rc != 0:
        raise DevFundConfigError(rc, "build_canonical_bytes")

    return out_buf.raw[:written.value]


def parse_canonical_bytes(data: bytes, max_address_len: int = 4096) -> DevFundConfigFields:
    """ Parse devfund-config canonical bytes into fields, for on-device
        review. Raises DevFundConfigError on any failure (including an
        unrecognized/corrupted payload -- see
        firmware/mldsa7f/src/devfund_config.rs's own doc comment for this
        parser's stated limitations). """
    lib = _lib()
    network_out = ctypes.c_uint8(0)
    address_out = ctypes.create_string_buffer(max_address_len)
    address_written = ctypes.c_size_t(0)
    effective_block_out = ctypes.c_uint64(0)
    timestamp_out = ctypes.c_uint64(0)

    rc = lib.mldsa7f_devfund_parse_canonical_bytes(
        data, len(data),
        ctypes.byref(network_out),
        address_out, max_address_len,
        ctypes.byref(address_written),
        ctypes.byref(effective_block_out),
        ctypes.byref(timestamp_out),
    )
    if rc != 0:
        raise DevFundConfigError(rc, "parse_canonical_bytes")

    return DevFundConfigFields(
        network=ChainKind(network_out.value),
        devfund_address=address_out.raw[:address_written.value].decode("utf-8"),
        effective_block=effective_block_out.value,
        timestamp=timestamp_out.value,
    )


def _format_timestamp(timestamp: int) -> str:
    """ Same "refuse rather than guess" doctrine as genesis_config.py's
        own _format_timestamp() -- see that function's docstring. """
    from datetime import datetime, timezone
    try:
        utc_str = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, OverflowError, ValueError):
        return f"{timestamp} (not a valid calendar date)"
    return f"{timestamp}\n({utc_str})"


def _labeled_values(fields: DevFundConfigFields) -> list[tuple[str, str]]:
    """ Single source of truth for review_fields() below -- matches
        firmware/mldsa7f/src/devfund_config.rs's render_lines() field
        order/content exactly: network, devfund_address, effective_block,
        timestamp -- sf-core's own DevFundConfig field order (minus
        `signatures`, which this device produces rather than reads). """
    return [
        ("Network", fields.network.name.lower()),
        ("Devfund address", fields.devfund_address),
        ("Effective block", str(fields.effective_block)),
        ("Timestamp", _format_timestamp(fields.timestamp)),
    ]


def review_fields(fields: DevFundConfigFields) -> list[ReviewField]:
    """ The no-blind-signing field list for the on-device review screen, one
        ReviewField per field carried in the signed canonical bytes
        (sf-core::DevFundConfig). Reuses chains.base.ReviewField, same as
        genesis_config.py's own review_fields(). """
    return [ReviewField(label=label, value=value) for label, value in _labeled_values(fields)]


def build_root_sig_json(signer_vk: bytes, sig: bytes, *, with_vk: bool = False) -> dict:
    """ The real, on-wire signature-export shape this device actually
        produces -- 7fchain's crates/sf-core/src/genesis_config.rs's RootSig
        struct, the SAME shape devfund signatures use ("Every Root signature
        over devfund_config_canonical_bytes, in any order. Same shape and
        same rules as GenesisConfig::signatures" -- that struct's own doc
        comment). Identical to genesis_config.py's build_root_sig_json();
        kept as its own function here (not imported from that module) so
        this module has no cross-dependency on genesis_config.py for a
        concept that's really owned by the shared RootSig wire format, not
        by genesis specifically. """
    return {
        "signer_vk": signer_vk.hex() if with_vk else "",
        "sig": sig.hex(),
    }
