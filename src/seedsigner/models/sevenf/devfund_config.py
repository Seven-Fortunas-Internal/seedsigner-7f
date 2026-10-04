"""
    Python ctypes bridge to firmware/mldsa7f's devfund-config canonical-bytes
    build/parse functions (src/ffi.rs's mldsa7f_devfund_build_canonical_bytes /
    mldsa7f_devfund_parse_canonical_bytes, backed by src/devfund_config.rs).

    RE-PORTED 2026-10-02: schema bumped to v2 on the real side -- the
    recipient is now a tagged union (Address/Multisig), not a bare address
    string. See devfund_config.rs's own module docstring for the full
    provenance. DevfundRecipient below mirrors that Rust enum.

    Reuses seedsigner.models.sevenf.mldsa's library loader (same compiled
    .so, same search order) rather than duplicating it. Mirrors
    genesis_config.py's own structure exactly -- see that module's docstring
    for the "why Python formatting here doesn't violate D12" reasoning,
    which applies identically here.
"""
import ctypes
from dataclasses import dataclass

from seedsigner.models.review import ReviewField
from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.models.sevenf.review_format import format_timestamp as _format_timestamp


#  Must match firmware/mldsa7f/src/ffi.rs's own ERR_* constants exactly --
# display-only here, the handful this module's own FFI calls can actually
# return (not every ERR_* constant in that file -- see this module's own
# argtypes registration above for which functions are called).
_ERR_NULL_POINTER = -1
_ERR_BAD_CHAIN_KIND = -12
_ERR_BAD_MESSAGE_UTF8 = -13
_ERR_OUTPUT_BUFFER_TOO_SMALL = -14
_ERR_MESSAGE_BUFFER_TOO_SMALL = -15
_ERR_PARSE_FAILED = -16
_ERR_BAD_RECIPIENT_TAG = -25

# 7f-review-parse-failure-messages-not-actionable (2026-10-04): what each
# code plausibly means for THIS artifact type, grounded directly in
# devfund_config.rs's own parse_canonical_bytes()/build_canonical_bytes()
# validation order (not guessed) -- used only to explain
# parse_canonical_bytes failures below, since that is the operator-facing
# path (a scanned devfund-config); build_canonical_bytes is test/tooling-
# only (no production view calls it), so its own failures get the
# shorter, code-name-only fallback instead.
_PARSE_FAILURE_CAUSES = (
    "the payload is missing or has the wrong domain tag (not a devfund-config at all), "
    "has an unsupported schema version, names an unrecognized network, has a malformed "
    "or truncated recipient field, or is truncated/overlong in its trailing fields"
)
_INTERNAL_ERROR_CODES = (_ERR_NULL_POINTER, _ERR_OUTPUT_BUFFER_TOO_SMALL, _ERR_MESSAGE_BUFFER_TOO_SMALL)
_ERR_CODE_NAMES = {
    _ERR_NULL_POINTER: "ERR_NULL_POINTER",
    _ERR_BAD_CHAIN_KIND: "ERR_BAD_CHAIN_KIND",
    _ERR_BAD_MESSAGE_UTF8: "ERR_BAD_MESSAGE_UTF8",
    _ERR_OUTPUT_BUFFER_TOO_SMALL: "ERR_OUTPUT_BUFFER_TOO_SMALL",
    _ERR_MESSAGE_BUFFER_TOO_SMALL: "ERR_MESSAGE_BUFFER_TOO_SMALL",
    _ERR_PARSE_FAILED: "ERR_PARSE_FAILED",
    _ERR_BAD_RECIPIENT_TAG: "ERR_BAD_RECIPIENT_TAG",
}


class DevFundConfigError(Exception):
    """ Raised for any non-zero return from the devfund-config FFI
        functions. `code` is the exact ERR_* constant from
        firmware/mldsa7f/src/ffi.rs.

        Message specificity improved 2026-10-04
        (7f-review-parse-failure-messages-not-actionable, found by the
        full-project adversarial review's UI/UX dimension): this used to
        render as a bare "mldsa7f devfund-config parse_canonical_bytes
        failed with code 3" shown straight to the operator, unlike
        genesis_config.py's own GenesisConfigJsonError, which gives
        specific field-level reasons. True single-cause differentiation
        (one message per root cause, not a list of plausible ones) would
        need either an FFI error-message buffer or more granular Rust-side
        codes -- bigger, FFI-contract-level work appropriately left to
        7f-review-ctypes-bridge-consolidation's own planned ErrCode enum,
        not attempted here. This is the honest improvement achievable from
        the code alone: distinguishing "this device has an internal bug"
        from "this artifact has a problem," and for parse_canonical_bytes
        specifically (the operator-facing scanned-artifact path), listing
        the actual plausible causes grounded in that function's own
        validation order instead of a bare code number. """
    def __init__(self, code: int, operation: str):
        self.code = code
        self.operation = operation
        code_name = _ERR_CODE_NAMES.get(code, str(code))
        if code in _INTERNAL_ERROR_CODES:
            message = f"devfund-config {operation}: internal device error ({code_name}); please report this"
        elif operation == "parse_canonical_bytes" and code == _ERR_PARSE_FAILED:
            message = f"{code_name}: {_PARSE_FAILURE_CAUSES}"
        else:
            message = f"devfund-config {operation} failed ({code_name})"
        super().__init__(message)


@dataclass(frozen=True)
class DevfundRecipient:
    """ Tagged union mirroring devfund_config.rs's own DevfundRecipient --
        tag values (1=Address, 2=Multisig) match that enum's explicit tag
        bytes exactly, never remapped at this boundary. """
    ADDRESS = 1
    MULTISIG = 2

    tag: int
    payload: str

    def __repr__(self):
        kind = "Address" if self.tag == self.ADDRESS else "Multisig" if self.tag == self.MULTISIG else self.tag
        return f"DevfundRecipient({kind}, {self.payload!r})"


@dataclass(frozen=True)
class DevFundConfigFields:
    network: ChainKind
    recipient: DevfundRecipient
    effective_block: int
    timestamp: int


# Fixed overhead per firmware/mldsa7f/src/ffi.rs's DEVFUND_FIXED_OVERHEAD
# constant (domain tag 14 + version 1 + network length prefix 2 + network
# max 7 + recipient tag 1 + payload length prefix 2 + effective_block 8 +
# timestamp 8 = 43). Kept as a literal here for the same reason
# genesis_config.py's _GENESIS_FIXED_OVERHEAD is -- the FFI call itself
# fails loudly with ERR_OUTPUT_BUFFER_TOO_SMALL rather than silently
# truncating either way, so this is a sizing convenience, not a security
# boundary.
_DEVFUND_FIXED_OVERHEAD = 43


def _lib():
    lib = mldsa._lib_handle()
    if not hasattr(lib, "_sevenf_devfund_argtypes_registered"):
        lib.mldsa7f_devfund_build_canonical_bytes.argtypes = [
            ctypes.c_uint8,                        # network
            ctypes.c_uint8,                        # recipient_tag
            ctypes.c_char_p, ctypes.c_size_t,      # payload
            ctypes.c_uint64, ctypes.c_uint64,      # effective_block, timestamp
            ctypes.c_char_p, ctypes.c_size_t,      # out
            ctypes.POINTER(ctypes.c_size_t),       # out_written
        ]
        lib.mldsa7f_devfund_build_canonical_bytes.restype = ctypes.c_int32

        lib.mldsa7f_devfund_parse_canonical_bytes.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,      # bytes
            ctypes.POINTER(ctypes.c_uint8),        # network_out
            ctypes.POINTER(ctypes.c_uint8),        # recipient_tag_out
            ctypes.c_char_p, ctypes.c_size_t,      # payload_out
            ctypes.POINTER(ctypes.c_size_t),       # payload_written_out
            ctypes.POINTER(ctypes.c_uint64),       # effective_block_out
            ctypes.POINTER(ctypes.c_uint64),       # timestamp_out
        ]
        lib.mldsa7f_devfund_parse_canonical_bytes.restype = ctypes.c_int32
        lib._sevenf_devfund_argtypes_registered = True
    return lib


def build_canonical_bytes(network: ChainKind, recipient: DevfundRecipient, effective_block: int, timestamp: int) -> bytes:
    """ Build devfund-config canonical bytes -- the exact bytes to sign.
        Raises DevFundConfigError on any failure. """
    lib = _lib()
    payload_bytes = recipient.payload.encode("utf-8")
    out_len = _DEVFUND_FIXED_OVERHEAD + len(payload_bytes) + 64  # margin, see module-level comment
    out_buf = ctypes.create_string_buffer(out_len)
    written = ctypes.c_size_t(0)

    rc = lib.mldsa7f_devfund_build_canonical_bytes(
        int(network),
        recipient.tag,
        payload_bytes, len(payload_bytes),
        effective_block, timestamp,
        out_buf, out_len,
        ctypes.byref(written),
    )
    if rc != 0:
        raise DevFundConfigError(rc, "build_canonical_bytes")

    return out_buf.raw[:written.value]


def parse_canonical_bytes(data: bytes, max_payload_len: int = 4096) -> DevFundConfigFields:
    """ Parse devfund-config canonical bytes into fields, for on-device
        review. Raises DevFundConfigError on any failure (including an
        unrecognized/corrupted payload or unknown recipient tag -- see
        firmware/mldsa7f/src/devfund_config.rs's own doc comment). """
    lib = _lib()
    network_out = ctypes.c_uint8(0)
    recipient_tag_out = ctypes.c_uint8(0)
    payload_out = ctypes.create_string_buffer(max_payload_len)
    payload_written = ctypes.c_size_t(0)
    effective_block_out = ctypes.c_uint64(0)
    timestamp_out = ctypes.c_uint64(0)

    rc = lib.mldsa7f_devfund_parse_canonical_bytes(
        data, len(data),
        ctypes.byref(network_out),
        ctypes.byref(recipient_tag_out),
        payload_out, max_payload_len,
        ctypes.byref(payload_written),
        ctypes.byref(effective_block_out),
        ctypes.byref(timestamp_out),
    )
    if rc != 0:
        raise DevFundConfigError(rc, "parse_canonical_bytes")

    return DevFundConfigFields(
        network=ChainKind(network_out.value),
        recipient=DevfundRecipient(
            tag=recipient_tag_out.value,
            payload=payload_out.raw[:payload_written.value].decode("utf-8"),
        ),
        effective_block=effective_block_out.value,
        timestamp=timestamp_out.value,
    )


def _labeled_values(fields: DevFundConfigFields) -> list[tuple[str, str]]:
    """ Single source of truth for review_fields() below -- matches
        firmware/mldsa7f/src/devfund_config.rs's render_lines() field
        order/content exactly: network, recipient kind, recipient payload,
        effective block, timestamp -- sf-core's own DevFundConfig field
        order (minus `signatures`, which this device produces rather than
        reads). Recipient kind is its own field, not folded into the
        payload label: the no-blind-signing requirement means an operator
        must see explicitly whether they're paying a single address or an
        M-of-N multisig commitment, not infer it from the string's shape.

        Labeled "Chain" (not "Network", despite the Rust field's own name)
        -- 7f-review-devfund-network-label-inconsistency, found by the
        full-project adversarial review's UI/UX dimension, 2026-10-03:
        genesis-config/Root self-cert/Deputy cross-cert all label the
        identical ChainKind concept "Chain"; this was the one flow calling
        it something else, in a ceremony sitting where an operator signs
        all four artifacts back to back on the same seed. """
    kind = "Address" if fields.recipient.tag == DevfundRecipient.ADDRESS else "Multisig"
    return [
        ("Chain", fields.network.name.lower()),
        ("Recipient kind", kind),
        ("Recipient", fields.recipient.payload),
        ("Effective block", str(fields.effective_block)),
        ("Timestamp", _format_timestamp(fields.timestamp)),
    ]


def review_fields(fields: DevFundConfigFields) -> list[ReviewField]:
    """ The no-blind-signing field list for the on-device review screen, one
        ReviewField per field carried in the signed canonical bytes
        (sf-core::DevFundConfig). Reuses models.review.ReviewField, same as
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
