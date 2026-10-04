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

from seedsigner.models.review import ReviewField
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


class DevfundRecipient:
    """ Tagged union mirroring devfund_config.rs's own DevfundRecipient --
        tag values (1=Address, 2=Multisig) match that enum's explicit tag
        bytes exactly, never remapped at this boundary. """
    ADDRESS = 1
    MULTISIG = 2

    def __init__(self, tag: int, payload: str):
        self.tag = tag
        self.payload = payload

    def __eq__(self, other):
        return isinstance(other, DevfundRecipient) and vars(self) == vars(other)

    def __repr__(self):
        kind = "Address" if self.tag == self.ADDRESS else "Multisig" if self.tag == self.MULTISIG else self.tag
        return f"DevfundRecipient({kind}, {self.payload!r})"


class DevFundConfigFields:
    def __init__(self, network: ChainKind, recipient: DevfundRecipient, effective_block: int, timestamp: int):
        self.network = network
        self.recipient = recipient
        self.effective_block = effective_block
        self.timestamp = timestamp

    def __eq__(self, other):
        return isinstance(other, DevFundConfigFields) and vars(self) == vars(other)


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
