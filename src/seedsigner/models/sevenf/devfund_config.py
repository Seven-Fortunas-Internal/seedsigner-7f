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
import re
from dataclasses import dataclass, field

from seedsigner.models.review import ReviewField
from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf._ffi import ErrCode, FfiCallFailed, MlDsa7fError, call_into_buffer, err_code_name, register_argtypes
from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.models.sevenf import config_json
from seedsigner.models.sevenf.review_format import canonical_digest, format_timestamp as _format_timestamp, group_hex_for_display, visible_text

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
# Codes this module's own FFI calls (build/parse_canonical_bytes) can
# actually return and that mean "this device has an internal bug" rather
# than "this artifact has a problem" -- not every ErrCode member, just the
# ones reachable here.
_INTERNAL_ERROR_CODES = (ErrCode.NULL_POINTER, ErrCode.OUTPUT_BUFFER_TOO_SMALL, ErrCode.MESSAGE_BUFFER_TOO_SMALL)

# Codes this module's own FFI calls can actually return, period -- the
# shared err_code_name() knows every ERR_* constant in ffi.rs, but this
# module's pre-consolidation behavior only ever named the handful below,
# falling back to the bare number for anything else (adversarial review,
# 2026-10-05: widening the lookup to the full shared enum silently changed
# message text for out-of-contract codes -- this clamp restores that).
_KNOWN_CODES = frozenset({
    ErrCode.NULL_POINTER, ErrCode.BAD_CHAIN_KIND, ErrCode.BAD_MESSAGE_UTF8,
    ErrCode.OUTPUT_BUFFER_TOO_SMALL, ErrCode.MESSAGE_BUFFER_TOO_SMALL,
    ErrCode.PARSE_FAILED, ErrCode.BAD_RECIPIENT_TAG,
})


def _code_name(code: int) -> str:
    return err_code_name(code) if code in _KNOWN_CODES else str(code)


class DevFundConfigError(MlDsa7fError):
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
        code_name = _code_name(code)
        if code in _INTERNAL_ERROR_CODES:
            message = f"devfund-config {operation}: internal device error ({code_name}); please report this"
        elif operation == "parse_canonical_bytes" and code == ErrCode.PARSE_FAILED:
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
    # The signer_vk of each signatures[] entry ("" for a keyless record), from
    # the JSON only: never signed, so not compared with the canonical parse.
    signer_vks: tuple[str, ...] = field(default=(), compare=False)


# Fixed overhead per firmware/mldsa7f/src/ffi.rs's DEVFUND_FIXED_OVERHEAD
# constant (domain tag 14 + version 1 + network length prefix 2 + network
# max 7 + recipient tag 1 + payload length prefix 2 + effective_block 8 +
# timestamp 8 = 43). Kept as a literal here for the same reason
# genesis_config.py's _GENESIS_FIXED_OVERHEAD is -- the FFI call itself
# fails loudly with ERR_OUTPUT_BUFFER_TOO_SMALL rather than silently
# truncating either way, so this is a sizing convenience, not a security
# boundary.
_DEVFUND_FIXED_OVERHEAD = 43


_DEVFUND_ARGTYPES = {
    "mldsa7f_devfund_build_canonical_bytes": ([
        ctypes.c_uint8,                        # network
        ctypes.c_uint8,                        # recipient_tag
        ctypes.c_char_p, ctypes.c_size_t,      # payload
        ctypes.c_uint64, ctypes.c_uint64,      # effective_block, timestamp
        ctypes.c_char_p, ctypes.c_size_t,      # out
        ctypes.POINTER(ctypes.c_size_t),       # out_written
    ], ctypes.c_int32),
    "mldsa7f_devfund_parse_canonical_bytes": ([
        ctypes.c_char_p, ctypes.c_size_t,      # bytes
        ctypes.POINTER(ctypes.c_uint8),        # network_out
        ctypes.POINTER(ctypes.c_uint8),        # recipient_tag_out
        ctypes.c_char_p, ctypes.c_size_t,      # payload_out
        ctypes.POINTER(ctypes.c_size_t),       # payload_written_out
        ctypes.POINTER(ctypes.c_uint64),       # effective_block_out
        ctypes.POINTER(ctypes.c_uint64),       # timestamp_out
    ], ctypes.c_int32),
}


def _lib():
    lib = mldsa._lib_handle()
    register_argtypes(lib, "_sevenf_devfund_argtypes_registered", _DEVFUND_ARGTYPES)
    return lib


# Registered apart from _DEVFUND_ARGTYPES so a library built before this
# function existed fails only address validation, not every devfund call.
_ADDRESS_ARGTYPES = {
    "mldsa7f_address_validate": ([ctypes.c_char_p, ctypes.c_size_t], ctypes.c_int32),
    "mldsa7f_address_describe": ([ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p], ctypes.c_int32),
}
# mldsa7f_address_describe's layer and signature-type bytes (ffi.rs); the
# network byte is a ChainKind.
_LAYER_NAMES = ("L1", "L2")
_SIG_TYPE_NAMES = ("ML-DSA", "Falcon", "WOTS+")


def _address_is_valid(address: str) -> bool:
    """ The crate's own Address::decode (prefix, length, charset, checksum) --
        what sf-core's DevfundRecipient::validate() runs. """
    lib = mldsa._lib_handle()
    try:
        register_argtypes(lib, "_sevenf_address_argtypes_registered", _ADDRESS_ARGTYPES)
    except AttributeError as e:
        raise DevFundConfigJsonError(
            "this device's signing library is too old to check a recipient address; update the firmware") from e
    raw = address.encode("utf-8")
    return lib.mldsa7f_address_validate(raw, len(raw)) == 0


def describe_address(address: str) -> tuple[str, str, str]:
    """ (network, layer, signature type) of an address, as 7fchain's
        Address::decode reads it. For display; acceptance is _address_is_valid. """
    lib = mldsa._lib_handle()
    register_argtypes(lib, "_sevenf_address_argtypes_registered", _ADDRESS_ARGTYPES)
    raw = _clean_address(address).encode("utf-8")
    out = ctypes.create_string_buffer(3)
    if lib.mldsa7f_address_describe(raw, len(raw), out) != 0:
        raise DevFundConfigJsonError(f"recipient address {address!r} does not decode")
    n, l, t = out.raw
    return ChainKind(n).name.lower(), _LAYER_NAMES[l], _SIG_TYPE_NAMES[t]


def build_canonical_bytes(network: ChainKind, recipient: DevfundRecipient, effective_block: int, timestamp: int) -> bytes:
    """ Build devfund-config canonical bytes -- the exact bytes to sign.
        Raises DevFundConfigError on any failure. """
    lib = _lib()
    payload_bytes = recipient.payload.encode("utf-8")
    out_len = _DEVFUND_FIXED_OVERHEAD + len(payload_bytes) + 64  # margin, see module-level comment

    try:
        return call_into_buffer(
            lib.mldsa7f_devfund_build_canonical_bytes,
            int(network),
            recipient.tag,
            payload_bytes, len(payload_bytes),
            effective_block, timestamp,
            cap=out_len,
        )
    except FfiCallFailed as e:
        raise DevFundConfigError(e.code, "build_canonical_bytes") from e


def parse_canonical_bytes(data: bytes, max_payload_len: int | None = None) -> DevFundConfigFields:
    """ Parse devfund-config canonical bytes into fields, for on-device
        review. Raises DevFundConfigError on any failure (including an
        unrecognized/corrupted payload or unknown recipient tag -- see
        firmware/mldsa7f/src/devfund_config.rs's own doc comment). """
    lib = _lib()
    network_out = ctypes.c_uint8(0)
    recipient_tag_out = ctypes.c_uint8(0)
    # The payload cannot be longer than the bytes that contain it (sf-core bounds
    # it only by its u16 length prefix), so the buffer is sized from the input.
    if max_payload_len is None:
        max_payload_len = max(len(data), 1)
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


class DevFundConfigJsonError(Exception):
    """ The scanned payload isn't a dev-fund definition this device will sign:
        anything sf-wallet-gov sign-devfund (or serde) would refuse. """


DEVFUND_SCHEMA_VERSION = 2
_U16_MAX = 0xFFFF
_NETWORKS = {"mainnet": ChainKind.MAINNET, "testnet": ChainKind.TESTNET, "devnet": ChainKind.DEVNET}


# Rust hex::decode: ASCII hex digits only -- no whitespace (which Python's
# bytes.fromhex skips) and no non-ASCII digits.
_HEX_128 = re.compile(r"[0-9a-fA-F]{128}")
# What Rust str::trim strips: Unicode White_Space. Python's str.strip()
# also strips \x1c-\x1f, which Rust would hand on to Address::decode.
_RUST_WHITESPACE = "\t\n\x0b\x0c\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"


def _clean_address(s: str) -> str:
    """ sf-core clean_address(): trim, then drop a trailing `# comment`. """
    trimmed = s.strip(_RUST_WHITESPACE)
    idx = trimmed.find("#")
    return trimmed[:idx].rstrip(_RUST_WHITESPACE) if idx >= 0 else trimmed


# The fields of sf-core's DevFundConfig and of each DevfundRecipient variant
# (#[serde(tag = "kind")]): serde refuses a repeat of any of them and ignores
# repeats of other keys (tests/test_sevenf_device_limits.py).
_DEVFUND_FIELDS = frozenset({"version", "network", "recipient", "effective_block", "timestamp", "signatures"})
_RECIPIENT_FIELDS = {"multisig": frozenset({"kind", "commitment"}), "address": frozenset({"kind", "address"})}


def _refuse_duplicates(obj: dict, known: frozenset, where: str) -> None:
    config_json.refuse_duplicate_fields(obj, known, where, DevFundConfigJsonError)


def _parse_recipient(obj) -> DevfundRecipient:
    """ sf-core DevfundRecipient (#[serde(tag = "kind")]) plus its validate(). """
    if not isinstance(obj, dict):
        raise DevFundConfigJsonError(f"recipient must be an object, got {type(obj).__name__}")
    _refuse_duplicates(obj, frozenset({"kind"}), "recipient")    # the tag, before the variant is known
    kind = obj.get("kind")
    if not isinstance(kind, str) or kind not in _RECIPIENT_FIELDS:
        raise DevFundConfigJsonError(
            f"unknown recipient kind {config_json.shown(kind)}, expected 'address' or 'multisig'")
    _refuse_duplicates(obj, _RECIPIENT_FIELDS[kind], "recipient")
    if kind == "multisig":
        commitment = config_json.require_string(obj, "commitment", "recipient.", DevFundConfigJsonError)
        if len(commitment) != 128:
            raise DevFundConfigJsonError(
                f"multisig commitment must be 128 hex characters, got {len(commitment)}")
        if not _HEX_128.fullmatch(commitment):
            raise DevFundConfigJsonError("multisig commitment is not hex (ASCII 0-9, a-f only)")
        return DevfundRecipient(tag=DevfundRecipient.MULTISIG, payload=commitment)
    address = config_json.require_string(obj, "address", "recipient.", DevFundConfigJsonError)
    clean = _clean_address(address)
    if not clean:
        raise DevFundConfigJsonError("recipient address is empty")
    if len(address.encode("utf-8")) > _U16_MAX:
        raise DevFundConfigJsonError("recipient address is too long")
    if not _address_is_valid(clean):
        raise DevFundConfigJsonError(f"recipient address {config_json.shown(clean)} does not decode")
    return DevfundRecipient(tag=DevfundRecipient.ADDRESS, payload=address)


def parse_devfund_config_json(data: bytes) -> DevFundConfigFields:
    """ Parse the coordinator's real artifact: `devfund-unsigned.json` as
        `sf-root-coordinator prepare-devfund` writes it and `sf-wallet-gov
        sign-devfund` reads it (sf_core::genesis_config::DevFundConfig, 7fchain
        416f576). Refuses everything sign-devfund refuses before signing --
        validate_devfund(): version 2, a known network spelling,
        DevfundRecipient::validate(), timestamp != 0 -- plus serde's own shape
        checks, including `signatures` entries. The signatures themselves are
        not used; this device always exports its own detached signature.

        Raises DevFundConfigJsonError. Pure JSON decoding except the address
        check, which uses the Rust Address::decode over FFI. """
    error = DevFundConfigJsonError
    obj = config_json.load_object(data, error, "devfund-config")
    _refuse_duplicates(obj, _DEVFUND_FIELDS, "the devfund-config")

    if "recipient" not in obj:
        # serde fails first, and sf-core says why for a version-1 file
        # (genesis_config.rs, the devfund_address hint); an extra
        # devfund_address in a version-2 file is ignored, as serde ignores it.
        if "devfund_address" in obj:
            raise error("this is a version-1 devfund-config (top-level devfund_address); its signed bytes "
                        "differ, so it can't be signed -- ask the coordinator to re-run prepare-devfund")
        raise error("recipient is missing")

    version = obj.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version != DEVFUND_SCHEMA_VERSION:
        raise error(f"devfund-config version is {config_json.shown(version)}, expected {DEVFUND_SCHEMA_VERSION}")

    # Exact spelling, as sf-crypto ChainKind::parse compares it.
    value = obj.get("network")
    network = _NETWORKS.get(value) if isinstance(value, str) else None
    if network is None:
        raise error(f"unrecognized network {config_json.shown(value)}, expected one of {sorted(_NETWORKS)}")
    recipient = _parse_recipient(obj["recipient"])

    effective_block = config_json.require_u64(obj, "effective_block", "", error)
    timestamp = config_json.require_u64(obj, "timestamp", "", error)
    if timestamp == 0:
        raise error("timestamp is 0, so this definition names no creation time")

    return DevFundConfigFields(
        network=network, recipient=recipient, effective_block=effective_block, timestamp=timestamp,
        signer_vks=config_json.signer_vks(obj, error))


_RECIPIENT_LABEL = "Recipient"   # review_fields() adds the warnings to this field


def _labeled_values(fields: DevFundConfigFields) -> list[tuple[str, str]]:
    """ Single source of truth for review_fields() below. Field order:
        network, recipient kind, recipient payload,
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
        # A 128-hex commitment can't wrap unbroken; group it for the screen.
        (_RECIPIENT_LABEL, group_hex_for_display(fields.recipient.payload)
         if fields.recipient.tag == DevfundRecipient.MULTISIG else visible_text(fields.recipient.payload)),
        ("Effective block", str(fields.effective_block)),
        ("Timestamp", _format_timestamp(fields.timestamp)),
    ]


def review_fields(fields: DevFundConfigFields, canonical_bytes: bytes | None = None,
                  signatures_so_far: int | None = None) -> list[ReviewField]:
    """ The no-blind-signing field list for the on-device review screen, one
        ReviewField per field carried in the signed canonical bytes
        (sf-core::DevFundConfig). Reuses models.review.ReviewField, same as
        genesis_config.py's own review_fields(). """
    out = []
    for label, value in _labeled_values(fields):
        if label != _RECIPIENT_LABEL:
            out.append(ReviewField(label=label, value=value))
            continue
        # sf-wallet-gov sign-devfund prints the same warning.
        out.append(ReviewField(label=label, value=value, is_warning=True,
                               warning_detail="This recipient receives the ENTIRE genesis reward."))
        if fields.recipient.tag == DevfundRecipient.ADDRESS:
            # 7fchain accepts any address that decodes (DevfundRecipient::validate
            # checks nothing more), so this device does too; it only shows what
            # the address is, and flags one that is not on this dev fund's network.
            try:
                network, layer, sig_type = describe_address(fields.recipient.payload)
            except DevFundConfigJsonError:
                out.append(ReviewField(label="Recipient address", value="does not decode", is_warning=True,
                                       warning_detail="7fchain would refuse this recipient. Do not sign."))
            else:
                other = network != fields.network.name.lower()
                out.append(ReviewField(
                    label="Recipient address", value=f"{network}, {layer}, {sig_type}", is_warning=other,
                    warning_detail=f"This address is on {network}, not {fields.network.name.lower()}." if other else None))
    if signatures_so_far is not None:
        out.append(ReviewField(label="Signatures so far", value=str(signatures_so_far)))   # sf-wallet-gov's review prints it
    # The digest of the exact bytes being signed; callers pass them. Rebuilt
    # from the fields only when not given (tests, tooling).
    canonical = canonical_bytes if canonical_bytes is not None else build_canonical_bytes(fields.network, fields.recipient, fields.effective_block, fields.timestamp)
    out.append(ReviewField(label="Canonical digest", value=canonical_digest(canonical)))
    return out
