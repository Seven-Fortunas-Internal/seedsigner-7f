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
import json
import re
from dataclasses import dataclass

from seedsigner.models.review import ReviewField
from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf._ffi import ErrCode, FfiCallFailed, MlDsa7fError, call_into_buffer, err_code_name, register_argtypes
from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.models.sevenf.review_format import canonical_digest, format_timestamp as _format_timestamp, group_hex_for_display

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
}


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


class DevFundConfigJsonError(Exception):
    """ The scanned payload isn't a dev-fund definition this device will sign:
        anything sf-wallet-gov sign-devfund (or serde) would refuse. """


DEVFUND_SCHEMA_VERSION = 2
_U64_MAX = 0xFFFFFFFFFFFFFFFF
_U16_MAX = 0xFFFF
_NETWORKS = {"mainnet": ChainKind.MAINNET, "testnet": ChainKind.TESTNET, "devnet": ChainKind.DEVNET}


def _require_u64(obj: dict, key: str) -> int:
    value = obj.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or not (0 <= value <= _U64_MAX):
        raise DevFundConfigJsonError(f"{key} must be a non-negative 64-bit integer, got {value!r}")
    return value


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


def _parse_recipient(obj) -> DevfundRecipient:
    """ sf-core DevfundRecipient (#[serde(tag = "kind")]) plus its validate(). """
    if not isinstance(obj, dict):
        raise DevFundConfigJsonError(f"recipient must be an object, got {type(obj).__name__}")
    kind = obj.get("kind")
    if kind == "multisig":
        commitment = obj.get("commitment")
        if not isinstance(commitment, str):
            raise DevFundConfigJsonError("recipient.commitment must be a string")
        if len(commitment) != 128:
            raise DevFundConfigJsonError(
                f"multisig commitment must be 128 hex characters, got {len(commitment)}")
        if not _HEX_128.fullmatch(commitment):
            raise DevFundConfigJsonError("multisig commitment is not hex (ASCII 0-9, a-f only)")
        return DevfundRecipient(tag=DevfundRecipient.MULTISIG, payload=commitment)
    if kind == "address":
        address = obj.get("address")
        if not isinstance(address, str):
            raise DevFundConfigJsonError("recipient.address must be a string")
        clean = _clean_address(address)
        if not clean:
            raise DevFundConfigJsonError("recipient address is empty")
        if len(address.encode("utf-8")) > _U16_MAX:
            raise DevFundConfigJsonError("recipient address is too long")
        if not _address_is_valid(clean):
            raise DevFundConfigJsonError(f"recipient address {clean} does not decode")
        return DevfundRecipient(tag=DevfundRecipient.ADDRESS, payload=address)
    raise DevFundConfigJsonError(f"unknown recipient kind {kind!r}, expected 'address' or 'multisig'")


def _refuse_constant(name: str):
    raise ValueError(f"non-standard JSON literal {name}")


def _refuse_duplicate_keys(pairs: list) -> dict:
    keys = [k for k, _ in pairs]
    duplicates = sorted({k for k in keys if keys.count(k) > 1})
    if duplicates:
        raise ValueError(f"duplicate key(s) {duplicates}")
    return dict(pairs)


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
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise DevFundConfigJsonError(f"payload is not valid UTF-8: {e}") from e
    try:
        obj = json.loads(text, parse_constant=_refuse_constant, object_pairs_hook=_refuse_duplicate_keys)
    except (json.JSONDecodeError, RecursionError, ValueError) as e:
        # RecursionError: see genesis_config.parse_genesis_config_json.
        # ValueError: NaN/Infinity or a duplicate key -- both refused by
        # serde_json, both accepted by Python's json by default.
        raise DevFundConfigJsonError(f"payload is not valid JSON: {e}") from e
    if not isinstance(obj, dict):
        raise DevFundConfigJsonError(f"expected a JSON object, got {type(obj).__name__}")

    if "devfund_address" in obj:
        raise DevFundConfigJsonError(
            "this is a version-1 devfund-config (top-level devfund_address); its signed bytes "
            "differ, so it can't be signed -- ask the coordinator to re-run prepare-devfund")

    version = obj.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version != DEVFUND_SCHEMA_VERSION:
        raise DevFundConfigJsonError(f"devfund-config version is {version!r}, expected {DEVFUND_SCHEMA_VERSION}")

    # Exact spelling, as sf-crypto ChainKind::parse compares it.
    network = _NETWORKS.get(obj.get("network"))
    if network is None:
        raise DevFundConfigJsonError(
            f"unrecognized network {obj.get('network')!r}, expected one of {sorted(_NETWORKS)}")

    if "recipient" not in obj:
        raise DevFundConfigJsonError("recipient is missing")
    recipient = _parse_recipient(obj["recipient"])

    effective_block = _require_u64(obj, "effective_block")
    timestamp = _require_u64(obj, "timestamp")
    if timestamp == 0:
        raise DevFundConfigJsonError("timestamp is 0, so this definition names no creation time")

    signatures = obj.get("signatures", [])
    if not isinstance(signatures, list):
        raise DevFundConfigJsonError(f"signatures must be an array, got {type(signatures).__name__}")
    for i, entry in enumerate(signatures):
        if not isinstance(entry, dict) or not all(isinstance(entry.get(k), str) for k in ("signer_vk", "sig")):
            raise DevFundConfigJsonError(f"signatures[{i}] must be an object with string signer_vk and sig")

    return DevFundConfigFields(
        network=network, recipient=recipient, effective_block=effective_block, timestamp=timestamp)


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
        # A 128-hex commitment can't wrap unbroken; group it for the screen.
        ("Recipient", group_hex_for_display(fields.recipient.payload)
         if fields.recipient.tag == DevfundRecipient.MULTISIG else fields.recipient.payload),
        ("Effective block", str(fields.effective_block)),
        ("Timestamp", _format_timestamp(fields.timestamp)),
    ]


def review_fields(fields: DevFundConfigFields, canonical_bytes: bytes | None = None) -> list[ReviewField]:
    """ The no-blind-signing field list for the on-device review screen, one
        ReviewField per field carried in the signed canonical bytes
        (sf-core::DevFundConfig). Reuses models.review.ReviewField, same as
        genesis_config.py's own review_fields(). """
    out = []
    for label, value in _labeled_values(fields):
        if label == "Recipient":
            # sf-wallet-gov sign-devfund prints the same warning.
            out.append(ReviewField(label=label, value=value, is_warning=True,
                                   warning_detail="This recipient receives the ENTIRE genesis reward."))
        else:
            out.append(ReviewField(label=label, value=value))
    # The digest of the exact bytes being signed; callers pass them. Rebuilt
    # from the fields only when not given (tests, tooling).
    canonical = canonical_bytes if canonical_bytes is not None else build_canonical_bytes(fields.network, fields.recipient, fields.effective_block, fields.timestamp)
    out.append(ReviewField(label="Canonical digest", value=canonical_digest(canonical)))
    return out


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
