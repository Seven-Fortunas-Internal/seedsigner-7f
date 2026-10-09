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
    reading of 7fchain's real `sf-root-coordinator prepare-genesis`
    (crates/sf-keytree/src/bin/sf-root-coordinator.rs) and `sf-wallet-gov
    sign-genesis` (crates/sf-wallet-gov/src/sign_ops.rs): the coordinator produces and
    every Root consumes a JSON file (sf_core::genesis_config::GenesisConfig),
    never raw canonical bytes. `parse_genesis_config_json()` below parses
    that REAL artifact directly -- the same "port the real format, don't
    invent one" discipline as every other wire-format module in this
    package -- then calls build_canonical_bytes() to compute the exact same
    bytes `sf-wallet-gov sign-genesis` would sign. Patrick's own tooling needs no
    change: it already produces this file today. parse_canonical_bytes()
    stays, both as the underlying primitive this module's own round trip
    uses and in case a future wire layer ever does carry bare canonical
    bytes directly.
"""
import ctypes
from dataclasses import dataclass, field

from seedsigner.models.review import ReviewField
from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf._ffi import FfiCallFailed, MlDsa7fError, call_into_buffer, register_argtypes
from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.models.sevenf import config_json
from seedsigner.models.sevenf.review_format import NOT_A_CALENDAR_DATE, canonical_digest, format_timestamp as _format_timestamp, utc_datetime, visible_text

# Must match firmware/mldsa7f/src/genesis_config.rs's DERIVATION_SCHEME_V1
# exactly -- display-only here (parse_canonical_bytes already enforces the
# real check on the Rust side; a mismatch here would only mislabel the
# review screen, not weaken validation).
DERIVATION_SCHEME_V1 = "7fchain.ml-dsa-keygen.v1"

# Must match sf_core::genesis_config::SCHEMA_VERSION exactly -- confirmed
# directly against that real, current source 2026-10-03.
SCHEMA_VERSION = 1


class GenesisConfigError(MlDsa7fError):
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


@dataclass(frozen=True)
class ConsensusParams:
    target_block_time_secs: int
    difficulty_adjustment_interval_blocks: int
    blocks_per_decay_period: int


# sf-core ConsensusParams::defaults_for (genesis_config.rs, 7fchain 416f576).
# Chain tempo is signed, so a definition with other values is a different
# chain; sf-wallet-gov refuses one without --accept-nondefault-consensus.
CONSENSUS_DEFAULTS = {
    ChainKind.DEVNET: ConsensusParams(30, 50, 200),
    ChainKind.TESTNET: ConsensusParams(420, 1500, 70000),
    ChainKind.MAINNET: ConsensusParams(420, 1500, 70000),
}


@dataclass(frozen=True)
class GenesisConfigFields:
    chain_kind: ChainKind
    timestamp: int
    message: str
    consensus: ConsensusParams
    # The signer_vk of each signatures[] entry ("" for a keyless record), from
    # the JSON only: never signed, so not compared with the canonical parse.
    signer_vks: tuple[str, ...] = field(default=(), compare=False)


# Fixed overhead per firmware/mldsa7f/src/ffi.rs's GENESIS_FIXED_OVERHEAD
# constant (domain tag 14 + version 1 + chain_kind max 7 + timestamp 8 +
# derivation_scheme 24 + 3 x u64 24 = 78). Kept as a literal here (not read
# from the library) since ctypes has no clean way to read a Rust `pub
# const usize` at runtime; if that constant ever changes, the "+64 margin"
# below still covers it, and the FFI call itself would fail loudly with
# ERR_OUTPUT_BUFFER_TOO_SMALL rather than silently truncating either way.
_GENESIS_FIXED_OVERHEAD = 78


_GENESIS_ARGTYPES = {
    "mldsa7f_genesis_build_canonical_bytes": ([
        ctypes.c_uint8,                       # chain_kind
        ctypes.c_uint64,                       # timestamp
        ctypes.c_char_p, ctypes.c_size_t,     # message
        ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64,  # consensus
        ctypes.c_char_p, ctypes.c_size_t,     # out
        ctypes.POINTER(ctypes.c_size_t),       # out_written
    ], ctypes.c_int32),
    "mldsa7f_genesis_parse_canonical_bytes": ([
        ctypes.c_char_p, ctypes.c_size_t,     # bytes
        ctypes.POINTER(ctypes.c_uint8),        # chain_kind_out
        ctypes.POINTER(ctypes.c_uint64),       # timestamp_out
        ctypes.c_char_p, ctypes.c_size_t,     # message_out
        ctypes.POINTER(ctypes.c_size_t),       # message_written_out
        ctypes.POINTER(ctypes.c_uint64),       # target_block_time_secs_out
        ctypes.POINTER(ctypes.c_uint64),       # difficulty_adjustment_interval_blocks_out
        ctypes.POINTER(ctypes.c_uint64),       # blocks_per_decay_period_out
    ], ctypes.c_int32),
}


def _lib():
    lib = mldsa._lib_handle()
    register_argtypes(lib, "_sevenf_genesis_argtypes_registered", _GENESIS_ARGTYPES)
    return lib


def build_canonical_bytes(chain_kind: ChainKind, timestamp: int, message: str, consensus: ConsensusParams) -> bytes:
    """ Build genesis-config canonical bytes -- the exact bytes to sign.
        Raises GenesisConfigError on any failure. """
    lib = _lib()
    message_bytes = message.encode("utf-8")
    out_len = _GENESIS_FIXED_OVERHEAD + len(message_bytes) + 64  # margin, see module-level comment

    try:
        return call_into_buffer(
            lib.mldsa7f_genesis_build_canonical_bytes,
            int(chain_kind),
            timestamp,
            message_bytes, len(message_bytes),
            consensus.target_block_time_secs,
            consensus.difficulty_adjustment_interval_blocks,
            consensus.blocks_per_decay_period,
            cap=out_len,
        )
    except FfiCallFailed as e:
        raise GenesisConfigError(e.code, "build_canonical_bytes") from e


def parse_canonical_bytes(data: bytes, max_message_len: int | None = None) -> GenesisConfigFields:
    """ Parse genesis-config canonical bytes into fields, for on-device
        review. Raises GenesisConfigError on any failure (including an
        unrecognized/corrupted payload -- see
        firmware/mldsa7f/src/genesis_config.rs's own doc comment for this
        parser's stated limitations). """
    lib = _lib()
    chain_kind_out = ctypes.c_uint8(0)
    timestamp_out = ctypes.c_uint64(0)
    # The message cannot be longer than the bytes that contain it (sf-core sets
    # no other limit), so the buffer is sized from the input.
    if max_message_len is None:
        max_message_len = max(len(data), 1)
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


# The fields of sf-core's GenesisConfig and ConsensusParams: serde refuses a
# repeat of any of them (it ignores repeats of other keys).
_GENESIS_FIELDS = frozenset({"version", "chain_kind", "timestamp", "message", "derivation_scheme", "consensus", "signatures"})
_CONSENSUS_FIELDS = frozenset({"target_block_time_secs", "difficulty_adjustment_interval_blocks", "blocks_per_decay_period"})
# Exact, case-sensitive spellings: sf-crypto's ChainKind is
# #[serde(rename_all = "lowercase")].
_CHAIN_KINDS = {"mainnet": ChainKind.MAINNET, "testnet": ChainKind.TESTNET, "devnet": ChainKind.DEVNET}


def parse_genesis_config_json(data: bytes) -> GenesisConfigFields:
    """ Parse the coordinator's real artifact: the genesis-config JSON file
        `sf-root-coordinator prepare-genesis` writes and `sf-wallet-gov
        sign-genesis` reads (sf_core::genesis_config::GenesisConfig). Refuses
        what serde and sign-genesis's validate_genesis refuse before signing:
        version, derivation scheme, chain kind, timestamp 0, and the shape of
        every field, `signatures` entries included. The signatures are read
        only for their keys (already signed? how many so far?); this device
        exports its own detached signature.

        Raises GenesisConfigJsonError. Pure JSON decoding: no FFI. """
    error = GenesisConfigJsonError
    obj = config_json.load_object(data, error, "genesis-config")
    config_json.refuse_duplicate_fields(obj, _GENESIS_FIELDS, "the genesis-config", error)
    _check_version_and_scheme(obj)
    return GenesisConfigFields(
        chain_kind=_chain_kind(obj),
        timestamp=_timestamp(obj),
        message=_message(obj),
        consensus=_consensus(obj),
        signer_vks=config_json.signer_vks(obj, error),
    )


def _check_version_and_scheme(obj: dict) -> None:
    version = obj.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version != SCHEMA_VERSION:
        raise GenesisConfigJsonError(f"genesis-config version is {config_json.shown(version)}, expected {SCHEMA_VERSION}")
    scheme = obj.get("derivation_scheme")
    if scheme != DERIVATION_SCHEME_V1:
        raise GenesisConfigJsonError(
            f"unrecognized derivation_scheme {config_json.shown(scheme)}, expected {DERIVATION_SCHEME_V1!r}")


def _chain_kind(obj: dict) -> ChainKind:
    value = obj.get("chain_kind")
    chain_kind = _CHAIN_KINDS.get(value) if isinstance(value, str) else None
    if chain_kind is None:
        raise GenesisConfigJsonError(
            f"unrecognized chain_kind {config_json.shown(value)}, expected one of {sorted(_CHAIN_KINDS)}")
    return chain_kind


def _timestamp(obj: dict) -> int:
    timestamp = config_json.require_u64(obj, "timestamp", "", GenesisConfigJsonError)
    if timestamp == 0:
        # sf-wallet-gov validate_genesis refuses it too.
        raise GenesisConfigJsonError("timestamp is 0, so this definition names no genesis time")
    return timestamp


def _message(obj: dict) -> str:
    # No length limit: sf-core puts none on the message.
    return config_json.require_string(obj, "message", "", GenesisConfigJsonError)


def _consensus(obj: dict) -> ConsensusParams:
    consensus = obj.get("consensus")
    if not isinstance(consensus, dict):
        raise GenesisConfigJsonError(f"consensus must be an object, got {type(consensus).__name__}")
    config_json.refuse_duplicate_fields(consensus, _CONSENSUS_FIELDS, "consensus", GenesisConfigJsonError)
    return ConsensusParams(*(config_json.require_u64(consensus, key, "consensus.", GenesisConfigJsonError)
                             for key in ("target_block_time_secs", "difficulty_adjustment_interval_blocks",
                                         "blocks_per_decay_period")))


# (label, ConsensusParams field, unit) for the review, the refusal and the
# warnings alike.
_CONSENSUS_SHOWN = (
    ("Target block time", "target_block_time_secs", "s"),
    ("Difficulty adjustment interval", "difficulty_adjustment_interval_blocks", " blocks"),
    ("Blocks per decay period", "blocks_per_decay_period", ""),
)


def nondefault_consensus(fields: GenesisConfigFields) -> list[tuple[str, str, str]]:
    """ (label, value, default), with units, for each consensus parameter that
        is not this network's default; sf-wallet-gov sign-genesis refuses any
        of them without --accept-nondefault-consensus (sign_ops.rs
        validate_genesis). """
    defaults = CONSENSUS_DEFAULTS[fields.chain_kind]
    return [(label, f"{getattr(fields.consensus, attr)}{unit}", f"{getattr(defaults, attr)}{unit}")
            for label, attr, unit in _CONSENSUS_SHOWN
            if getattr(fields.consensus, attr) != getattr(defaults, attr)]


def _labeled_values(fields: GenesisConfigFields) -> list[tuple[str, str]]:
    """ Single source of truth for both genesis_config_review_lines() and
        review_fields() below, so the two can't drift out of sync. Order:
        chain_kind, timestamp, message, derivation_scheme, then the three
        consensus fields -- sf-core's own GenesisConfig field order. """
    return [
        ("Chain", fields.chain_kind.name.lower()),
        ("Timestamp", _format_timestamp(fields.timestamp)),
        ("Message", visible_text(fields.message)),
        ("Derivation scheme", DERIVATION_SCHEME_V1),
        *((label, f"{getattr(fields.consensus, attr)}{unit}") for label, attr, unit in _CONSENSUS_SHOWN),
    ]


def genesis_config_review_lines(fields: GenesisConfigFields) -> list[str]:
    """ Human-readable lines for the review screen -- plain UI formatting,
        not derivation/canonical-bytes logic (see this module's own
        docstring for why this is safe to implement in Python rather than
        calling into Rust for it). Field order/content comes from
        _labeled_values() above. """
    return [f"{label}: {value}" for label, value in _labeled_values(fields)]


def review_fields(fields: GenesisConfigFields, canonical_bytes: bytes | None = None,
                  signatures_so_far: int | None = None) -> list[ReviewField]:
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
    default_of = {label: default for label, _value, default in nondefault_consensus(fields)}
    out = []
    for label, value in _labeled_values(fields):
        if label == "Timestamp" and utc_datetime(fields.timestamp) is None:
            out.append(ReviewField(label=label, value=value, is_warning=True, warning_detail=NOT_A_CALENDAR_DATE))
        elif label in default_of:
            out.append(ReviewField(
                label=label, value=value, is_warning=True,
                warning_detail=f"Not the {fields.chain_kind.name.lower()} default ({default_of[label]}). "
                               "A different tempo is a different chain: continue only if the coordinator meant it.",
            ))
        else:
            out.append(ReviewField(label=label, value=value))
    if signatures_so_far is not None:
        out.append(ReviewField(label="Signatures so far", value=str(signatures_so_far)))   # sf-wallet-gov's review prints it
    # The digest of the exact bytes being signed; callers pass them. Rebuilt
    # from the fields only when not given (tests, tooling).
    canonical = canonical_bytes if canonical_bytes is not None else build_canonical_bytes(fields.chain_kind, fields.timestamp, fields.message, fields.consensus)
    out.append(ReviewField(label="Canonical digest", value=canonical_digest(canonical)))
    return out
