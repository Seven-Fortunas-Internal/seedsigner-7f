"""
    Python bridge for 7fchain's X.509 CertRequest signing (Root self-
    certification / enrollment, Deputy cross-certification). Two parts:

    1. Parsing/validating the CertRequest JSON envelope itself -- pure
       envelope parsing (field types, hex decoding, length bounds), not
       derivation or canonical-bytes logic, so doing it in Python here
       doesn't violate D12 (see genesis_config.py's own docstring for the
       same reasoning already applied to genesis-config's review-line
       formatting).
    2. A ctypes bridge to firmware/mldsa7f's TBS-building functions
       (ffi.rs's mldsa7f_cert_root_tbs / mldsa7f_cert_deputy_tbs, backed by
       src/cert_request.rs) -- the actual crypto-adjacent, byte-precise work,
       which IS Rust, per D12.

    Confirmed field-for-field against 7fchain's real
    crates/sf-ca/src/x509_ceremony.rs::CertRequest struct (not guessed):
    version, kind, role ("root"|"deputy"), subject_vk (hex), not_before,
    days, serial (hex). `kind` is the SAME sf_core::genesis_config::ChainKind
    genesis-config's own `chain_kind` field uses, so it serializes the same
    lowercase strings ("devnet"/"testnet"/"mainnet").

    **Chain-kind cross-check, stated here since this module cannot enforce
    it itself**: a CertRequest's `kind` is chosen by the coordinator, not the
    device. Whatever calls into this module to derive the signer's own
    ML-DSA-65 keypair MUST use `CertRequestFields.kind` for that derivation
    -- never a separately-configured/assumed chain -- mirroring
    SevenFPlugin.sign()'s existing pattern of re-deriving chain_kind from the
    payload itself rather than trusting a separately-supplied argument. A
    device that used the wrong chain for derivation would produce a
    different, VALID key and silently sign a wrong-network certificate with
    no error. Found in adversarial plan-stage review, 2026-09-28 (CRITICAL).
"""
import ctypes
import json
from dataclasses import dataclass

from seedsigner.chains.base import ReviewField
from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf.constants import ML_DSA_PK_LEN, ChainKind
from seedsigner.models.sevenf.genesis_config import _format_timestamp, root_id

# Confirmed against 7fchain's crates/sf-ca/src/x509_ceremony.rs.
CERT_REQUEST_VERSION = 1
ROLE_ROOT = "root"
ROLE_DEPUTY = "deputy"

# Must match firmware/mldsa7f/src/ffi.rs's CERT_TBS_MAX_LEN exactly --
# display/sizing-only here (the FFI call itself fails loudly with a
# buffer-too-small error rather than silently truncating either way).
_CERT_TBS_MAX_LEN = 4096


class CertRequestError(Exception):
    """ Raised for a malformed/invalid CertRequest JSON envelope, or for any
        non-zero return from the cert-request TBS FFI functions (`code` is
        then the exact ERR_* constant from firmware/mldsa7f/src/ffi.rs). """
    def __init__(self, message: str, code: int = None):
        self.code = code
        super().__init__(message)


@dataclass
class CertRequestFields:
    version: int
    kind: ChainKind
    role: str
    subject_vk: bytes
    not_before: int
    days: int
    serial: bytes


def parse_cert_request_json(data: bytes) -> CertRequestFields:
    """ Parse and validate a CertRequest JSON envelope, refusing loudly
        (CertRequestError) on anything malformed rather than guessing --
        this data arrives over an untrusted airgap QR channel from a
        potentially buggy coordinator. """
    try:
        obj = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise CertRequestError(f"CertRequest is not valid JSON: {e}") from e
    if not isinstance(obj, dict):
        raise CertRequestError("CertRequest JSON must be an object")

    version = obj.get("version")
    if version != CERT_REQUEST_VERSION:
        raise CertRequestError(f"this request is version {version!r}, and this device speaks version {CERT_REQUEST_VERSION}")

    role = obj.get("role")
    if role not in (ROLE_ROOT, ROLE_DEPUTY):
        raise CertRequestError(f"role must be {ROLE_ROOT!r} or {ROLE_DEPUTY!r}, got {role!r}")

    kind_str = obj.get("kind")
    try:
        kind = ChainKind[str(kind_str).upper()]
    except KeyError:
        raise CertRequestError(f"unknown chain kind {kind_str!r} (devnet, testnet or mainnet)") from None

    subject_vk_hex = obj.get("subject_vk")
    if not isinstance(subject_vk_hex, str):
        raise CertRequestError("subject_vk must be a hex string")
    try:
        subject_vk = bytes.fromhex(subject_vk_hex.strip())
    except ValueError as e:
        raise CertRequestError(f"subject_vk is not hex: {e}") from e
    if len(subject_vk) != ML_DSA_PK_LEN:
        raise CertRequestError(f"subject_vk must be an ML-DSA-65 public key of {ML_DSA_PK_LEN} bytes, not {len(subject_vk)}")

    not_before = obj.get("not_before")
    if not isinstance(not_before, int) or isinstance(not_before, bool) or not_before < 0:
        raise CertRequestError("not_before must be a non-negative integer")

    days = obj.get("days")
    if not isinstance(days, int) or isinstance(days, bool) or days <= 0:
        raise CertRequestError("a certificate valid for zero (or negative) days is not worth signing")

    serial_hex = obj.get("serial")
    if not isinstance(serial_hex, str):
        raise CertRequestError("serial must be a hex string")
    try:
        serial = bytes.fromhex(serial_hex.strip())
    except ValueError as e:
        raise CertRequestError(f"serial is not hex: {e}") from e
    if not (1 <= len(serial) <= 20) or serial[0] & 0x80:
        raise CertRequestError("serial must be 1 to 20 bytes and positive")

    return CertRequestFields(
        version=version, kind=kind, role=role, subject_vk=subject_vk,
        not_before=not_before, days=days, serial=serial,
    )


def subject_matches(req: CertRequestFields, derived_vk: bytes) -> bool:
    """ Fail-closed comparison for no-blind-signing: a caller MUST refuse to
        sign (not just warn) on a mismatch, mirroring the real
        sf-root.rs::cmd_sign_root_cert's own hard refusal ("This request is
        for Root X, and this database holds Root Y"). Applies to the root
        flow (subject_vk vs. the device's own derived key) and, in the
        deputy flow, to the Root's own re-derived key used as issuer. """
    return req.subject_vk == derived_vk


def _lib():
    lib = mldsa._lib_handle()
    if not hasattr(lib, "_sevenf_cert_request_argtypes_registered"):
        lib.mldsa7f_cert_root_tbs.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,      # subject_vk
            ctypes.c_uint8,                        # chain_kind
            ctypes.c_uint64, ctypes.c_uint64,      # not_before, days
            ctypes.c_char_p, ctypes.c_size_t,      # serial
            ctypes.c_char_p, ctypes.c_size_t,      # out
            ctypes.POINTER(ctypes.c_size_t),       # out_written
        ]
        lib.mldsa7f_cert_root_tbs.restype = ctypes.c_int32

        lib.mldsa7f_cert_deputy_tbs.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,      # root_vk
            ctypes.c_uint8,                        # chain_kind
            ctypes.c_uint64, ctypes.c_uint64,      # root_not_before, root_days
            ctypes.c_char_p, ctypes.c_size_t,      # deputy_vk
            ctypes.c_uint64, ctypes.c_uint64,      # deputy_not_before, deputy_days
            ctypes.c_char_p, ctypes.c_size_t,      # deputy_serial
            ctypes.c_char_p, ctypes.c_size_t,      # out
            ctypes.POINTER(ctypes.c_size_t),       # out_written
        ]
        lib.mldsa7f_cert_deputy_tbs.restype = ctypes.c_int32
        lib._sevenf_cert_request_argtypes_registered = True
    return lib


def build_root_tbs(subject_vk: bytes, kind: ChainKind, not_before: int, days: int, serial: bytes) -> bytes:
    """ The unsigned body of a Root's own self-signed certificate -- the
        exact bytes a Root signs for enrollment. Raises CertRequestError on
        any failure. """
    lib = _lib()
    out_buf = ctypes.create_string_buffer(_CERT_TBS_MAX_LEN)
    written = ctypes.c_size_t(0)
    rc = lib.mldsa7f_cert_root_tbs(
        subject_vk, len(subject_vk),
        int(kind),
        not_before, days,
        serial, len(serial),
        out_buf, _CERT_TBS_MAX_LEN,
        ctypes.byref(written),
    )
    if rc != 0:
        raise CertRequestError("build_root_tbs failed", code=rc)
    return out_buf.raw[:written.value]


def build_deputy_tbs(
    root_vk: bytes, root_kind: ChainKind, root_not_before: int, root_days: int,
    deputy_vk: bytes, deputy_not_before: int, deputy_days: int, deputy_serial: bytes,
) -> bytes:
    """ The unsigned body of one Root's Deputy certificate. `root_*`
        parameters are the SAME values used to build that Root's own
        `build_root_tbs()` -- see cert_request.rs's own doc comment for why
        this device never needs to parse/verify an assembled certificate for
        this. Raises CertRequestError on any failure. """
    lib = _lib()
    out_buf = ctypes.create_string_buffer(_CERT_TBS_MAX_LEN)
    written = ctypes.c_size_t(0)
    rc = lib.mldsa7f_cert_deputy_tbs(
        root_vk, len(root_vk),
        int(root_kind),
        root_not_before, root_days,
        deputy_vk, len(deputy_vk),
        deputy_not_before, deputy_days,
        deputy_serial, len(deputy_serial),
        out_buf, _CERT_TBS_MAX_LEN,
        ctypes.byref(written),
    )
    if rc != 0:
        raise CertRequestError("build_deputy_tbs failed", code=rc)
    return out_buf.raw[:written.value]


def root_tbs_from_request(req: CertRequestFields) -> bytes:
    """ Rebuild a Root's own body from its CertRequest. Confirmed against
        x509_ceremony.rs's `root_tbs_from_request()`. """
    if req.role != ROLE_ROOT:
        raise CertRequestError(f"this is a {req.role!r} request, and it was handed to the {ROLE_ROOT!r} operation")
    return build_root_tbs(req.subject_vk, req.kind, req.not_before, req.days, req.serial)


def deputy_tbs_from_request(root_vk: bytes, root_kind: ChainKind, root_not_before: int, root_days: int, req: CertRequestFields) -> bytes:
    """ Rebuild one Root's Deputy body from the Deputy's CertRequest and that
        Root's own (already-reviewed) fields. Confirmed against
        x509_ceremony.rs's `deputy_tbs_from_request()`. """
    if req.role != ROLE_DEPUTY:
        raise CertRequestError(f"this is a {req.role!r} request, and it was handed to the {ROLE_DEPUTY!r} operation")
    return build_deputy_tbs(root_vk, root_kind, root_not_before, root_days, req.subject_vk, req.not_before, req.days, req.serial)


def _labeled_values(req: CertRequestFields) -> list[tuple[str, str]]:
    """ Single source of truth for review_fields() below. Every field a
        no-blind-signing review must show for a CertRequest: role, the
        subject key's short id (the same root_id() convention signature
        exports already use), chain, the validity window's start (raw +
        UTC, like genesis-config's own timestamp field), its length in days,
        and the serial -- shown explicitly so a coordinator re-run with a
        fresh timestamp (which changes the serial, since CertRequest's
        serial is SHA256(role||subject_vk||now||days)) is visibly
        distinguishable from what looks like "the same" request. Added
        2026-09-28 after two independent adversarial reviews both found this
        review screen missing entirely from the original story filing
        (CRITICAL). """
    return [
        ("Role", req.role),
        ("Subject key id", root_id(req.subject_vk.hex())),
        ("Chain", req.kind.name.lower()),
        ("Valid from", _format_timestamp(req.not_before)),
        ("Valid for", f"{req.days} days"),
        ("Serial", req.serial.hex()),
    ]


def review_fields(req: CertRequestFields) -> list[ReviewField]:
    """ The no-blind-signing field list for the on-device review screen.
        Reuses chains.base.ReviewField, same as genesis_config.review_fields()
        and the EVM chain plugin's review screens. """
    return [ReviewField(label=label, value=value) for label, value in _labeled_values(req)]
