"""
    Python bridge for 7fchain's X.509 CertRequest signing (Root self-
    certification / enrollment) and Deputy cross-certification. Two
    generations of the Deputy flow coexist in this module's own history --
    see the "PKCS#10 REWORK" note below for which one is current.

    1. Parsing/validating the CertRequest JSON envelope itself -- pure
       envelope parsing (field types, hex decoding, length bounds), not
       derivation or canonical-bytes logic, so doing it in Python here
       doesn't violate D12 (see genesis_config.py's own docstring for the
       same reasoning already applied to genesis-config's review-line
       formatting). **STALE as of 2026-10-03, corrected here rather than
       left to contradict the newer note below**: this was "still current
       for Root self-certification, confirmed unaffected by the Deputy
       rework" when written (deputy-cross-cert-pkcs10-rework-plan.md §6),
       but the Root self-cert PKCS#10 rework below retired that usage too.
       `parse_cert_request_json`/`CertRequestFields`/`root_tbs_from_request`/
       `subject_matches`/`review_fields`/`ROLE_ROOT`/`ROLE_DEPUTY`/
       `CERT_REQUEST_VERSION` now have zero callers anywhere in the view
       layer (confirmed by grep) -- kept only because removing them is out
       of this story's reviewed scope (flagged as a follow-up, not silently
       expanded into), not because anything still calls them for real.
    2. A ctypes bridge to firmware/mldsa7f's TBS-building functions
       (ffi.rs's mldsa7f_cert_root_tbs and the PKCS#10-based entry points
       below, backed by src/cert_request.rs) -- the actual crypto-adjacent,
       byte-precise work, which IS Rust, per D12.

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

    **PKCS#10 REWORK, 2026-10-03** (closes
    7f-signing-support-deputy-cross-certification-pkcs10-rework): 7fchain
    commit `ea91758` ("retire the detached Deputy path") removed the JSON
    `CertRequest{role:"deputy"}` wire shape and `deputy_tbs_from_request`
    entirely -- "A Root answers a Deputy's PKCS#10 with a whole certificate,
    so there is nothing to assemble and no serial to pin across the Roots."
    `build_deputy_tbs`/`deputy_tbs_from_request` (and the FFI/Rust functions
    they called) were removed from this device in the same pass -- they
    implemented a ceremony the network no longer performs. The real current
    Deputy flow (see the Gate-1 plan's §2-§3 for the full reasoning, and its
    §9 for the adversarial review that shaped it) is: a Root receives (1)
    its OWN real, signed X.509 certificate (never reconstructed -- the one
    real production path, `sign-deputy --csr`, requires and validates the
    actual file) and (2) the Deputy's self-signed PKCS#10 CSR (proof of
    possession, verified on-device -- the first time this device verifies
    rather than only signs). `chain_kind` is operator-supplied (a PKCS#10
    carries no network) and cross-checked against the real certificate's
    own embedded value. `parse_root_certificate_der`/`verify_and_parse_csr_der`/
    `generate_serial`/`build_deputy_tbs_v2`/`deputy_cross_cert_v2_review_fields`
    below implement this; `ParsedRootCertificate`/`ParsedCsr` are their
    return shapes.

    **ROOT SELF-CERT PKCS#10 REWORK, 2026-10-03** (backs
    7f-signing-support-root-self-certification-pkcs10-rework): 7fchain
    commit `3bf7bfe` ("four MVP tasks on the Root ceremony", M-38) removed
    the JSON `CertRequest{role:"root"}` wire shape the same way `ea91758`
    removed the Deputy one. The real current flow (`sf-root sign-root-cert`)
    has no external input at all: the Root derives its own key, self-signs
    using its own wall-clock time and a fresh CSPRNG serial, and the real
    `issue()` function assembles a COMPLETE certificate in the same call
    that signs -- there is no detached-signature export for this artifact in
    the real ceremony. This device's prior export shape (D11:
    `{signer_vk, sig}`, no TBS) turns out to be unreconstructable downstream
    for any artifact whose TBS carries device-chosen fields (the CSPRNG
    serial, the wall-clock `not_before`) -- see
    docs/7f-integration/root-self-cert-pkcs10-rework-plan.md §3 for the full
    finding (filed as its own bug, `7f-signing-support-detached-sig-
    export-unreconstructable`, since it also affects the Deputy flow above).
    `assemble_root_cert_der`/`root_self_cert_review_fields` below implement
    the fix for this artifact: assemble a complete X.509 `Certificate`
    on-device and export THAT, not a detached signature.
"""
import ctypes
import json
import secrets
from dataclasses import dataclass

from seedsigner.chains.base import ReviewField
from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf.constants import ML_DSA_PK_LEN, ML_DSA_SIG_LEN, ChainKind
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

        lib.mldsa7f_cert_parse_root.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,      # cert_der
            ctypes.c_char_p, ctypes.c_size_t,      # subject_vk_out
            ctypes.POINTER(ctypes.c_uint64),       # not_before_out
            ctypes.POINTER(ctypes.c_uint64),       # not_after_out
            ctypes.POINTER(ctypes.c_uint8),        # chain_kind_out
        ]
        lib.mldsa7f_cert_parse_root.restype = ctypes.c_int32

        lib.mldsa7f_cert_verify_csr.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,      # csr_der
            ctypes.c_char_p, ctypes.c_size_t,      # subject_vk_out
        ]
        lib.mldsa7f_cert_verify_csr.restype = ctypes.c_int32

        lib.mldsa7f_cert_deputy_tbs_v2.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,      # root_cert_der
            ctypes.c_char_p, ctypes.c_size_t,      # deputy_csr_der
            ctypes.c_uint8,                        # chain_kind
            ctypes.c_uint64, ctypes.c_uint64,      # now, days
            ctypes.c_char_p, ctypes.c_size_t,      # serial
            ctypes.c_char_p, ctypes.c_size_t,      # out
            ctypes.POINTER(ctypes.c_size_t),       # out_written
        ]
        lib.mldsa7f_cert_deputy_tbs_v2.restype = ctypes.c_int32

        lib.mldsa7f_cert_assemble_root.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,      # tbs_der
            ctypes.c_char_p, ctypes.c_size_t,      # signature
            ctypes.c_char_p, ctypes.c_size_t,      # subject_vk
            ctypes.c_char_p, ctypes.c_size_t,      # out
            ctypes.POINTER(ctypes.c_size_t),       # out_written
        ]
        lib.mldsa7f_cert_assemble_root.restype = ctypes.c_int32

        lib.mldsa7f_cert_assemble_deputy.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,      # tbs_der
            ctypes.c_char_p, ctypes.c_size_t,      # signature
            ctypes.c_char_p, ctypes.c_size_t,      # root_cert_der
            ctypes.c_char_p, ctypes.c_size_t,      # out
            ctypes.POINTER(ctypes.c_size_t),       # out_written
        ]
        lib.mldsa7f_cert_assemble_deputy.restype = ctypes.c_int32
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


def root_tbs_from_request(req: CertRequestFields) -> bytes:
    """ Rebuild a Root's own body from its CertRequest. Confirmed against
        x509_ceremony.rs's `root_tbs_from_request()`. """
    if req.role != ROLE_ROOT:
        raise CertRequestError(f"this is a {req.role!r} request, and it was handed to the {ROLE_ROOT!r} operation")
    return build_root_tbs(req.subject_vk, req.kind, req.not_before, req.days, req.serial)


# --- PKCS#10 / real-certificate-based Deputy cross-certification ---
# (see this module's own "PKCS#10 REWORK" docstring note above).

# Must match firmware/mldsa7f/src/ffi.rs's CERT_SUBJECT_VK_LEN exactly.
_CERT_SUBJECT_VK_LEN = ML_DSA_PK_LEN

# Must match 7fchain's real crates/sf-ca/src/x509_ceremony.rs::DEPUTY_DAYS
# exactly (10 years) -- confirmed directly against that source.
DEPUTY_DAYS = 3650


@dataclass
class ParsedRootCertificate:
    """ A real X.509 Root certificate's fields, parsed off the wire -- never
        reconstructed. Mirrors cert_request.rs's own ParsedRootCertificate
        (minus `authority_key_id`, which only the Rust-side TBS builder
        needs internally). """
    subject_vk: bytes
    not_before: int
    not_after: int
    chain_kind: ChainKind


@dataclass
class ParsedCsr:
    """ A PKCS#10 CSR's subject public key, returned only after its
        self-signature verifies -- proof the requester holds the matching
        private key. Does NOT establish identity (see the Gate-1 plan's §8
        enrollment-fingerprint doctrine, applied in the view layer). """
    subject_vk: bytes


def generate_serial(length: int = 16) -> bytes:
    """ A fresh positive serial number from the device's own CSPRNG.
        `mldsa7f_cert_deputy_tbs_v2` requires the caller to supply one --
        see ffi.rs's own doc comment: "this function never silently falls
        back to a different source of randomness than the rest of this
        device uses." Matches build_ca_tbs's own validation (1 to 20 bytes,
        high bit of the first byte clear so the DER INTEGER encoding stays
        positive) -- see root_tbs/CertRequest's own serial validation above
        for the same bound, applied there to a coordinator-supplied value
        instead of a generated one. """
    serial = bytearray(secrets.token_bytes(length))
    serial[0] &= 0x7F
    return bytes(serial)


def parse_root_certificate_der(cert_der: bytes) -> ParsedRootCertificate:
    """ Parse a real, signed X.509 Root certificate (scanned from a QR) --
        the issuing Root's own certificate, used as issuer context for a
        Deputy cross-certification. Raises CertRequestError on anything
        malformed, missing, or not a CA certificate. See cert_request.rs's
        own parse_root_certificate() doc comment for exactly which fields
        this reads (confirmed field-for-field against what
        deputy_tbs_for_root's real IssuerRef::Ca(cert) branch needs). """
    lib = _lib()
    subject_vk_out = ctypes.create_string_buffer(_CERT_SUBJECT_VK_LEN)
    not_before_out = ctypes.c_uint64(0)
    not_after_out = ctypes.c_uint64(0)
    chain_kind_out = ctypes.c_uint8(0)
    rc = lib.mldsa7f_cert_parse_root(
        cert_der, len(cert_der),
        subject_vk_out, _CERT_SUBJECT_VK_LEN,
        ctypes.byref(not_before_out),
        ctypes.byref(not_after_out),
        ctypes.byref(chain_kind_out),
    )
    if rc != 0:
        raise CertRequestError("couldn't parse the Root certificate", code=rc)
    return ParsedRootCertificate(
        subject_vk=subject_vk_out.raw[:_CERT_SUBJECT_VK_LEN],
        not_before=not_before_out.value,
        not_after=not_after_out.value,
        chain_kind=ChainKind(chain_kind_out.value),
    )


def verify_and_parse_csr_der(csr_der: bytes) -> ParsedCsr:
    """ Parse a PKCS#10 CSR (scanned from a QR) and verify its
        self-signature -- proof the requester holds the matching private
        key. Raises CertRequestError on malformed DER, a wrong algorithm,
        or a signature that does not verify. This device's first-ever
        on-device signature verification over untrusted scanned input --
        see this module's own "PKCS#10 REWORK" docstring note.

        A CSR's `extensionRequest` attribute (RFC 2985), if present, is
        never read or honored here or anywhere downstream -- confirmed
        against cert_request.rs's own verify_and_parse_csr() doc comment,
        which only reads the CSR's algorithm/signature/public-key fields.
        The Deputy certificate's own extensions are always built from the
        issuing Root's real certificate and the operator-confirmed
        chain_kind (Gate-1 plan's §7.6), never from anything the CSR asks
        for. """
    lib = _lib()
    subject_vk_out = ctypes.create_string_buffer(_CERT_SUBJECT_VK_LEN)
    rc = lib.mldsa7f_cert_verify_csr(
        csr_der, len(csr_der),
        subject_vk_out, _CERT_SUBJECT_VK_LEN,
    )
    if rc != 0:
        raise CertRequestError("couldn't verify this certificate request", code=rc)
    return ParsedCsr(subject_vk=subject_vk_out.raw[:_CERT_SUBJECT_VK_LEN])


def build_deputy_tbs_v2(
    root_cert_der: bytes, deputy_csr_der: bytes, chain_kind: ChainKind, now: int, days: int, serial: bytes,
) -> bytes:
    """ Build a Deputy certificate TBS body against the issuing Root's REAL
        certificate and the Deputy's PKCS#10 CSR -- both independently
        re-parsed/re-verified inside this one Rust call, never trusting an
        earlier parse (closes any time-of-check/time-of-use gap; see
        ffi.rs's own mldsa7f_cert_deputy_tbs_v2 doc comment). `chain_kind`
        is the operator-confirmed value and is checked against the real
        Root certificate's own chain_kind, fail-closed on mismatch. Raises
        CertRequestError on any failure. """
    lib = _lib()
    out_buf = ctypes.create_string_buffer(_CERT_TBS_MAX_LEN)
    written = ctypes.c_size_t(0)
    rc = lib.mldsa7f_cert_deputy_tbs_v2(
        root_cert_der, len(root_cert_der),
        deputy_csr_der, len(deputy_csr_der),
        int(chain_kind),
        now, days,
        serial, len(serial),
        out_buf, _CERT_TBS_MAX_LEN,
        ctypes.byref(written),
    )
    if rc != 0:
        raise CertRequestError("couldn't build the Deputy certificate body", code=rc)
    return out_buf.raw[:written.value]


def deputy_cross_cert_v2_review_fields(
    root_cert: ParsedRootCertificate, csr: ParsedCsr, chain_kind: ChainKind, now: int, days: int, serial: bytes,
) -> list[ReviewField]:
    """ The no-blind-signing field list for the PKCS#10-based Deputy
        cross-certification review screen (Gate-1 plan §5/§8). Shows the
        REAL issuing Root certificate's own fingerprint AND validity
        window -- plan §8 extends the existing fingerprint-only doctrine to
        the window too, since a coordinator presenting a genuine-but-wrong
        certificate (different Root, backdated, unexpectedly long-lived)
        must be just as catchable as a wrong fingerprint -- the Deputy
        CSR's proven-possession fingerprint, the operator-confirmed
        chain_kind, and the new certificate's own granted validity window
        and serial. """
    return [
        ReviewField(label="Issuing Root: Subject key id", value=root_id(root_cert.subject_vk.hex())),
        ReviewField(label="Issuing Root: Valid from", value=_format_timestamp(root_cert.not_before)),
        ReviewField(label="Issuing Root: Valid until", value=_format_timestamp(root_cert.not_after)),
        ReviewField(label="Chain", value=chain_kind.name.lower()),
        ReviewField(label="Deputy: Subject key id", value=root_id(csr.subject_vk.hex())),
        ReviewField(label="Deputy: Valid from", value=_format_timestamp(now)),
        ReviewField(label="Deputy: Valid for", value=f"{days} days"),
        ReviewField(label="Deputy: Serial", value=serial.hex()),
    ]


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


# --- Root self-certification: real-certificate assembly (PKCS#10-era rework) ---
# (see this module's own "ROOT SELF-CERT PKCS#10 REWORK" docstring note above).

# Must match 7fchain's real crates/sf-ca/src/x509_ceremony.rs::ROOT_DAYS
# exactly (20 years) -- confirmed directly against that source.
ROOT_DAYS = 7_300

# Must match firmware/mldsa7f/src/ffi.rs's CERT_FULL_MAX_LEN exactly --
# display/sizing-only here (the FFI call itself fails loudly with a
# buffer-too-small error rather than silently truncating either way).
_CERT_FULL_MAX_LEN = _CERT_TBS_MAX_LEN + ML_DSA_SIG_LEN + 64


def assemble_root_cert_der(tbs_der: bytes, signature: bytes, subject_vk: bytes) -> bytes:
    """ Assemble a complete, DER-encoded X.509 `Certificate` from a Root TBS
        body this device already built (`build_root_tbs`) and a signature
        this device already produced over it, via
        root_ceremony.sign_with_root_ca(). Raises CertRequestError if the
        signature doesn't verify over the TBS under this key, or if
        `subject_vk` doesn't match the TBS's own embedded subject key --
        see cert_request.rs's own assemble_root_cert_der() doc comment for
        the full safety-property reasoning (verifies against the
        re-encoded TBS bytes, not the raw input, so a decode/re-encode
        mismatch fails closed rather than producing a self-inconsistent
        certificate). """
    lib = _lib()
    out_buf = ctypes.create_string_buffer(_CERT_FULL_MAX_LEN)
    written = ctypes.c_size_t(0)
    rc = lib.mldsa7f_cert_assemble_root(
        tbs_der, len(tbs_der),
        signature, len(signature),
        subject_vk, len(subject_vk),
        out_buf, _CERT_FULL_MAX_LEN,
        ctypes.byref(written),
    )
    if rc != 0:
        raise CertRequestError("couldn't assemble the Root certificate", code=rc)
    return out_buf.raw[:written.value]


def assemble_deputy_cert_der(tbs_der: bytes, signature: bytes, root_cert_der: bytes) -> bytes:
    """ Assemble a complete, DER-encoded X.509 `Certificate` from a Deputy TBS
        body this device already built (`build_deputy_tbs_v2`) and a signature
        this device already produced over it under the ISSUING ROOT'S key
        (never the Deputy's own) -- closes the Deputy half of
        `7f-signing-support-detached-sig-export-unreconstructable`, the same
        detached-signature-export gap already fixed for Root self-cert above.
        Raises CertRequestError if the signature doesn't verify over the TBS
        under the Root's real key (re-parsed fresh from `root_cert_der`), or
        if the Deputy TBS's own AuthorityKeyIdentifier doesn't match that same
        Root certificate's key identifier -- see cert_request.rs's own
        assemble_deputy_cert_der() doc comment for the full safety-property
        reasoning (self-signed-vs-CA-issued distinction, and why the AKI
        binding check is genuine defense-in-depth rather than a no-op). """
    lib = _lib()
    out_buf = ctypes.create_string_buffer(_CERT_FULL_MAX_LEN)
    written = ctypes.c_size_t(0)
    rc = lib.mldsa7f_cert_assemble_deputy(
        tbs_der, len(tbs_der),
        signature, len(signature),
        root_cert_der, len(root_cert_der),
        out_buf, _CERT_FULL_MAX_LEN,
        ctypes.byref(written),
    )
    if rc != 0:
        raise CertRequestError("couldn't assemble the Deputy certificate", code=rc)
    return out_buf.raw[:written.value]


def root_self_cert_review_fields(subject_vk: bytes, chain_kind: ChainKind, not_before: int, not_after: int, serial: bytes) -> list[ReviewField]:
    """ The no-blind-signing field list for the Root self-certification
        review screen (Gate-1 plan §4 item 7). No "Issuing Root" fields --
        this artifact is self-signed, so there is no separate issuer to
        show. Per the plan's §8 (revised after adversarial review): the
        displayed subject key id must be checked by the operator against a
        previously recorded enrollment value, not merely displayed
        informationally -- this is the compensating control the plan ships
        in place of a compiled-in pin allowlist (§5.1). """
    return [
        ReviewField(label="Subject key id", value=root_id(subject_vk.hex())),
        ReviewField(label="Chain", value=chain_kind.name.lower()),
        ReviewField(label="Valid from", value=_format_timestamp(not_before)),
        ReviewField(label="Valid until", value=_format_timestamp(not_after)),
        ReviewField(label="Serial", value=serial.hex()),
    ]
