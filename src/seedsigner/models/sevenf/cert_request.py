"""
    Python ctypes bridge to firmware/mldsa7f's X.509 Root self-
    certification and Deputy cross-certification TBS-building, assembly,
    and CSR verification/building functions (ffi.rs's cert-related entry
    points, backed by src/cert_request.rs) -- the actual crypto-adjacent,
    byte-precise work, which IS Rust, per D12. Two generations of the
    Deputy flow coexisted in this module's own history; only the PKCS#10
    one described below is current.

    TRIMMED 2026-10-04 (7f-review-dead-json-certrequest-code, found by the
    full-project adversarial review's modularity dimension): this module
    used to also carry ~185 dead lines parsing/validating the RETIRED JSON
    CertRequest wire envelope (`parse_cert_request_json`/
    `CertRequestFields`/`root_tbs_from_request`/`subject_matches`/
    `review_fields`/`ROLE_ROOT`/`ROLE_DEPUTY`/`CERT_REQUEST_VERSION`) --
    kept alive only by ~40 dead-code-only references in this module's own
    test file, with zero callers anywhere in the view layer (confirmed by
    grep at the time, and the deletion that followed). "CertRequest" (the
    retired JSON envelope this module is named for) no longer describes
    what this module actually does -- renaming it (e.g. x509_cert.py, or
    splitting into root_cert.py/deputy_cert.py) is a bigger, separately-
    scoped decision this story deliberately left undone; see
    7f-review-dead-json-certrequest-code's own closure note in
    _delivery/backlog.yaml for why.

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
    docs/7f-integration/archive/root-self-cert-pkcs10-rework-plan.md §3 for the full
    finding (filed as its own bug, `7f-signing-support-detached-sig-
    export-unreconstructable`, since it also affects the Deputy flow above).
    `assemble_root_cert_der`/`root_self_cert_review_fields` below implement
    the fix for this artifact: assemble a complete X.509 `Certificate`
    on-device and export THAT, not a detached signature.
"""
import ctypes
import secrets
from dataclasses import dataclass

from seedsigner.models.review import ReviewField
from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf._ffi import ErrCode, FfiCallFailed, MlDsa7fError, call_into_buffer, err_code_name, register_argtypes
from seedsigner.models.sevenf.constants import ML_DSA_PK_LEN, ML_DSA_SIG_LEN, ChainKind
from seedsigner.models.sevenf.review_format import group_hex_for_display, format_timestamp as _format_timestamp, ski

# Must match firmware/mldsa7f/src/ffi.rs's CERT_TBS_MAX_LEN exactly --
# display/sizing-only here (the FFI call itself fails loudly with a
# buffer-too-small error rather than silently truncating either way).
_CERT_TBS_MAX_LEN = 4096


class CertRequestError(MlDsa7fError):
    """ Raised for any non-zero return from the cert-request FFI functions
        (`code` is then the exact ERR_* constant from
        firmware/mldsa7f/src/ffi.rs). """
    def __init__(self, message: str, code: int | None = None):
        self.code = code
        super().__init__(message)


# Codes this module's own FFI calls can actually return and that mean
# "this device has an internal bug" rather than "this artifact has a
# problem" -- not every ErrCode member, just the ones reachable here.
_INTERNAL_ERROR_CODES = (ErrCode.NULL_POINTER, ErrCode.OUTPUT_BUFFER_TOO_SMALL)

# Codes this module's own FFI calls can actually return, period -- the
# shared err_code_name() knows every ERR_* constant in ffi.rs, but this
# module's pre-consolidation behavior only ever named the handful below,
# falling back to the bare number for anything else (adversarial review,
# 2026-10-05: widening the lookup to the full shared enum silently changed
# message text for out-of-contract codes -- this clamp restores that).
_KNOWN_CODES = frozenset({
    ErrCode.NULL_POINTER, ErrCode.BAD_CHAIN_KIND, ErrCode.OUTPUT_BUFFER_TOO_SMALL,
    ErrCode.PARSE_FAILED, ErrCode.CERT_BUILD_FAILED, ErrCode.CSR_VERIFY_FAILED, ErrCode.CERT_PARSE_FAILED,
})


def _code_name(code: int) -> str:
    return err_code_name(code) if code in _KNOWN_CODES else str(code)


def _raise_cert_error(rc: int, artifact_causes: str) -> None:
    """ 7f-review-parse-failure-messages-not-actionable (2026-10-04, found
        by the full-project adversarial review's UI/UX dimension): these
        raise sites used to show the same generic text ("couldn't parse
        the Root certificate") regardless of the actual FFI return code,
        unlike genesis_config.py's own GenesisConfigJsonError, which gives
        specific field-level reasons. True single-cause differentiation
        (one message per root cause, not a list of plausible ones) would
        need either an FFI error-message buffer or more granular Rust-side
        codes for the handful of these FFI functions that currently
        collapse every internal failure into one code -- bigger,
        FFI-contract-level work appropriately left to
        7f-review-ctypes-bridge-consolidation's own planned ErrCode enum,
        not attempted here. This is the honest improvement achievable from
        the code alone: distinguishing "this device has an internal bug"
        (NULL_POINTER/OUTPUT_BUFFER_TOO_SMALL) from "this artifact has a
        problem," and for the latter, naming the actual plausible causes
        (`artifact_causes`, grounded in the relevant cert_request.rs
        function's own doc comment) instead of a bare code number. The
        caller's own message (e.g. "couldn't parse the Root certificate")
        is supplied by the view layer that catches this, not repeated
        here, to avoid "couldn't X: couldn't X" doubling. """
    if rc in _INTERNAL_ERROR_CODES:
        raise CertRequestError(f"internal device error ({_code_name(rc)}); please report this", code=rc)
    raise CertRequestError(f"{_code_name(rc)}: {artifact_causes}", code=rc)


_CERT_REQUEST_ARGTYPES = {
    "mldsa7f_cert_root_tbs": ([
        ctypes.c_char_p, ctypes.c_size_t,      # subject_vk
        ctypes.c_uint8,                        # chain_kind
        ctypes.c_uint64, ctypes.c_uint64,      # not_before, days
        ctypes.c_char_p, ctypes.c_size_t,      # serial
        ctypes.c_char_p, ctypes.c_size_t,      # out
        ctypes.POINTER(ctypes.c_size_t),       # out_written
    ], ctypes.c_int32),
    "mldsa7f_cert_parse_root": ([
        ctypes.c_char_p, ctypes.c_size_t,      # cert_der
        ctypes.c_char_p, ctypes.c_size_t,      # subject_vk_out
        ctypes.POINTER(ctypes.c_uint64),       # not_before_out
        ctypes.POINTER(ctypes.c_uint64),       # not_after_out
        ctypes.POINTER(ctypes.c_uint8),        # chain_kind_out
    ], ctypes.c_int32),
    "mldsa7f_cert_verify_csr": ([
        ctypes.c_char_p, ctypes.c_size_t,      # csr_der
        ctypes.c_char_p, ctypes.c_size_t,      # subject_vk_out
    ], ctypes.c_int32),
    "mldsa7f_cert_deputy_tbs_v2": ([
        ctypes.c_char_p, ctypes.c_size_t,      # root_cert_der
        ctypes.c_char_p, ctypes.c_size_t,      # deputy_csr_der
        ctypes.c_uint8,                        # chain_kind
        ctypes.c_uint64, ctypes.c_uint64,      # now, days
        ctypes.c_char_p, ctypes.c_size_t,      # serial
        ctypes.c_char_p, ctypes.c_size_t,      # out
        ctypes.POINTER(ctypes.c_size_t),       # out_written
    ], ctypes.c_int32),
    "mldsa7f_cert_assemble_root": ([
        ctypes.c_char_p, ctypes.c_size_t,      # tbs_der
        ctypes.c_char_p, ctypes.c_size_t,      # signature
        ctypes.c_char_p, ctypes.c_size_t,      # subject_vk
        ctypes.c_char_p, ctypes.c_size_t,      # out
        ctypes.POINTER(ctypes.c_size_t),       # out_written
    ], ctypes.c_int32),
    "mldsa7f_cert_assemble_deputy": ([
        ctypes.c_char_p, ctypes.c_size_t,      # tbs_der
        ctypes.c_char_p, ctypes.c_size_t,      # signature
        ctypes.c_char_p, ctypes.c_size_t,      # root_cert_der
        ctypes.c_char_p, ctypes.c_size_t,      # out
        ctypes.POINTER(ctypes.c_size_t),       # out_written
    ], ctypes.c_int32),
}


def _lib():
    lib = mldsa._lib_handle()
    register_argtypes(lib, "_sevenf_cert_request_argtypes_registered", _CERT_REQUEST_ARGTYPES)
    return lib


def _csr_tooling_lib():
    """ Separate from _lib() deliberately (7f-review-csr-tooling-ships-in-
        production-cdylib, 2026-10-04): mldsa7f_cert_build_csr_info/
        mldsa7f_cert_assemble_csr now only exist in the compiled library
        when it was built with `cargo build --release --features
        test-tooling` (see firmware/mldsa7f/src/cert_request.rs's own
        module-doc note) -- a normal `cargo build --release` (what the
        device's eventual production image will run) omits them entirely.
        Registering their argtypes inside _lib() itself would make EVERY
        cert_request.py function (not just the two CSR builders) raise an
        opaque ctypes AttributeError the moment any of them first touched
        the library, since ctypes looks up `.argtypes` by symbol name and
        fails immediately if the symbol isn't exported -- a normal device
        build would never be able to use this module at all. Kept lazy and
        separate so only csr_info_der/assemble_csr_der -- the two functions
        that actually need these symbols -- ever pay that cost, and fail
        with a clear, specific message when they do. """
    lib = mldsa._lib_handle()
    _csr_tooling_argtypes = {
        "mldsa7f_cert_build_csr_info": ([
            ctypes.c_char_p, ctypes.c_size_t,      # subject_vk
            ctypes.c_char_p, ctypes.c_size_t,      # out
            ctypes.POINTER(ctypes.c_size_t),       # out_written
        ], ctypes.c_int32),
        "mldsa7f_cert_assemble_csr": ([
            ctypes.c_char_p, ctypes.c_size_t,      # info_der
            ctypes.c_char_p, ctypes.c_size_t,      # signature
            ctypes.c_char_p, ctypes.c_size_t,      # out
            ctypes.POINTER(ctypes.c_size_t),       # out_written
        ], ctypes.c_int32),
    }
    try:
        register_argtypes(lib, "_sevenf_csr_tooling_argtypes_registered", _csr_tooling_argtypes)
    except AttributeError as e:
        raise CertRequestError(
            "This build of mldsa7f doesn't include the PKCS#10 CSR test-tooling "
            "functions. Rebuild firmware/mldsa7f with `cargo build --release "
            "--features test-tooling` to use csr_info_der/assemble_csr_der."
        ) from e
    return lib


def build_root_tbs(subject_vk: bytes, kind: ChainKind, not_before: int, days: int, serial: bytes) -> bytes:
    """ The unsigned body of a Root's own self-signed certificate -- the
        exact bytes a Root signs for enrollment. Raises CertRequestError on
        any failure. """
    lib = _lib()
    try:
        return call_into_buffer(
            lib.mldsa7f_cert_root_tbs,
            subject_vk, len(subject_vk),
            int(kind),
            not_before, days,
            serial, len(serial),
            cap=_CERT_TBS_MAX_LEN,
        )
    except FfiCallFailed as e:
        raise CertRequestError("build_root_tbs failed", code=e.code) from e


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
    # As 7fchain's shared-crypto x509 does: high bit clear (positive) and 0x40
    # set, so the first byte is never 00 and the serial shown on review is
    # exactly the one the DER INTEGER encodes.
    serial[0] = (serial[0] & 0x7F) | 0x40
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
        _raise_cert_error(rc, "it may not be a well-formed X.509 Root certificate: wrong signature "
                               "algorithm or key length, a name or key identifier that isn't the "
                               "canonical Root's, or a self-signature that doesn't verify")
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

        sf-ca's issuing-CA policy is applied in the library, in the same
        Rust path that builds the Deputy certificate: a request that asks
        for any extension is refused (an empty request and other attributes
        are fine), as sf-wallet-gov sign-deputy-cert refuses it.
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
    if rc == ErrCode.CSR_POLICY:
        raise CertRequestError("this certificate request asks for extensions (e.g. CA/path length); "
                               "a Deputy request must not -- ask the Deputy to create a fresh one")
    if rc != 0:
        _raise_cert_error(rc, "it may not be a well-formed PKCS#10 request, may use the wrong "
                               "signature algorithm, or its self-signature may not actually verify")
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
    try:
        return call_into_buffer(
            lib.mldsa7f_cert_deputy_tbs_v2,
            root_cert_der, len(root_cert_der),
            deputy_csr_der, len(deputy_csr_der),
            int(chain_kind),
            now, days,
            serial, len(serial),
            cap=_CERT_TBS_MAX_LEN,
        )
    except FfiCallFailed as e:
        rc = e.code
        # Unlike this module's other raise sites, mldsa7f_cert_deputy_tbs_v2
        # (ffi.rs) genuinely DOES distinguish which of its two scanned
        # inputs failed from the TBS-building step itself -- the three
        # branches below name the real, different cause for each of its
        # three possible failure codes, not a shared list of plausible ones.
        if rc == ErrCode.CERT_PARSE_FAILED:
            _raise_cert_error(rc, "the scanned Root certificate isn't valid (malformed, not a "
                                   "CA certificate, wrong algorithm, or wrong key length)")
        elif rc == ErrCode.CSR_VERIFY_FAILED:
            _raise_cert_error(rc, "the scanned Deputy certificate request isn't valid (malformed, "
                                   "wrong algorithm, or its self-signature doesn't verify)")
        else:
            # _raise_cert_error itself still distinguishes an internal-bug
            # code (NULL_POINTER/OUTPUT_BUFFER_TOO_SMALL) from the real
            # ERR_CERT_BUILD_FAILED case below.
            _raise_cert_error(rc, "the requested chain or validity window doesn't match the "
                                   "issuing Root certificate's own")


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
        and serial.

        "Deputy: Valid until" (added 2026-10-03,
        7f-review-deputy-cert-relative-validity-display, found by the
        full-project adversarial review's UI/UX dimension): every other
        validity window on this screen set shows an absolute date;
        "Valid for: N days" alone made the operator mentally compute the
        actual expiry under ceremony pressure. Computed with the SAME
        clamp cert_request.rs's own deputy_tbs_der_from_root_cert() applies
        when it builds the real TBS body this device signs
        (`min(now + days*DAY, root.not_after)`) -- a Deputy's requested
        window can never outlive its issuing Root's own certificate, so the
        displayed date must reflect that clamp, not a naive day-count
        projection that could overstate what's actually being signed. """
    not_after = min(now + days * 86_400, root_cert.not_after)
    return [
        ReviewField(
            label="Issuing Root: Subject key id", value=group_hex_for_display(ski(root_cert.subject_vk.hex())), is_warning=True,
            warning_detail="Compare against the subject key id the Root's holder reported.",
        ),
        ReviewField(label="Issuing Root: Valid from", value=_format_timestamp(root_cert.not_before)),
        ReviewField(label="Issuing Root: Valid until", value=_format_timestamp(root_cert.not_after)),
        ReviewField(label="Chain", value=chain_kind.name.lower()),
        ReviewField(
            label="Deputy: Subject key id", value=group_hex_for_display(ski(csr.subject_vk.hex())), is_warning=True,
            warning_detail="Compare against the subject key id the Deputy's holder reported.",
        ),
        ReviewField(label="Deputy: Valid from", value=_format_timestamp(now)),
        ReviewField(label="Deputy: Valid for", value=f"{days} days"),
        ReviewField(label="Deputy: Valid until", value=_format_timestamp(not_after)),
        ReviewField(label="Deputy: Serial", value=serial.hex()),
    ]


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
    try:
        return call_into_buffer(
            lib.mldsa7f_cert_assemble_root,
            tbs_der, len(tbs_der),
            signature, len(signature),
            subject_vk, len(subject_vk),
            cap=_CERT_FULL_MAX_LEN,
        )
    except FfiCallFailed as e:
        raise CertRequestError("couldn't assemble the Root certificate", code=e.code) from e


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
    try:
        return call_into_buffer(
            lib.mldsa7f_cert_assemble_deputy,
            tbs_der, len(tbs_der),
            signature, len(signature),
            root_cert_der, len(root_cert_der),
            cap=_CERT_FULL_MAX_LEN,
        )
    except FfiCallFailed as e:
        raise CertRequestError("couldn't assemble the Deputy certificate", code=e.code) from e


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
        ReviewField(
            label="Subject key id", value=group_hex_for_display(ski(subject_vk.hex())), is_warning=True,
            warning_detail="Compare against your recorded subject key id.",
        ),
        ReviewField(label="Chain", value=chain_kind.name.lower()),
        ReviewField(label="Valid from", value=_format_timestamp(not_before)),
        ReviewField(label="Valid until", value=_format_timestamp(not_after)),
        ReviewField(label="Serial", value=serial.hex()),
    ]


# --- PKCS#10 CSR building: test/tooling-only ---
#
# This device never builds a CSR as part of any production signing flow --
# verify_and_parse_csr_der's own docstring confirms the device only ever
# VERIFIES one; the real CSR-building happens on 7fchain's own sf-deputy
# CLI, a different tool entirely. These two functions exist solely so
# tools/make_sevenf_test_qrs.py can generate a real, self-signed PKCS#10 CSR
# for hardware testing (closes
# 7f-signing-support-hardware-test-tooling-pkcs10-staleness) instead of the
# retired JSON CertRequest{role:"deputy"} shape it used to fake. No view in
# sevenf_views.py calls either of these.

def csr_info_der(subject_vk: bytes) -> bytes:
    """ The unsigned body of a PKCS#10 CertificationRequest -- the exact
        bytes a CSR requester signs. Raises CertRequestError on any
        failure (e.g. a wrong-length subject_vk). """
    lib = _csr_tooling_lib()
    try:
        return call_into_buffer(
            lib.mldsa7f_cert_build_csr_info,
            subject_vk, len(subject_vk),
            cap=_CERT_TBS_MAX_LEN,
        )
    except FfiCallFailed as e:
        raise CertRequestError("couldn't build the CSR body", code=e.code) from e


def assemble_csr_der(info_der: bytes, signature: bytes) -> bytes:
    """ Assemble a complete, DER-encoded PKCS#10 `CertificationRequest` from
        an unsigned body (`csr_info_der`) and a signature already produced
        over it under the same key the body embeds (a CSR is always
        self-signed). Raises CertRequestError if the signature doesn't
        verify over the info under its own embedded subject key. """
    lib = _csr_tooling_lib()
    try:
        return call_into_buffer(
            lib.mldsa7f_cert_assemble_csr,
            info_der, len(info_der),
            signature, len(signature),
            cap=_CERT_FULL_MAX_LEN,
        )
    except FfiCallFailed as e:
        raise CertRequestError("couldn't assemble the CSR", code=e.code) from e
