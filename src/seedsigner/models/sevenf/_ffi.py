"""
    Shared ctypes-bridge infrastructure for firmware/mldsa7f's C ABI
    (src/ffi.rs), used by mldsa.py, cert_request.py, devfund_config.py,
    genesis_config.py, and encrypted_blob.py.

    CONSOLIDATED 2026-10-05 (7f-review-ctypes-bridge-consolidation, found
    by the full-project adversarial review's Python-quality and modularity
    dimensions): those 5 modules had drifted into inconsistent conventions
    for the same three things --

    1. ARGTYPES REGISTRATION: mldsa.py registered eagerly inside its own
       _lib_handle(); the other four each rolled their own
       "_sevenf_*_argtypes_registered" hasattr-marker guard. `register_
       argtypes()` below is the one implementation all five now share,
       keeping each module's own marker attribute name (nothing downstream
       inspects these, confirmed by grep, but keeping the same names is
       free and avoids an unforced change).

    2. ERROR CLASSES: 5 classes (MlDsaError, GenesisConfigError,
       DevFundConfigError, EncryptedBlobError, CertRequestError) had no
       shared ancestor, so `except <any 7F FFI error>:` wasn't expressible
       in one clause. `MlDsa7fError` below is that shared base. Deliberately
       NOT unifying their constructor shapes: CertRequestError's
       `(message, code=None)` differs from the other four's `(code,
       operation)`, and at least one caller outside this package constructs
       it with that exact shape (tests/test_sevenf_views.py). Reshaping it
       would be a breaking API change across 19+ importing files for a
       cosmetic inconsistency the story itself only flagged as "confusing,"
       not incorrect -- each subclass keeps its own exact `__init__`
       unchanged, now just rooted under one common ancestor.

    3. BUFFER SIZING: ~10 of this package's ~15 FFI entry points share one
       exact shape -- the real work's leading arguments, then a caller-
       sized `(out: c_char_p, out_len: c_size_t)` pair, then a trailing
       `out_written: POINTER(c_size_t)` -- and every one of those 10 call
       sites repeated the same "allocate buffer, call, check rc, slice to
       written length" triple verbatim. `call_into_buffer()` below is that
       shared triple. Functions with a different shape (a fixed-length
       output with no out_written at all, or several scalar out-params
       mixed with one variable one) call their FFI function directly
       instead -- forcing those into the same helper would obscure more
       than it saves.

    `ErrCode` mirrors every ERR_* constant in firmware/mldsa7f/src/ffi.rs
    (confirmed against that live file 2026-10-05), replacing the two
    near-identical `_ERR_CODE_NAMES` dicts that previously lived in
    cert_request.py and devfund_config.py with one source. Not every FFI
    function can return every code -- each domain module still keeps its
    own notion of which codes are reachable from its own calls and which of
    those mean "internal device bug" vs "artifact problem"; that
    differentiation is domain-specific and stays where it is.
"""
import ctypes
from enum import IntEnum


class ErrCode(IntEnum):
    """ Mirrors firmware/mldsa7f/src/ffi.rs's ERR_* constants exactly. """
    NULL_POINTER = -1
    BAD_MASTER_SEED_LEN = -2
    BAD_PATH_UTF8 = -3
    BAD_NETWORK = -4
    BAD_LAYER = -5
    PK_BUFFER_TOO_SMALL = -6
    ADDRESS_BUFFER_TOO_SMALL = -7
    SIGNATURE_BUFFER_TOO_SMALL = -8
    DERIVATION_FAILED = -9
    ADDRESS_ENCODING_FAILED = -10
    SIGNING_FAILED = -11
    BAD_CHAIN_KIND = -12
    BAD_MESSAGE_UTF8 = -13
    OUTPUT_BUFFER_TOO_SMALL = -14
    MESSAGE_BUFFER_TOO_SMALL = -15
    PARSE_FAILED = -16
    CERT_BUILD_FAILED = -17
    ENCRYPT_FAILED = -18
    DECRYPT_FAILED = -19
    BAD_UTF8 = -20
    SEED_BUFFER_TOO_SMALL = -21
    PANIC = -22
    CSR_VERIFY_FAILED = -23
    CERT_PARSE_FAILED = -24
    BAD_RECIPIENT_TAG = -25
    BAD_ADDRESS = -26
    BAD_PATH = -27
    SIGNATURE_SELF_CHECK_FAILED = -28
    CSR_POLICY = -29


def err_code_name(code: int) -> str:
    """ "ERR_WHATEVER" for a recognized code, or the bare code itself
        (stringified) for one this enum doesn't know about -- an unknown
        code is itself informative (it means this Python layer is stale
        against a newer ffi.rs), so it's shown rather than hidden. """
    try:
        return f"ERR_{ErrCode(code).name}"
    except ValueError:
        return str(code)


class MlDsa7fError(Exception):
    """ Shared ancestor for every exception this package's ctypes bridges
        raise on a non-zero return from firmware/mldsa7f's C ABI. See this
        module's own docstring for why subclasses keep their own exact
        constructor shapes rather than being unified here. """
    # Type hints only, no defaults -- every subclass sets these itself in
    # its own __init__ (and CertRequestError's `operation` stays unset,
    # by design, since its shape never had one).
    code: int | None
    operation: str | None


def register_argtypes(lib: ctypes.CDLL, marker: str, specs: dict) -> None:
    """ Idempotent per-CDLL argtypes/restype registration, guarded by a
        hasattr marker on the shared library object (a ctypes CDLL has no
        query of its own for "have I already configured this symbol").
        `specs` maps an exported symbol name to (argtypes_list, restype).
        Raises AttributeError, uncaught, if a symbol isn't exported by this
        build of the library -- callers whose symbols are conditionally
        compiled in (e.g. cert_request.py's test-tooling-gated CSR
        builders) catch that themselves, same as before this helper
        existed. """
    if hasattr(lib, marker):
        return
    for name, (argtypes, restype) in specs.items():
        fn = getattr(lib, name)
        fn.argtypes = argtypes
        fn.restype = restype
    setattr(lib, marker, True)


class FfiCallFailed(Exception):
    """ Internal signal only, raised by call_into_buffer() and always
        caught immediately by its caller, which re-raises its own
        domain-specific error (MlDsaError/GenesisConfigError/etc, each with
        its own message). Never escapes a public function in this
        package. """
    def __init__(self, code: int):
        self.code = code


def call_into_buffer(fn, *args, cap: int) -> bytes:
    """ Calls an FFI function shaped `fn(*args, out: c_char_p, out_len:
        c_size_t, out_written: POINTER(c_size_t)) -> c_int32`: allocates a
        `cap`-byte output buffer, makes the call, and returns exactly the
        bytes written on success. Raises FfiCallFailed(rc) on any non-zero
        return -- the caller's own `except FfiCallFailed as e:` is where
        `e.code` becomes that module's own error type with its own
        message. """
    out_buf = ctypes.create_string_buffer(cap)
    written = ctypes.c_size_t(0)
    rc = fn(*args, out_buf, cap, ctypes.byref(written))
    if rc != 0:
        raise FfiCallFailed(rc)
    return out_buf.raw[:written.value]
