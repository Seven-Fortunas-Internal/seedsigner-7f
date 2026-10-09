"""
    Python ctypes bridge to firmware/mldsa7f's C ABI (src/ffi.rs). No entry
    point returns secret material: only public keys, addresses and
    signatures.

    Paths are checked by 7fchain's own rules inside the library (the verbatim
    port of sf-keytree's path.rs), and a key is derived from its path exactly
    as written, as sf-keytree's keypair_at does; the network and layer of an
    address come from the path itself. derive_pubkey/derive_and_sign check the
    path first only so a caller gets 7fchain's message (PathLexiconError)
    rather than a bare code. Every signature is verified under its own key
    before it is returned (as sf-wallet-gov's sign_checked). The path API
    callers use is path_lexicon.py.

    The compiled library search order:
      1. SEEDSIGNER_MLDSA7F_LIB env var, an explicit path override (tests/dev).
      2. resources/lib/libmldsa7f.so next to this package (the packaged
         location; production packaging is
         7f-signing-support-buildroot-packaging in _delivery/backlog.yaml).
      3. firmware/mldsa7f/target/{release,debug}/libmldsa7f.{so,dylib}
         relative to this repo checkout, for a local `cargo build`.
    Whichever loads must report EXPECTED_ABI_VERSION.
"""
import ctypes
import os
from pathlib import Path

from seedsigner.models.sevenf._ffi import ErrCode, MlDsa7fError, err_code_name, register_argtypes
from seedsigner.models.sevenf.constants import (
    ADDRESS_LEN,
    ML_DSA_PK_LEN,
    ML_DSA_SIG_LEN,
    MASTER_SEED_LEN,
    key_index_segment,
)


class MlDsaError(MlDsa7fError):
    """ Raised for any non-zero return from the mldsa7f C ABI. `code` is
        the exact ERR_* constant from firmware/mldsa7f/src/ffi.rs, so a
        caller (or a test) can distinguish failure modes precisely rather
        than getting one generic exception. """
    def __init__(self, code: int, operation: str):
        self.code = code
        self.operation = operation
        super().__init__(f"mldsa7f {operation} failed: {err_code_name(code)} ({code})")


class PathLexiconError(Exception):
    """ A path 7fchain's rules refuse; the message is 7fchain's. """


def _candidate_lib_paths() -> list[Path]:
    candidates = []
    env_override = os.environ.get("SEEDSIGNER_MLDSA7F_LIB")
    if env_override:
        candidates.append(Path(env_override))

    package_dir = Path(__file__).resolve().parent
    # models/sevenf/ -> models/ -> seedsigner/ -> src/ -> seedsigner-7f/
    resources_lib = package_dir.parent.parent / "resources" / "lib"
    candidates.append(resources_lib / "libmldsa7f.so")

    # Dev convenience: .../firmware/seedsigner-7f/src/seedsigner/models/sevenf/
    # -> up 4 to .../firmware/, then into mldsa7f/target/*.
    firmware_dir = package_dir.parents[4]
    for profile in ("release", "debug"):
        target_dir = firmware_dir / "mldsa7f" / "target" / profile
        candidates.append(target_dir / "libmldsa7f.so")
        candidates.append(target_dir / "libmldsa7f.dylib")

    return candidates


def _load_library() -> ctypes.CDLL:
    tried = []
    for path in _candidate_lib_paths():
        tried.append(str(path))
        if path.is_file():
            return ctypes.CDLL(str(path))
    raise FileNotFoundError(
        "mldsa7f shared library not found. Tried:\n  " + "\n  ".join(tried) +
        "\nBuild it with `cargo build --release` in firmware/mldsa7f/, or set "
        "SEEDSIGNER_MLDSA7F_LIB to an explicit path."
    )


_lib = None

_MLDSA_ARGTYPES = {
    "mldsa7f_derive_pubkey": ([
        ctypes.c_char_p, ctypes.c_size_t,   # master_seed64
        ctypes.c_char_p, ctypes.c_size_t,   # path
        ctypes.c_char_p, ctypes.c_size_t,   # pk_out
        ctypes.c_char_p, ctypes.c_size_t,   # address_out
        ctypes.POINTER(ctypes.c_size_t),     # address_written_out
    ], ctypes.c_int32),
    "mldsa7f_path_validate": ([
        ctypes.c_char_p, ctypes.c_size_t,   # path
        ctypes.c_char_p, ctypes.c_size_t,   # msg_out
        ctypes.POINTER(ctypes.c_size_t),     # msg_written_out
    ], ctypes.c_int32),
    "mldsa7f_path_for": ([
        ctypes.c_char_p, ctypes.c_size_t,   # role
        ctypes.c_uint8, ctypes.c_uint32,     # chain_kind, index
        ctypes.c_char_p, ctypes.c_size_t,   # out
        ctypes.POINTER(ctypes.c_size_t),     # out_written
    ], ctypes.c_int32),
    "mldsa7f_derive_and_sign": ([
        ctypes.c_char_p, ctypes.c_size_t,   # master_seed64
        ctypes.c_char_p, ctypes.c_size_t,   # path
        ctypes.c_char_p, ctypes.c_size_t,   # msg
        ctypes.c_char_p, ctypes.c_size_t,   # pk_out
        ctypes.c_char_p, ctypes.c_size_t,   # sig_out
    ], ctypes.c_int32),
}


def _lib_handle() -> ctypes.CDLL:
    """ Lazy singleton -- avoids loading the shared library at import time
        (which would make every test that imports this module, even ones
        unrelated to 7F, require the compiled artifact to exist). """
    global _lib
    if _lib is None:
        lib = _load_library()
        _check_abi(lib)
        register_argtypes(lib, "_sevenf_mldsa_argtypes_registered", _MLDSA_ARGTYPES)
        _lib = lib
    return _lib


# The C ABI this bridge is written for (firmware/mldsa7f/src/ffi.rs ABI_VERSION).
EXPECTED_ABI_VERSION = 2


def _check_abi(lib) -> None:
    """ Refuse a library built for another ABI (for example one copied to the
        device separately from this code), rather than call it with the wrong
        arguments. """
    try:
        fn = lib.mldsa7f_abi_version
    except AttributeError:
        raise MlDsa7fError(f"the mldsa7f library predates ABI versioning; this code needs ABI {EXPECTED_ABI_VERSION}. "
                           "Install the library built from this tree.") from None
    fn.argtypes = []
    fn.restype = ctypes.c_uint32
    version = fn()
    if version != EXPECTED_ABI_VERSION:
        raise MlDsa7fError(f"the mldsa7f library is ABI {version}; this code needs ABI {EXPECTED_ABI_VERSION}. "
                           "Install the library built from this tree.")


# Room for a path, or for 7fchain's message about one.
_PATH_TEXT_MAX = 512


def path_refusal(path: str) -> str | None:
    """ None if 7fchain's path rules accept `path`, else 7fchain's message. """
    lib = _lib_handle()
    path_bytes = path.encode("utf-8")
    msg_buf = ctypes.create_string_buffer(_PATH_TEXT_MAX)
    written = ctypes.c_size_t(0)
    rc = lib.mldsa7f_path_validate(path_bytes, len(path_bytes), msg_buf, _PATH_TEXT_MAX, ctypes.byref(written))
    if rc == 0:
        return None
    if rc == ErrCode.BAD_PATH:
        return msg_buf.raw[:min(written.value, _PATH_TEXT_MAX)].decode("utf-8", errors="replace")
    if rc == ErrCode.BAD_PATH_UTF8:
        return "derivation path is not valid UTF-8"
    raise MlDsaError(rc, "path_validate")


def _refuse_bad_path(path: str) -> None:
    refusal = path_refusal(path)
    if refusal is not None:
        raise PathLexiconError(refusal)


def path_for(role: str, chain_kind: int, index: int) -> str:
    """ The derivation path for `role` on `chain_kind` at `index`, built by
        7fchain's own path_for (the verbatim port in firmware/mldsa7f).
        Raises TypeError/ValueError for an index that is not a u32 (ctypes
        would wrap it). """
    key_index_segment(index)
    lib = _lib_handle()
    role_bytes = role.encode("utf-8")
    out = ctypes.create_string_buffer(_PATH_TEXT_MAX)
    written = ctypes.c_size_t(0)
    rc = lib.mldsa7f_path_for(role_bytes, len(role_bytes), int(chain_kind), index, out, _PATH_TEXT_MAX, ctypes.byref(written))
    if rc != 0:
        raise MlDsaError(rc, "path_for")
    return out.raw[:written.value].decode("ascii")


def derive_pubkey(master_seed: bytes, path: str) -> tuple[bytes, str]:
    """ Derive the ML-DSA-65 public key and 7fchain address for `path`; the
        address is on the path's own network and layer. Raises
        PathLexiconError (7fchain's message) for a path its rules refuse,
        MlDsaError on any other failure. """
    if len(master_seed) != MASTER_SEED_LEN:
        raise ValueError(f"master_seed must be {MASTER_SEED_LEN} bytes, got {len(master_seed)}")
    _refuse_bad_path(path)

    lib = _lib_handle()
    pk_buf = ctypes.create_string_buffer(ML_DSA_PK_LEN)
    addr_buf = ctypes.create_string_buffer(ADDRESS_LEN)
    written = ctypes.c_size_t(0)

    path_bytes = path.encode("utf-8")

    rc = lib.mldsa7f_derive_pubkey(
        master_seed, len(master_seed),
        path_bytes, len(path_bytes),
        pk_buf, ML_DSA_PK_LEN,
        addr_buf, ADDRESS_LEN,
        ctypes.byref(written),
    )
    if rc != 0:
        raise MlDsaError(rc, "derive_pubkey")

    # Belt-and-suspenders: addr_buf is exactly ADDRESS_LEN bytes, so the FFI
    # contract already bounds `written`, but a slice with a garbage/over-
    # long value would silently return truncated or wrong-looking address
    # bytes instead of failing loudly -- not exploitable from the Python
    # side alone (the buffer itself can't be overrun), but worth asserting
    # explicitly rather than trusting the FFI's own bound silently.
    if not 0 <= written.value <= ADDRESS_LEN:
        raise ValueError(f"derive_pubkey returned an out-of-range address length: {written.value}")

    address = addr_buf.raw[:written.value].decode("ascii")
    return pk_buf.raw[:ML_DSA_PK_LEN], address


def derive_and_sign(master_seed: bytes, path: str, message: bytes) -> tuple[bytes, bytes]:
    """ Derive the ML-DSA-65 keypair for `path` and sign `message` with it
        under the empty FIPS 204 context, hedged, as sf-wallet-gov's
        sign_checked does (sign_ops.rs); the signature is verified under its
        key before it is returned. Raises PathLexiconError (7fchain's
        message) for a refused path, MlDsaError otherwise. """
    if len(master_seed) != MASTER_SEED_LEN:
        raise ValueError(f"master_seed must be {MASTER_SEED_LEN} bytes, got {len(master_seed)}")
    _refuse_bad_path(path)

    lib = _lib_handle()
    pk_buf = ctypes.create_string_buffer(ML_DSA_PK_LEN)
    sig_buf = ctypes.create_string_buffer(ML_DSA_SIG_LEN)

    path_bytes = path.encode("utf-8")

    rc = lib.mldsa7f_derive_and_sign(
        master_seed, len(master_seed),
        path_bytes, len(path_bytes),
        message, len(message),
        pk_buf, ML_DSA_PK_LEN,
        sig_buf, ML_DSA_SIG_LEN,
    )
    if rc != 0:
        raise MlDsaError(rc, "derive_and_sign")

    return pk_buf.raw[:ML_DSA_PK_LEN], sig_buf.raw[:ML_DSA_SIG_LEN]
