"""
    Python ctypes bridge to firmware/mldsa7f's C ABI (src/ffi.rs).
    derive_pubkey/derive_and_sign match docs/7f-integration/README.md's
    original "no raw-secret-key API" design.

    RE-PORTED 2026-10-03 (R27): collapsed from the old `(purpose_path,
    role_path)` two-path signature to a single combined `path`, matching
    7fchain's own single-grammar derivation rewrite -- see
    firmware/mldsa7f/src/derive.rs's doc comment for why the two-level
    split retired, and path_lexicon.py for this device's own path-building
    layer under the new grammar.

    REMOVED 2026-10-03 (adversarial review of the R27 re-port):
    `derive_seed_raw`/`mldsa7f_derive_seed_raw`, the one function on this
    FFI surface that ever returned raw secret seed material. Its sole
    purpose was the Root-to-Deputy child-seed handoff (the sole caller,
    `deputy_ca_export.py`), which is retired on 7fchain's side (C8:
    the Deputy derives its own key on its own holder's own airgap instead;
    the `KeyDatabase` format that caller targeted was deleted, M-8). With
    no live purpose and no live caller, the raw-secret-export primitive was
    removed rather than kept around as dead attack surface -- see
    7f-signing-support-deputy-seed-export-obsolete in _delivery/backlog.yaml
    for the decision record. "No raw-secret-key API" is now simply true of
    this module, not true-with-one-exception.

    Paths are checked by 7fchain's own rules inside the library: derivation
    parses the path with the verbatim port of sf-keytree's path.rs and refuses
    an invalid one, and the network and layer of an address come from the path
    itself. derive_pubkey/derive_and_sign call path_lexicon.validate() first
    only so a caller gets 7fchain's message rather than a bare error code.
    Every signature is verified under its own key before it is returned
    (as sf-wallet-gov's sign_checked).

    The compiled library search order:
      1. SEEDSIGNER_MLDSA7F_LIB env var, an explicit path override (tests/dev).
      2. resources/lib/libmldsa7f.so next to this package (the eventual
         packaged location -- doesn't exist yet; production packaging is
         tracked separately as 7f-signing-support-buildroot-packaging in
         _delivery/backlog.yaml, see docs/7f-integration/README.md's
         "What's built" table for current status).
      3. firmware/mldsa7f/target/{release,debug}/libmldsa7f.{so,dylib}
         relative to this repo checkout -- a dev-only convenience so this
         module works against a local `cargo build` without a packaging
         step, since production packaging doesn't exist yet.
"""
import ctypes
import os
from pathlib import Path

from seedsigner.models.sevenf import path_lexicon
from seedsigner.models.sevenf._ffi import MlDsa7fError, register_argtypes
from seedsigner.models.sevenf.constants import (
    ADDRESS_LEN,
    ML_DSA_PK_LEN,
    ML_DSA_SIG_LEN,
    MASTER_SEED_LEN,
)


class MlDsaError(MlDsa7fError):
    """ Raised for any non-zero return from the mldsa7f C ABI. `code` is
        the exact ERR_* constant from firmware/mldsa7f/src/ffi.rs, so a
        caller (or a test) can distinguish failure modes precisely rather
        than getting one generic exception. """
    def __init__(self, code: int, operation: str):
        self.code = code
        self.operation = operation
        super().__init__(f"mldsa7f {operation} failed with code {code}")


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
    try:
        fn.argtypes = []
        fn.restype = ctypes.c_uint32
    except AttributeError:
        pass
    version = fn()
    if version != EXPECTED_ABI_VERSION:
        raise MlDsa7fError(f"the mldsa7f library is ABI {version}; this code needs ABI {EXPECTED_ABI_VERSION}. "
                           "Install the library built from this tree.")


_PATH_MESSAGE_MAX = 512
ERR_BAD_PATH_UTF8 = -3
ERR_BAD_PATH = -27


def path_refusal(path: str) -> str | None:
    """ None if 7fchain's path rules accept `path`, else 7fchain's message. """
    lib = _lib_handle()
    path_bytes = path.encode("utf-8")
    msg_buf = ctypes.create_string_buffer(_PATH_MESSAGE_MAX)
    written = ctypes.c_size_t(0)
    rc = lib.mldsa7f_path_validate(path_bytes, len(path_bytes), msg_buf, _PATH_MESSAGE_MAX, ctypes.byref(written))
    if rc == 0:
        return None
    if rc == ERR_BAD_PATH:
        return msg_buf.raw[:min(written.value, _PATH_MESSAGE_MAX)].decode("utf-8", errors="replace")
    if rc == ERR_BAD_PATH_UTF8:
        return "derivation path is not valid UTF-8"
    raise MlDsaError(rc, "path_validate")


def derive_pubkey(master_seed: bytes, path: str) -> tuple[bytes, str]:
    """ Derive the ML-DSA-65 public key and 7fchain address for `path`; the
        address is on the path's own network and layer. Raises
        path_lexicon.PathLexiconError (7fchain's message) for a path its rules
        refuse, MlDsaError on any other failure. """
    if len(master_seed) != MASTER_SEED_LEN:
        raise ValueError(f"master_seed must be {MASTER_SEED_LEN} bytes, got {len(master_seed)}")
    path_lexicon.validate(path)

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
        key before it is returned. Raises path_lexicon.PathLexiconError
        (7fchain's message) for a refused path, MlDsaError otherwise. """
    if len(master_seed) != MASTER_SEED_LEN:
        raise ValueError(f"master_seed must be {MASTER_SEED_LEN} bytes, got {len(master_seed)}")
    path_lexicon.validate(path)

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
