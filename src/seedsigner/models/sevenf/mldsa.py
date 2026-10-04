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

    Every path this module hands to the FFI is validated against
    `path_lexicon.validate()` first (added in the same adversarial-review
    pass that removed the above) -- this is the actual boundary every real
    and future Python caller on this device passes through, closing the gap
    flagged against firmware/mldsa7f/src/derive.rs's own `derive_seed`,
    which deliberately does not validate (see that function's doc comment
    and 7f-signing-support-path-validation-not-enforced).

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
from seedsigner.models.sevenf.constants import (
    ADDRESS_LEN,
    ML_DSA_PK_LEN,
    ML_DSA_SIG_LEN,
    MASTER_SEED_LEN,
)


class MlDsaError(Exception):
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


def _lib_handle() -> ctypes.CDLL:
    """ Lazy singleton -- avoids loading the shared library at import time
        (which would make every test that imports this module, even ones
        unrelated to 7F, require the compiled artifact to exist). """
    global _lib
    if _lib is None:
        lib = _load_library()
        lib.mldsa7f_derive_pubkey.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,   # master_seed64
            ctypes.c_char_p, ctypes.c_size_t,   # path
            ctypes.c_uint8, ctypes.c_uint8,      # network, layer
            ctypes.c_char_p, ctypes.c_size_t,   # pk_out
            ctypes.c_char_p, ctypes.c_size_t,   # address_out
            ctypes.POINTER(ctypes.c_size_t),     # address_written_out
        ]
        lib.mldsa7f_derive_pubkey.restype = ctypes.c_int32

        lib.mldsa7f_derive_and_sign.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,   # master_seed64
            ctypes.c_char_p, ctypes.c_size_t,   # path
            ctypes.c_char_p, ctypes.c_size_t,   # msg
            ctypes.c_char_p, ctypes.c_size_t,   # pk_out
            ctypes.c_char_p, ctypes.c_size_t,   # sig_out
        ]
        lib.mldsa7f_derive_and_sign.restype = ctypes.c_int32
        _lib = lib
    return _lib


def derive_pubkey(master_seed: bytes, path: str, network: int, layer: int) -> tuple[bytes, str]:
    """ Derive the ML-DSA-65 public key and 7fchain address for `path` on
        the given network/layer. Raises MlDsaError on any failure, or
        path_lexicon.PathLexiconError if `path` fails lexicon validation
        (added 2026-10-03, adversarial review -- see this module's own
        docstring). """
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
        network, layer,
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
        under the empty FIPS 204 context (the default hedged/randomized
        path -- matches sf-root sign-genesis). Raises MlDsaError on any
        failure, or path_lexicon.PathLexiconError if `path` fails lexicon
        validation (added 2026-10-03, adversarial review -- see this
        module's own docstring). """
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
