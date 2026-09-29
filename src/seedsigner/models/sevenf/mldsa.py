"""
    Python ctypes bridge to firmware/mldsa7f's C ABI (src/ffi.rs).
    derive_pubkey/derive_and_sign match docs/7f-integration/README.md's
    original "no raw-secret-key API" design.

    derive_purpose_seed is ONE deliberate, narrow exception, added for the
    Root-to-Deputy child-seed handoff (`m/deputy-ca/l1/<chain_kind>/0`,
    confirmed against 7fchain's real `sf-root export`/`sf-deputy init`) --
    see that function's own docstring and ffi.rs's matching "One deliberate,
    narrow exception" doc comment. No other caller should use it for
    anything else, and its result must be encrypted (see
    seedsigner.models.sevenf.encrypted_blob) before it ever leaves the
    device.

    The compiled library search order:
      1. SEEDSIGNER_MLDSA7F_LIB env var, an explicit path override (tests/dev).
      2. resources/lib/libmldsa7f.so next to this package (the eventual
         packaged location, per docs/7f-integration/README.md's Packaging
         section -- doesn't exist yet as of this story; production
         packaging is separate, not-yet-filed work).
      3. firmware/mldsa7f/target/{release,debug}/libmldsa7f.{so,dylib}
         relative to this repo checkout -- a dev-only convenience so this
         module works against a local `cargo build` without a packaging
         step, since production packaging doesn't exist yet.
"""
import ctypes
import os
from pathlib import Path

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
            ctypes.c_char_p, ctypes.c_size_t,   # purpose_path
            ctypes.c_char_p, ctypes.c_size_t,   # role_path
            ctypes.c_uint8, ctypes.c_uint8,      # network, layer
            ctypes.c_char_p, ctypes.c_size_t,   # pk_out
            ctypes.c_char_p, ctypes.c_size_t,   # address_out
            ctypes.POINTER(ctypes.c_size_t),     # address_written_out
        ]
        lib.mldsa7f_derive_pubkey.restype = ctypes.c_int32

        lib.mldsa7f_derive_and_sign.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,   # master_seed64
            ctypes.c_char_p, ctypes.c_size_t,   # purpose_path
            ctypes.c_char_p, ctypes.c_size_t,   # role_path
            ctypes.c_char_p, ctypes.c_size_t,   # msg
            ctypes.c_char_p, ctypes.c_size_t,   # pk_out
            ctypes.c_char_p, ctypes.c_size_t,   # sig_out
        ]
        lib.mldsa7f_derive_and_sign.restype = ctypes.c_int32

        lib.mldsa7f_derive_purpose_seed.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,   # master_seed64
            ctypes.c_char_p, ctypes.c_size_t,   # purpose_path
            ctypes.c_char_p, ctypes.c_size_t,   # out
        ]
        lib.mldsa7f_derive_purpose_seed.restype = ctypes.c_int32
        _lib = lib
    return _lib


def derive_pubkey(master_seed: bytes, purpose_path: str, role_path: str, network: int, layer: int) -> tuple[bytes, str]:
    """ Derive the ML-DSA-65 public key and 7fchain address for
        (purpose_path, role_path) on the given network/layer. Raises
        MlDsaError on any failure. """
    if len(master_seed) != MASTER_SEED_LEN:
        raise ValueError(f"master_seed must be {MASTER_SEED_LEN} bytes, got {len(master_seed)}")

    lib = _lib_handle()
    pk_buf = ctypes.create_string_buffer(ML_DSA_PK_LEN)
    addr_buf = ctypes.create_string_buffer(ADDRESS_LEN)
    written = ctypes.c_size_t(0)

    purpose_bytes = purpose_path.encode("utf-8")
    role_bytes = role_path.encode("utf-8")

    rc = lib.mldsa7f_derive_pubkey(
        master_seed, len(master_seed),
        purpose_bytes, len(purpose_bytes),
        role_bytes, len(role_bytes),
        network, layer,
        pk_buf, ML_DSA_PK_LEN,
        addr_buf, ADDRESS_LEN,
        ctypes.byref(written),
    )
    if rc != 0:
        raise MlDsaError(rc, "derive_pubkey")

    address = addr_buf.raw[:written.value].decode("ascii")
    return pk_buf.raw[:ML_DSA_PK_LEN], address


def derive_and_sign(master_seed: bytes, purpose_path: str, role_path: str, message: bytes) -> tuple[bytes, bytes]:
    """ Derive the ML-DSA-65 keypair for (purpose_path, role_path) and sign
        `message` with it under the empty FIPS 204 context (the default
        hedged/randomized path -- matches sf-root sign-genesis). Raises
        MlDsaError on any failure. """
    if len(master_seed) != MASTER_SEED_LEN:
        raise ValueError(f"master_seed must be {MASTER_SEED_LEN} bytes, got {len(master_seed)}")

    lib = _lib_handle()
    pk_buf = ctypes.create_string_buffer(ML_DSA_PK_LEN)
    sig_buf = ctypes.create_string_buffer(ML_DSA_SIG_LEN)

    purpose_bytes = purpose_path.encode("utf-8")
    role_bytes = role_path.encode("utf-8")

    rc = lib.mldsa7f_derive_and_sign(
        master_seed, len(master_seed),
        purpose_bytes, len(purpose_bytes),
        role_bytes, len(role_bytes),
        message, len(message),
        pk_buf, ML_DSA_PK_LEN,
        sig_buf, ML_DSA_SIG_LEN,
    )
    if rc != 0:
        raise MlDsaError(rc, "derive_and_sign")

    return pk_buf.raw[:ML_DSA_PK_LEN], sig_buf.raw[:ML_DSA_SIG_LEN]


def derive_purpose_seed(master_seed: bytes, purpose_path: str) -> bytes:
    """ Derive the raw purpose seed for `purpose_path` from the master seed.

        THE ONE RAW-SECRET-EXPORTING FUNCTION IN THIS MODULE -- see this
        module's own docstring and ffi.rs's matching doc comment for why
        this is a deliberate, narrow, sanctioned exception (D4a: exporting a
        derived LEAF seed is permitted, the master seed itself never is),
        scoped specifically to the Root-to-Deputy child-seed handoff.

        The caller MUST encrypt the result (see
        seedsigner.models.sevenf.encrypted_blob.encrypt()) before it leaves
        the device by any means -- this function returns plaintext secret
        material and does no encryption itself. Raises MlDsaError on any
        failure. """
    if len(master_seed) != MASTER_SEED_LEN:
        raise ValueError(f"master_seed must be {MASTER_SEED_LEN} bytes, got {len(master_seed)}")

    lib = _lib_handle()
    out_buf = ctypes.create_string_buffer(MASTER_SEED_LEN)
    purpose_bytes = purpose_path.encode("utf-8")

    rc = lib.mldsa7f_derive_purpose_seed(
        master_seed, len(master_seed),
        purpose_bytes, len(purpose_bytes),
        out_buf, MASTER_SEED_LEN,
    )
    if rc != 0:
        raise MlDsaError(rc, "derive_purpose_seed")

    return out_buf.raw[:MASTER_SEED_LEN]
