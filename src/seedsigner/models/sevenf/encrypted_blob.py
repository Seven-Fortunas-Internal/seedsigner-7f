"""
    Python ctypes bridge to firmware/mldsa7f's Argon2id + AES-256-GCM
    encrypted-blob primitive (ffi.rs's mldsa7f_blob_encrypt/mldsa7f_blob_decrypt,
    backed by src/encrypted_blob.rs). Used by the encrypted seed-file
    backup (requirements doc section 5.7, models/seed_backup.py) -- see
    that module for the higher-level flow; this module is just the
    primitive.

    A SeedSigner-only format, frozen: it mirrors no 7fchain format, and a
    backup is restored on a SeedSigner. The envelope JSON (version,
    algorithm, argon2_salt, argon2_memory_kb, argon2_iterations, aes_nonce,
    ciphertext) must not change, so every backup ever written stays
    readable; the pinned reference vector in the tests holds it.
"""
import ctypes

from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf._ffi import FfiCallFailed, MlDsa7fError, call_into_buffer, register_argtypes

# Must match firmware/mldsa7f/src/ffi.rs's ENCRYPTED_BLOB_MAX_LEN exactly --
# display/sizing-only here (the FFI call itself fails loudly with a
# buffer-too-small error rather than silently truncating either way).
_ENCRYPTED_BLOB_MAX_LEN = 4096


class EncryptedBlobError(MlDsa7fError):
    """ Raised for any non-zero return from the encrypted-blob FFI
        functions. `code` is the exact ERR_* constant from
        firmware/mldsa7f/src/ffi.rs -- in particular, a wrong passphrase and
        a corrupted/tampered envelope are indistinguishable by design
        (AES-GCM's whole point), both surfacing as this same error. """
    def __init__(self, code: int, operation: str):
        self.code = code
        self.operation = operation
        super().__init__(f"mldsa7f encrypted-blob {operation} failed with code {code}")


_ENCRYPTED_BLOB_ARGTYPES = {
    "mldsa7f_blob_encrypt": ([
        ctypes.c_char_p, ctypes.c_size_t,      # plaintext
        ctypes.c_char_p, ctypes.c_size_t,      # passphrase
        ctypes.c_char_p, ctypes.c_size_t,      # out
        ctypes.POINTER(ctypes.c_size_t),       # out_written
    ], ctypes.c_int32),
    "mldsa7f_blob_decrypt": ([
        ctypes.c_char_p, ctypes.c_size_t,      # envelope_json
        ctypes.c_char_p, ctypes.c_size_t,      # passphrase
        ctypes.c_char_p, ctypes.c_size_t,      # out
        ctypes.POINTER(ctypes.c_size_t),       # out_written
    ], ctypes.c_int32),
}


def _lib():
    lib = mldsa._lib_handle()
    register_argtypes(lib, "_sevenf_encrypted_blob_argtypes_registered", _ENCRYPTED_BLOB_ARGTYPES)
    return lib


def encrypt(plaintext: bytes, passphrase: bytes) -> str:
    """ Encrypt `plaintext` under `passphrase`, returning the envelope as a
        JSON string. Raises EncryptedBlobError on any failure. """
    lib = _lib()
    try:
        out = call_into_buffer(
            lib.mldsa7f_blob_encrypt,
            plaintext, len(plaintext),
            passphrase, len(passphrase),
            cap=_ENCRYPTED_BLOB_MAX_LEN,
        )
    except FfiCallFailed as e:
        raise EncryptedBlobError(e.code, "encrypt") from e
    return out.decode("utf-8")


def decrypt(envelope_json: str, passphrase: bytes) -> bytes:
    """ Decrypt an envelope produced by encrypt() under `passphrase`, returning the plaintext bytes. Raises
        EncryptedBlobError on any failure (wrong passphrase, corrupt/
        tampered envelope, or malformed JSON) -- never returns garbage. """
    lib = _lib()
    envelope_bytes = envelope_json.encode("utf-8")
    try:
        return call_into_buffer(
            lib.mldsa7f_blob_decrypt,
            envelope_bytes, len(envelope_bytes),
            passphrase, len(passphrase),
            cap=_ENCRYPTED_BLOB_MAX_LEN,
        )
    except FfiCallFailed as e:
        raise EncryptedBlobError(e.code, "decrypt") from e
