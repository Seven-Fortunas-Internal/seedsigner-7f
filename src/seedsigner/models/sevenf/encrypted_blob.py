"""
    Python ctypes bridge to firmware/mldsa7f's Argon2id + AES-256-GCM
    encrypted-blob primitive (ffi.rs's mldsa7f_blob_encrypt/mldsa7f_blob_decrypt,
    backed by src/encrypted_blob.rs). Used by the encrypted seed-file
    backup (requirements doc section 5.7, models/seed_backup.py) -- see
    that module for the higher-level flow; this module is just the
    primitive. Previously also shared by the Root-to-Deputy child-seed
    export, removed 2026-10-03
    (7f-signing-support-deputy-seed-export-obsolete) once 7fchain's own
    ceremony design dropped that handoff; this is the only caller left.

    The envelope JSON shape (version, algorithm, argon2_salt,
    argon2_memory_kb, argon2_iterations, aes_nonce, ciphertext) is confirmed
    field-for-field against 7fchain's real crates/sf-keytree/src/database.rs
    -- an envelope this module produces is byte-for-byte interoperable with
    that real code's own KeyDatabase::load_encrypted, and vice versa.
"""
import ctypes

from seedsigner.models.sevenf import mldsa

# Must match firmware/mldsa7f/src/ffi.rs's ENCRYPTED_BLOB_MAX_LEN exactly --
# display/sizing-only here (the FFI call itself fails loudly with a
# buffer-too-small error rather than silently truncating either way).
_ENCRYPTED_BLOB_MAX_LEN = 4096


class EncryptedBlobError(Exception):
    """ Raised for any non-zero return from the encrypted-blob FFI
        functions. `code` is the exact ERR_* constant from
        firmware/mldsa7f/src/ffi.rs -- in particular, a wrong passphrase and
        a corrupted/tampered envelope are indistinguishable by design
        (AES-GCM's whole point), both surfacing as this same error. """
    def __init__(self, code: int, operation: str):
        self.code = code
        self.operation = operation
        super().__init__(f"mldsa7f encrypted-blob {operation} failed with code {code}")


def _lib():
    lib = mldsa._lib_handle()
    if not hasattr(lib, "_sevenf_encrypted_blob_argtypes_registered"):
        lib.mldsa7f_blob_encrypt.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,      # plaintext
            ctypes.c_char_p, ctypes.c_size_t,      # passphrase
            ctypes.c_char_p, ctypes.c_size_t,      # out
            ctypes.POINTER(ctypes.c_size_t),       # out_written
        ]
        lib.mldsa7f_blob_encrypt.restype = ctypes.c_int32

        lib.mldsa7f_blob_decrypt.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,      # envelope_json
            ctypes.c_char_p, ctypes.c_size_t,      # passphrase
            ctypes.c_char_p, ctypes.c_size_t,      # out
            ctypes.POINTER(ctypes.c_size_t),       # out_written
        ]
        lib.mldsa7f_blob_decrypt.restype = ctypes.c_int32
        lib._sevenf_encrypted_blob_argtypes_registered = True
    return lib


def encrypt(plaintext: bytes, passphrase: bytes) -> str:
    """ Encrypt `plaintext` under `passphrase`, returning the envelope as a
        JSON string. Raises EncryptedBlobError on any failure. """
    lib = _lib()
    out_buf = ctypes.create_string_buffer(_ENCRYPTED_BLOB_MAX_LEN)
    written = ctypes.c_size_t(0)
    rc = lib.mldsa7f_blob_encrypt(
        plaintext, len(plaintext),
        passphrase, len(passphrase),
        out_buf, _ENCRYPTED_BLOB_MAX_LEN,
        ctypes.byref(written),
    )
    if rc != 0:
        raise EncryptedBlobError(rc, "encrypt")
    return out_buf.raw[:written.value].decode("utf-8")


def decrypt(envelope_json: str, passphrase: bytes) -> bytes:
    """ Decrypt an envelope produced by encrypt() (or by 7fchain's own
        KeyDatabase::save_encrypted -- the formats are identical) under
        `passphrase`, returning the plaintext bytes. Raises
        EncryptedBlobError on any failure (wrong passphrase, corrupt/
        tampered envelope, or malformed JSON) -- never returns garbage. """
    lib = _lib()
    envelope_bytes = envelope_json.encode("utf-8")
    out_buf = ctypes.create_string_buffer(_ENCRYPTED_BLOB_MAX_LEN)
    written = ctypes.c_size_t(0)
    rc = lib.mldsa7f_blob_decrypt(
        envelope_bytes, len(envelope_bytes),
        passphrase, len(passphrase),
        out_buf, _ENCRYPTED_BLOB_MAX_LEN,
        ctypes.byref(written),
    )
    if rc != 0:
        raise EncryptedBlobError(rc, "decrypt")
    return out_buf.raw[:written.value]
