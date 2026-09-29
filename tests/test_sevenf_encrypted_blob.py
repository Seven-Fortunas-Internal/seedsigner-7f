"""
    Tests seedsigner.models.sevenf.encrypted_blob -- the ctypes bridge to
    firmware/mldsa7f's Argon2id + AES-256-GCM encrypted-blob primitive.
    Backs 7f-signing-support-encrypted-blob-primitive.

    Requires firmware/mldsa7f's compiled library (see test_sevenf_mldsa.py's
    own docstring for the search order); skips cleanly if it's missing.
"""
import pytest

from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf.encrypted_blob import EncryptedBlobError, decrypt, encrypt


def _lib_available() -> bool:
    try:
        mldsa._lib_handle()
        return True
    except FileNotFoundError:
        return False


pytestmark = pytest.mark.skipif(
    not _lib_available(),
    reason="firmware/mldsa7f not built -- run `cargo build --release` in firmware/mldsa7f/ first",
)

# Real reference vector extracted directly from 7fchain's own
# KeyDatabase::save_encrypted/load_encrypted (crates/sf-keytree/src/database.rs),
# via a temporary #[test] added and immediately reverted in that checkout --
# encrypts a KeyDatabase JSON containing one entry:
# path="m/deputy-ca/l1/testnet/0", seed_hex="ab"*64, under the 11-byte
# passphrase below. Same vector firmware/mldsa7f's own encrypted_blob.rs and
# ffi.rs test modules pin.
REFERENCE_PASSPHRASE = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b])
REFERENCE_ENVELOPE = """{
  "version": 1,
  "algorithm": "argon2id-aes256gcm",
  "argon2_salt": "48f38b4d5e940d3795b7b3db7e35c59063f4fccf45eb0ef2ea2852ad5dfc7c7a",
  "argon2_memory_kb": 65536,
  "argon2_iterations": 3,
  "aes_nonce": "8d3285ed2d45378ec9529d49",
  "ciphertext": "9fcbd553d12ce78a57adcb65e1327a6fc9d9268b0aa06e22b94b39788bbab103a3cba00e32117e21f68c6a1fe42b8f50d986f1890bf84a50dd2f53a04de24ec64d9b8484583a0ce8ce77048020ef65e725d962032571b299fa7fa86e300c1b4f475a558a18eed2d9fe697d2ef340c6cf685e2fb84c10612212e23a6b0ca8f64ed0b23a35d24baf9c26b17fee7e877a0eb950fe22c68a52666ba63adb1a6bd115d9e0a8e428c0548ad7d63b73df5fb5e5772f1f23478c8f69a58c62c84f63a00ac81c9a6c6a0ac9ef6695b4b6654c53b74f2157e03eb016a690bfdef75d16c9240155b134a85a01ecaf279fa2fc2e600b7328949acfcf2fd776e6984edd8ad561d077e76c90f406953884138de1f1c33075a12c51b528199e317ab5fe76"
}"""


def test_decrypts_the_real_reference_vector_from_7fchain():
    import json
    plaintext = decrypt(REFERENCE_ENVELOPE, REFERENCE_PASSPHRASE)
    doc = json.loads(plaintext)
    assert doc["entries"][0]["path"] == "m/deputy-ca/l1/testnet/0"
    assert doc["entries"][0]["seed_hex"] == "ab" * 64
    assert doc["entries"][0]["status"] == "active"


def test_decrypt_rejects_the_reference_vector_under_the_wrong_passphrase():
    with pytest.raises(EncryptedBlobError):
        decrypt(REFERENCE_ENVELOPE, bytes([0xff]) * 11)


def test_round_trips_through_encrypt_then_decrypt():
    plaintext = b'{"hello":"world"}'
    passphrase = b"a test passphrase, arbitrary length"
    envelope = encrypt(plaintext, passphrase)
    assert decrypt(envelope, passphrase) == plaintext


def test_round_trip_rejects_the_wrong_passphrase():
    envelope = encrypt(b"secret", b"correct passphrase")
    with pytest.raises(EncryptedBlobError):
        decrypt(envelope, b"wrong passphrase")


def test_two_encryptions_of_the_same_plaintext_use_different_salt_and_nonce():
    a = encrypt(b"same plaintext", b"same passphrase")
    b = encrypt(b"same plaintext", b"same passphrase")
    assert a != b


def test_envelope_is_valid_json_with_the_expected_fields():
    import json
    envelope = encrypt(b"secret", b"a passphrase")
    doc = json.loads(envelope)
    assert doc["version"] == 1
    assert doc["algorithm"] == "argon2id-aes256gcm"
    assert doc["argon2_memory_kb"] == 65536
    assert doc["argon2_iterations"] == 3
    assert len(bytes.fromhex(doc["argon2_salt"])) == 32
    assert len(bytes.fromhex(doc["aes_nonce"])) == 12


def test_decrypt_rejects_a_tampered_ciphertext():
    import json
    envelope = encrypt(b"secret", b"a passphrase")
    doc = json.loads(envelope)
    ct = bytearray(bytes.fromhex(doc["ciphertext"]))
    ct[0] ^= 0xFF
    doc["ciphertext"] = ct.hex()
    with pytest.raises(EncryptedBlobError):
        decrypt(json.dumps(doc), b"a passphrase")


def test_decrypt_rejects_malformed_json():
    with pytest.raises(EncryptedBlobError):
        decrypt("not json at all", b"whatever")


def test_encrypt_handles_a_realistic_small_plaintext():
    """ The actual shape this primitive's real callers produce: a small
        KeyDatabase-style JSON document, well within ENCRYPTED_BLOB_MAX_LEN. """
    import json
    plaintext = json.dumps({
        "version": 1,
        "created_at": 1_790_000_000,
        "entries": [{
            "path": "m/deputy-ca/l1/testnet/0",
            "seed_hex": "ab" * 64,
            "created_at": 1_790_000_000,
            "status": "active",
        }],
    }).encode("utf-8")
    passphrase = bytes(range(11))
    envelope = encrypt(plaintext, passphrase)
    assert decrypt(envelope, passphrase) == plaintext
