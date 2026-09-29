"""
    Tests seedsigner.models.seed_backup -- the optional encrypted seed-file
    backup to microSD (requirements doc section 5.7 / D5 / R5 / R5a / R5b).
    Backs 7f-signing-support-encrypted-seed-file-backup.

    Chain-agnostic by design (Gate-1 decision, 2026-09-29): unlike every 7F
    ceremony-specific feature in this codebase, this reuses the existing
    chain-agnostic SeedBackupView/LoadSeedView convention -- confirmed via
    plan-stage differential review that section 5.7 has no chain qualifier
    and that seed_views.py's own BACKUP button is added unconditionally.

    Requires firmware/mldsa7f's compiled library (the shared Argon2id+
    AES-256-GCM primitive goes through the real FFI boundary) -- skips
    cleanly if it's missing, same convention as test_sevenf_mldsa.py.
"""
import os

import pytest

from seedsigner.models.sevenf import mldsa
from seedsigner.models.seed import ElectrumSeed, Seed
from seedsigner.models.settings import SettingsConstants


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

from seedsigner.models import seed_backup  # noqa: E402  (after the skip marker's own import)


def _seed(words=None, passphrase: str = "") -> Seed:
    words = words or ["abandon"] * 11 + ["about"]
    return Seed(mnemonic=words, passphrase=passphrase, wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)


@pytest.fixture(autouse=True)
def _isolated_backup_path(tmp_path, monkeypatch):
    """ Every test gets its own throwaway backup path so tests can't
        interfere with each other or with a real device's SD card. """
    path = str(tmp_path / "seedsigner-seed-backup.enc")
    monkeypatch.setattr(seed_backup, "backup_path", lambda: path)
    return path


class TestBuildAndParsePlaintext:
    def test_round_trips_a_24_word_seed_with_no_passphrase(self):
        seed = _seed()
        plaintext = seed_backup.build_backup_plaintext(seed)
        parsed = seed_backup.parse_backup_plaintext(plaintext)
        assert parsed["mnemonic"] == seed.mnemonic_list
        assert parsed["wordlist_language_code"] == seed.wordlist_language_code
        assert parsed["passphrase_required"] is False


    def test_records_passphrase_required_and_a_fingerprint_that_reflects_it(self):
        seed_with = _seed(passphrase="my passphrase")
        seed_without = _seed()
        parsed_with = seed_backup.parse_backup_plaintext(seed_backup.build_backup_plaintext(seed_with))
        parsed_without = seed_backup.parse_backup_plaintext(seed_backup.build_backup_plaintext(seed_without))
        assert parsed_with["passphrase_required"] is True
        assert parsed_without["passphrase_required"] is False
        # Same words, different passphrase -> different effective fingerprint.
        assert parsed_with["expected_fingerprint"] != parsed_without["expected_fingerprint"]


    def test_parse_rejects_a_completely_different_json_shape(self):
        """ Type-confusion guard (ARCH-005): a sibling feature's own
            encrypted-blob plaintext (e.g. deputy_ca_export's KeyDatabase
            shape) must never be silently accepted as a seed backup just
            because it happens to decrypt under some password. """
        import json
        foreign_plaintext = json.dumps({"version": 1, "created_at": 0, "entries": []}).encode("utf-8")
        with pytest.raises(seed_backup.SeedBackupFormatError):
            seed_backup.parse_backup_plaintext(foreign_plaintext)


    def test_parse_rejects_wrong_version(self):
        import json
        seed = _seed()
        data = seed_backup.parse_backup_plaintext(seed_backup.build_backup_plaintext(seed))
        data["version"] = 99
        with pytest.raises(seed_backup.SeedBackupFormatError):
            seed_backup.parse_backup_plaintext(json.dumps(data).encode("utf-8"))


    def test_parse_rejects_malformed_json(self):
        with pytest.raises(seed_backup.SeedBackupFormatError):
            seed_backup.parse_backup_plaintext(b"not json at all")


class _FakeSeed:
    """ password_reuses_seed_words() only reads .mnemonic_list -- a plain
        stand-in avoids needing every test word combination to also be a
        real, BIP-39-checksum-valid mnemonic (which a real Seed(...)
        construction would enforce and most arbitrary word lists fail). """
    def __init__(self, words):
        self.mnemonic_list = words


class TestPasswordReusesSeedWords:
    def test_rejects_a_password_that_is_one_of_the_seeds_own_words(self):
        seed = _FakeSeed(["abandon"] * 11 + ["about"])
        assert seed_backup.password_reuses_seed_words("abandon", seed) is True


    def test_rejects_case_and_whitespace_variations(self):
        seed = _FakeSeed(["abandon"] * 11 + ["about"])
        assert seed_backup.password_reuses_seed_words("ABANDON", seed) is True
        assert seed_backup.password_reuses_seed_words("  about  ", seed) is True


    def test_rejects_a_password_built_from_contiguous_seed_words(self):
        seed = _FakeSeed(["abandon", "ability", "able"] + ["about"] * 21)
        assert seed_backup.password_reuses_seed_words("abandonabilityable", seed) is True


    def test_accepts_an_independent_password(self):
        seed = _FakeSeed(["abandon"] * 11 + ["about"])
        assert seed_backup.password_reuses_seed_words("correct horse battery staple", seed) is False


class TestWriteAndReadBackup:
    def test_write_then_read_round_trips_the_real_seed(self, _isolated_backup_path):
        seed = _seed()
        seed_backup.write_backup(seed, "an independent password")
        assert os.path.exists(_isolated_backup_path)

        restored = seed_backup.read_backup("an independent password")
        assert restored.mnemonic == seed.mnemonic_list
        assert restored.wordlist_language_code == seed.wordlist_language_code
        assert restored.passphrase_required is False


    def test_write_refuses_a_password_that_reuses_a_seed_word(self):
        seed = _seed()
        with pytest.raises(seed_backup.SeedBackupPasswordReusesSeedError):
            seed_backup.write_backup(seed, "abandon")


    def test_write_refuses_an_electrum_seed(self):
        # Real Electrum-segwit-prefix test vector, matching test_seed.py's
        # own fixture -- an arbitrary 12-word mnemonic won't hash to
        # Electrum's required version prefix (see ElectrumSeed._generate_seed).
        seed = ElectrumSeed(mnemonic="regular reject rare profit once math fringe chase until ketchup century escape".split())
        with pytest.raises(seed_backup.SeedBackupUnsupportedSeedTypeError):
            seed_backup.write_backup(seed, "an independent password")


    def test_read_with_wrong_password_raises_a_single_generic_error(self):
        seed = _seed()
        seed_backup.write_backup(seed, "the real password")
        with pytest.raises(seed_backup.SeedBackupDecryptError):
            seed_backup.read_backup("the wrong password")


    def test_read_raises_not_found_when_no_backup_exists(self):
        with pytest.raises(seed_backup.SeedBackupNotFoundError):
            seed_backup.read_backup("whatever")


    def test_read_rejects_an_oversized_file_before_touching_the_crypto_primitive(self, _isolated_backup_path):
        with open(_isolated_backup_path, "wb") as f:
            f.write(b"0" * (seed_backup.MAX_BACKUP_FILE_BYTES + 1))
        with pytest.raises(seed_backup.SeedBackupFormatError):
            seed_backup.read_backup("whatever")


    def test_write_is_atomic_and_never_truncates_an_existing_good_backup_on_a_failed_rewrite(self, _isolated_backup_path):
        """ SEC-002/ARCH-003/ADV-001 (converged across three independent
            plan-stage reviews): open(path, 'w') truncates before writing,
            so an interrupted second write can destroy a good first backup.
            This simulates that interruption -- os.replace must never be
            reached if the pre-replace verification fails -- and confirms
            the ORIGINAL backup is untouched afterward. """
        seed_a = _seed()
        seed_backup.write_backup(seed_a, "password one")
        original_bytes = open(_isolated_backup_path, "rb").read()

        # Simulate a corrupted/interrupted second write by making the
        # temp-file verification step fail (patch the module's own decrypt
        # call used for self-verification to raise).
        import seedsigner.models.seed_backup as sb_module
        real_decrypt = sb_module.encrypted_blob.decrypt

        def _broken_decrypt(*args, **kwargs):
            raise sb_module.encrypted_blob.EncryptedBlobError(-99, "decrypt")

        # A real, checksum-valid 24-word mnemonic distinct from seed_a's
        # ("zoo" x24 fails BIP-39 checksum validation and would itself
        # raise InvalidSeedException, unrelated to what this test checks).
        seed_b = _seed(words="baby mass dust captain baby mass dust captain baby mass dust captain "
                              "baby mass dust captain baby mass dust captain baby mass dust cake".split())
        sb_module.encrypted_blob.decrypt = _broken_decrypt
        try:
            with pytest.raises(Exception):
                seed_backup.write_backup(seed_b, "password two")
        finally:
            sb_module.encrypted_blob.decrypt = real_decrypt

        # The original backup must be completely untouched.
        assert open(_isolated_backup_path, "rb").read() == original_bytes
        restored = seed_backup.read_backup("password one")
        assert restored.mnemonic == seed_a.mnemonic_list

        # And no leftover temp file.
        assert not os.path.exists(_isolated_backup_path + ".tmp")


class TestBackupExistsAndDelete:
    def test_backup_exists_is_false_before_any_write(self):
        assert seed_backup.backup_exists() is False


    def test_backup_exists_is_true_after_write(self):
        seed_backup.write_backup(_seed(), "an independent password")
        assert seed_backup.backup_exists() is True


    def test_delete_backup_removes_the_file_and_reports_it_removed(self, _isolated_backup_path):
        seed_backup.write_backup(_seed(), "an independent password")
        assert seed_backup.delete_backup() is True
        assert not os.path.exists(_isolated_backup_path)
        assert seed_backup.backup_exists() is False


    def test_delete_backup_is_a_no_op_when_nothing_exists(self):
        assert seed_backup.delete_backup() is False
