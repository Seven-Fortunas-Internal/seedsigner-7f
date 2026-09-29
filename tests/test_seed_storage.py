"""
    Tests seedsigner.models.seed_storage.SeedStorage's pending-seed
    fingerprint-commitment gate -- added for the encrypted seed-file
    backup's restore flow (7f-signing-support-encrypted-seed-file-backup).

    Moved here rather than kept as a per-view check (the original plan) after
    three independent plan-stage adversarial reviews converged on the same
    finding: a check bolted onto individual Views is fragile (a future
    third caller of finalize_pending_seed() could skip it silently; the
    plan's own two-guarded-call-site design still had gaps in the reused
    passphrase-entry views' exit paths). Tying the expected fingerprint to
    the pending seed's own lifecycle in SeedStorage itself makes every
    caller -- present and future -- fail closed automatically.
"""
import pytest

from seedsigner.models.seed import Seed
from seedsigner.models.seed_storage import PendingSeedFingerprintMismatchError, SeedStorage
from seedsigner.models.settings import SettingsConstants


def _seed(passphrase: str = "") -> Seed:
    return Seed(mnemonic=["abandon"] * 11 + ["about"], passphrase=passphrase, wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)


class TestSetAndClearPendingSeed:
    def test_set_pending_seed_defaults_to_no_fingerprint_gate(self):
        storage = SeedStorage()
        storage.set_pending_seed(_seed())
        assert storage.pending_seed_fingerprint_matches() is True


    def test_clear_pending_seed_also_clears_the_fingerprint_gate(self):
        storage = SeedStorage()
        seed = _seed()
        storage.set_pending_seed(seed, expected_fingerprint="not-the-real-fingerprint")
        storage.clear_pending_seed()
        storage.set_pending_seed(seed)  # a later, unrelated set with no gate
        assert storage.pending_seed_fingerprint_matches() is True


    def test_convert_pending_mnemonic_to_pending_seed_has_no_fingerprint_gate(self):
        storage = SeedStorage()
        storage.set_pending_seed(_seed(), expected_fingerprint="stale-value-from-a-different-flow")
        storage.init_pending_mnemonic(num_words=12)
        for i, word in enumerate(["abandon"] * 11 + ["about"]):
            storage.update_pending_mnemonic(word, i)
        storage.convert_pending_mnemonic_to_pending_seed()
        assert storage.pending_seed_fingerprint_matches() is True


class TestPendingSeedFingerprintMatches:
    def test_matches_when_no_gate_was_set(self):
        storage = SeedStorage()
        storage.set_pending_seed(_seed())
        assert storage.pending_seed_fingerprint_matches() is True


    def test_matches_the_real_effective_fingerprint(self):
        from seedsigner.models import seed_storage as seed_storage_module
        storage = SeedStorage()
        seed = _seed()
        real_fingerprint = seed.get_fingerprint(network=seed_storage_module.FINGERPRINT_NETWORK)
        storage.set_pending_seed(seed, expected_fingerprint=real_fingerprint)
        assert storage.pending_seed_fingerprint_matches() is True


    def test_does_not_match_a_wrong_fingerprint(self):
        storage = SeedStorage()
        storage.set_pending_seed(_seed(), expected_fingerprint="0" * 8)
        assert storage.pending_seed_fingerprint_matches() is False


    def test_a_passphrase_changes_whether_it_matches(self):
        """ The whole point of the gate: restoring a backup that recorded
            'this seed had a passphrase' and then finalizing WITHOUT
            re-entering it must be caught -- the effective fingerprint
            (passphrase applied) differs from the naked one. """
        from seedsigner.models import seed_storage as seed_storage_module
        storage = SeedStorage()
        seed_with_passphrase = _seed(passphrase="my passphrase")
        expected = seed_with_passphrase.get_fingerprint(network=seed_storage_module.FINGERPRINT_NETWORK)

        naked_seed = _seed()  # same words, no passphrase (yet)
        storage.set_pending_seed(naked_seed, expected_fingerprint=expected)
        assert storage.pending_seed_fingerprint_matches() is False

        naked_seed.set_passphrase("my passphrase")
        assert storage.pending_seed_fingerprint_matches() is True


class TestFinalizePendingSeedFingerprintGate:
    def test_finalizes_normally_when_no_gate_was_set(self):
        """ Every existing caller in this codebase calls set_pending_seed()
            with no expected_fingerprint -- this must behave exactly as it
            did before this feature existed. """
        storage = SeedStorage()
        seed = _seed()
        storage.set_pending_seed(seed)
        finalized = storage.finalize_pending_seed()
        assert finalized is seed
        assert seed in storage.seeds
        assert storage.get_pending_seed() is None


    def test_finalizes_normally_when_the_fingerprint_matches(self):
        from seedsigner.models import seed_storage as seed_storage_module
        storage = SeedStorage()
        seed = _seed()
        storage.set_pending_seed(seed, expected_fingerprint=seed.get_fingerprint(network=seed_storage_module.FINGERPRINT_NETWORK))
        finalized = storage.finalize_pending_seed()
        assert finalized is seed
        assert seed in storage.seeds


    def test_raises_and_does_not_finalize_on_a_fingerprint_mismatch(self):
        """ Fail-closed: this is the core property three separate
            adversarial reviews required -- a caller CANNOT accidentally
            finalize a restored seed whose fingerprint doesn't match what
            the backup recorded, regardless of which UI path got here. """
        storage = SeedStorage()
        seed = _seed()
        storage.set_pending_seed(seed, expected_fingerprint="0" * 8)
        with pytest.raises(PendingSeedFingerprintMismatchError):
            storage.finalize_pending_seed()
        # Must NOT have been finalized.
        assert seed not in storage.seeds
        assert storage.get_pending_seed() is seed


    def test_the_gate_is_one_shot_after_a_successful_finalize(self):
        from seedsigner.models import seed_storage as seed_storage_module
        storage = SeedStorage()
        seed = _seed()
        storage.set_pending_seed(seed, expected_fingerprint=seed.get_fingerprint(network=seed_storage_module.FINGERPRINT_NETWORK))
        storage.finalize_pending_seed()

        # A later, totally unrelated seed must never be checked against a
        # stale gate left over from this finalize.
        another_seed = Seed(mnemonic="baby mass dust captain baby mass dust captain baby mass dust captain "
                                      "baby mass dust captain baby mass dust captain baby mass dust cake".split())
        storage.set_pending_seed(another_seed)
        assert storage.pending_seed_fingerprint_matches() is True
