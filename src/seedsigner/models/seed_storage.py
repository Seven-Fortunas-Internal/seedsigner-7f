from typing import List
from seedsigner.models.seed import Seed, ElectrumSeed, InvalidSeedException
from seedsigner.models.settings_definition import SettingsConstants

# Fixed, internal-only network choice for the pending-seed fingerprint
# commitment (see set_pending_seed()/pending_seed_fingerprint_matches()
# below) -- exposed here, not in seedsigner.models.seed_backup, so that
# module depends on this one for the constant rather than the other way
# around (SeedStorage is a core model; it must not import a specific
# feature's module). Fixed rather than settings-driven so a fingerprint
# computed when the gate was set and one computed when it's checked are
# always comparable regardless of what network setting is active at either
# moment.
FINGERPRINT_NETWORK = SettingsConstants.MAINNET


class PendingSeedFingerprintMismatchError(Exception):
    """ Raised by finalize_pending_seed() when the pending seed's effective
        fingerprint doesn't match the expected_fingerprint it was set with
        (see set_pending_seed()). Added for the encrypted seed-file
        backup's restore flow (7f-signing-support-encrypted-seed-file-backup):
        a backup never stores the seed's optional BIP-39 passphrase, only a
        commitment to what the fingerprint should be once the right
        passphrase is re-entered -- this is the fail-closed enforcement of
        that commitment, living here (not in any individual View) so that
        EVERY current and future caller of finalize_pending_seed() is
        automatically protected, not just the ones a plan remembered to
        instrument by hand (found by three independent plan-stage
        adversarial reviews to be the fragile part of the original,
        View-level-guard design). """


class SeedStorage:
    def __init__(self) -> None:
        self.seeds: List[Seed] = []
        self.pending_seed: Seed = None
        self._pending_seed_expected_fingerprint: str = None
        self._pending_mnemonic: List[str] = []
        self._pending_is_electrum : bool = False


    def set_pending_seed(self, seed: Seed, expected_fingerprint: str = None):
        """ `expected_fingerprint`, when given, arms the fingerprint-
            commitment gate: finalize_pending_seed() will refuse to
            finalize `seed` unless its effective fingerprint (computed
            against FINGERPRINT_NETWORK, passphrase applied) matches. Every
            caller that doesn't pass it (i.e. every pre-existing caller in
            this codebase) gets no gate at all, exactly as before this
            parameter existed. """
        self.pending_seed = seed
        self._pending_seed_expected_fingerprint = expected_fingerprint


    def get_pending_seed(self) -> Seed:
        return self.pending_seed


    def pending_seed_fingerprint_matches(self) -> bool:
        """ True if no gate is armed (nothing to check), or if the pending
            seed's current effective fingerprint matches the expected one
            it was armed with. Fingerprints aren't secret (already shown
            on-screen elsewhere), so a plain comparison is fine. """
        if self._pending_seed_expected_fingerprint is None:
            return True
        return self.pending_seed.get_fingerprint(network=FINGERPRINT_NETWORK) == self._pending_seed_expected_fingerprint


    def finalize_pending_seed(self) -> Seed:
        if not self.pending_seed_fingerprint_matches():
            raise PendingSeedFingerprintMismatchError(
                "pending seed's fingerprint doesn't match the expected commitment; refusing to finalize")

        # Store the pending seed and return it
        seed = self.pending_seed
        if seed not in self.seeds:
            self.seeds.append(seed)
        self.pending_seed = None
        self._pending_seed_expected_fingerprint = None
        return seed


    def clear_pending_seed(self):
        self.pending_seed = None
        self._pending_seed_expected_fingerprint = None


    def wipe(self):
        """ Drop every seed and every pending phrase (the network tripwire).
            Python cannot overwrite str/bytes in place, so this removes the
            references; powering off is what clears the memory. """
        self.seeds.clear()
        self.clear_pending_seed()
        self._pending_mnemonic.clear()
        self._pending_is_electrum = False


    def validate_mnemonic(self, mnemonic: List[str]) -> bool:
        try:
            Seed(mnemonic=mnemonic)
        except InvalidSeedException as e:
            return False
        
        return True


    def num_seeds(self):
        return len(self.seeds)
    

    @property
    def pending_mnemonic(self) -> List[str]:
        # Always return a copy so that the internal List can't be altered
        return list(self._pending_mnemonic)


    @property
    def pending_mnemonic_length(self) -> int:
        return len(self._pending_mnemonic)


    def init_pending_mnemonic(self, num_words:int = 12, is_electrum:bool = False):
        self._pending_mnemonic = [None] * num_words
        self._pending_is_electrum = is_electrum


    def update_pending_mnemonic(self, word: str, index: int):
        """
        Replaces the nth word in the pending mnemonic.

        * may specify a negative `index` (e.g. -1 is the last word).
        """
        if index >= len(self._pending_mnemonic):
            raise Exception(f"index {index} is too high")
        self._pending_mnemonic[index] = word
    

    def get_pending_mnemonic_word(self, index: int) -> str:
        if index < len(self._pending_mnemonic):
            return self._pending_mnemonic[index]
        return None
    

    def get_pending_mnemonic_fingerprint(self, network: str = SettingsConstants.MAINNET) -> str:
        try:
            if self._pending_is_electrum:
                seed = ElectrumSeed(self._pending_mnemonic)
            else:
                seed = Seed(self._pending_mnemonic)
            return seed.get_fingerprint(network)
        except InvalidSeedException:
            return None


    def convert_pending_mnemonic_to_pending_seed(self):
        if self._pending_is_electrum:
            self.pending_seed = ElectrumSeed(self._pending_mnemonic)
        else:
            self.pending_seed = Seed(self._pending_mnemonic)
        self._pending_seed_expected_fingerprint = None
        self.discard_pending_mnemonic()
    

    def discard_pending_mnemonic(self):
        self._pending_mnemonic = []
        self._pending_is_electrum = False
