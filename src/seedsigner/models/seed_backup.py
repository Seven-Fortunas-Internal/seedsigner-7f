"""
    Optional encrypted seed-file backup to microSD (requirements doc section
    5.7 / D5 / R5 / R5a / R5b). Backs 7f-signing-support-encrypted-seed-file-backup.

    Gate-1 plan, adversarially reviewed 2026-09-29 (four parallel plan-stage
    reviews -- architecture, security, adversarial edge-case, spec-
    differential -- before any of this module's own code existed) before
    two remaining product decisions were confirmed by the operator:
      - Chain-agnostic scope: this feature lives alongside every seed
        regardless of active chain mode, matching the existing chain-
        agnostic SeedBackupView/LoadSeedView convention and section 5.7's
        own unqualified "a member"/"the seed" wording -- NOT gated on
        active_chain_id, unlike every 7F-ceremony-specific feature.
      - Passphrase handling: a seed's optional BIP-39 passphrase is never
        stored in the backup. Instead the plaintext records a
        `passphrase_required` flag and an `expected_fingerprint` (the
        seed's own EFFECTIVE fingerprint, i.e. computed with whatever
        passphrase was set at backup time). On restore, if
        passphrase_required is set, the caller MUST force passphrase entry
        and refuse to finalize unless the resulting fingerprint matches --
        this closes the "restore silently produces a different wallet"
        failure two independent reviews found in the alternative
        (warning-only) design.

    Deliberately different plaintext shape from the sibling
    deputy_ca_export.py: that module stores a derived LEAF seed's raw bytes
    (seed_hex), which is fine because that value is a ONE-WAY derivation
    never meant to become words again. This module backs up the operator's
    own master seed, and Seed.seed_bytes is itself a one-way PBKDF2-HMAC-
    SHA512 derivation from the mnemonic (models/seed.py) -- there is no
    bytes -> mnemonic inverse, so the plaintext here MUST be the mnemonic
    word list, not seed_bytes, or restoring would be permanently impossible.

    Security notes carried over from adversarial review, not decided here:
      - R5b (non-negotiable): the device never accepts a password that
        reuses any part of the seed phrase -- see
        password_reuses_seed_words(), enforced by write_backup().
      - Untrusted input: restore is the first code path in this project
        that decrypts an envelope read from removable media rather than
        one this device just produced itself. MAX_BACKUP_FILE_BYTES bounds
        what's ever read before parsing; the shared primitive
        (mldsa7f's encrypted_blob.rs) independently pins Argon2 parameters
        against a crafted envelope's inflated memory/iteration cost.
      - Atomic write: write_backup() writes to a temp file, verifies it by
        actually decrypting it back and comparing the recovered mnemonic
        word-for-word against the original, and only then atomically
        replaces the real backup path (os.replace). The real backup is
        never truncated or touched until the new one is independently
        confirmed good -- closing a data-loss failure mode three separate
        reviews converged on (SEC-002/ARCH-003/ADV-001): open(path, 'w')
        truncates before writing, so an interrupted overwrite could
        destroy a good backup and leave nothing.
      - ElectrumSeed is refused at backup time: its derivation (a
        different PBKDF2 salt/scheme, see models/seed.py's ElectrumSeed)
        isn't reconstructible through this module's plain
        Seed(mnemonic=..., passphrase=...) restore path.
      - Wrong-password vs. corrupted/tampered file are indistinguishable
        by AES-GCM design (same doctrine as encrypted_blob.py) -- restore
        callers get exactly one generic SeedBackupDecryptError, never a
        guess at which.

    NOT this module's job (left to the view layer that will call it):
      - The no-blind-persist confirmation before writing.
      - Password double-entry (typo-catching) at entry time -- this
        module's write_backup() takes a single already-confirmed password
        string; the string-compare-based typo check belongs in the UI,
        before Argon2 ever runs, not here.
      - The "empty/trivial password -- are you sure?" friction dialog
        (KeePassXC's own resolved design for this exact tension: a non-
        blocking warning with an explicit override, never a hard block --
        matches R5a's "no enforced length or composition").
      - Forcing passphrase re-entry and the fingerprint-match check on
        restore when passphrase_required is set.
"""
import json
import os
import time
import unicodedata

from seedsigner.models.seed import ElectrumSeed, Seed
from seedsigner.models.settings import Settings, SettingsConstants
from seedsigner.models.sevenf import encrypted_blob

BACKUP_TYPE = "seedsigner-encrypted-seed-backup"
BACKUP_FORMAT_VERSION = 1

# Deliberately generic, not fingerprint- or label-derived (SEC-004/ARCH-012):
# a distinctively-named file is itself a targeting signal on removable media
# that's designed to be carried, lost, or read by another device.
BACKUP_FILENAME = "seedsigner-seed-backup.enc"

# A real backup envelope is well under 1KB (mldsa7f's own ENCRYPTED_BLOB_MAX_LEN
# doc comment). Generous headroom, but bounded -- refuses an absurdly large
# file cheaply, before it's ever read into memory or parsed as JSON.
MAX_BACKUP_FILE_BYTES = 65_536

# Fixed, internal-only network choice for the fingerprint commitment
# recorded in the backup -- never shown to the operator as "the"
# fingerprint (SeedFinalizeView already shows that, computed against the
# active Settings network). Fixed rather than settings-driven so a
# fingerprint computed at backup time and one computed at restore time are
# always comparable regardless of what network setting happens to be
# active on either device at either moment.
_FINGERPRINT_NETWORK = SettingsConstants.MAINNET


class SeedBackupError(Exception):
    """ Base class for every error this module raises. """


class SeedBackupFormatError(SeedBackupError):
    """ The plaintext isn't a seedsigner-encrypted-seed-backup document (a
        different backup format, or corrupted/malformed) -- includes a
        wrong `type`/`version`, or JSON that doesn't parse at all. """


class SeedBackupPasswordReusesSeedError(SeedBackupError):
    """ R5b: the entered password reuses part of the seed phrase. """


class SeedBackupUnsupportedSeedTypeError(SeedBackupError):
    """ This seed can't be represented by this module's restore path
        (currently: ElectrumSeed, whose derivation this schema can't
        reconstruct through a plain Seed(mnemonic=..., passphrase=...)). """


class SeedBackupNotFoundError(SeedBackupError):
    """ No backup file exists at backup_path(). """


class SeedBackupDecryptError(SeedBackupError):
    """ Decryption failed -- wrong password or a corrupted/tampered file,
        deliberately indistinguishable (AES-GCM design, same doctrine as
        encrypted_blob.EncryptedBlobError). """


class RestoredBackup:
    def __init__(self, mnemonic: list, wordlist_language_code: str, passphrase_required: bool, expected_fingerprint: str):
        self.mnemonic = mnemonic
        self.wordlist_language_code = wordlist_language_code
        self.passphrase_required = passphrase_required
        self.expected_fingerprint = expected_fingerprint


def backup_path() -> str:
    """ Mirrors Settings.SETTINGS_FILENAME's own hostname-based path switch
        (models/settings.py) -- on real SeedSigner OS hardware this is the
        microSD mount point; on any other build (dev machines, CI) it's a
        local relative path, the same convention Settings already uses
        rather than pretending /mnt/microsd exists (ADV-004). """
    from seedsigner.hardware.microsd import MicroSD
    if Settings.HOSTNAME == Settings.SEEDSIGNER_OS:
        return os.path.join(MicroSD.MOUNT_POINT, BACKUP_FILENAME)
    return BACKUP_FILENAME


def backup_exists() -> bool:
    return os.path.exists(backup_path())


def delete_backup() -> bool:
    """ Removes the backup file if one exists. Returns whether a file was
        actually removed. Addresses section 5.8's rehearsal-discard intent
        ("keys discarded afterwards") -- without this, a testnet
        rehearsal's throwaway seed would otherwise persist on the card
        indefinitely if the optional backup was ever enabled for it. """
    path = backup_path()
    if not os.path.exists(path):
        return False
    os.remove(path)
    return True


def _effective_fingerprint(seed: Seed) -> str:
    return seed.get_fingerprint(network=_FINGERPRINT_NETWORK)


def password_reuses_seed_words(password: str, seed: Seed) -> bool:
    """ R5b, non-negotiable per the requirements doc: "The device never
        accepts any part of the seed phrase as the password for the
        file." Catches both a password typed as one of the seed's own
        words (matched case/whitespace-insensitively) and a password built
        by concatenating contiguous seed words with no separator (the
        exact "using the first words of the phrase as the password"
        scenario the requirements doc names). """
    normalized_password = unicodedata.normalize("NFKD", password).strip().casefold()
    if not normalized_password:
        return False

    words = [unicodedata.normalize("NFKD", w).casefold() for w in seed.mnemonic_list]

    for token in normalized_password.split():
        if token in words:
            return True

    password_no_spaces = normalized_password.replace(" ", "")
    mnemonic_no_spaces = "".join(words)
    if password_no_spaces and password_no_spaces in mnemonic_no_spaces:
        return True

    return False


def build_backup_plaintext(seed: Seed) -> bytes:
    return json.dumps({
        "type": BACKUP_TYPE,
        "version": BACKUP_FORMAT_VERSION,
        "created_at": int(time.time()),
        "mnemonic": seed.mnemonic_list,
        "wordlist_language_code": seed.wordlist_language_code,
        "passphrase_required": seed.has_passphrase,
        "expected_fingerprint": _effective_fingerprint(seed),
    }).encode("utf-8")


def parse_backup_plaintext(data: bytes) -> dict:
    """ Strict validation, refusing rather than guessing (ARCH-005): a
        sibling feature's own encrypted-blob plaintext (e.g.
        deputy_ca_export's KeyDatabase shape) must never be silently
        accepted here just because it happened to decrypt under some
        password -- the `type`/`version` check is what tells the two
        apart. """
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise SeedBackupFormatError("not a valid seed-backup document") from e

    if not isinstance(parsed, dict) or parsed.get("type") != BACKUP_TYPE:
        raise SeedBackupFormatError("not a seedsigner-encrypted-seed-backup document")
    if parsed.get("version") != BACKUP_FORMAT_VERSION:
        raise SeedBackupFormatError(f"unsupported backup format version {parsed.get('version')!r}")

    mnemonic = parsed.get("mnemonic")
    if not isinstance(mnemonic, list) or len(mnemonic) not in (12, 24) or not all(isinstance(w, str) for w in mnemonic):
        raise SeedBackupFormatError("malformed mnemonic field")
    if not isinstance(parsed.get("wordlist_language_code"), str):
        raise SeedBackupFormatError("malformed wordlist_language_code field")
    if not isinstance(parsed.get("passphrase_required"), bool):
        raise SeedBackupFormatError("malformed passphrase_required field")
    if not isinstance(parsed.get("expected_fingerprint"), str):
        raise SeedBackupFormatError("malformed expected_fingerprint field")

    return parsed


def write_backup(seed: Seed, password: str) -> None:
    """ Encrypts and writes `seed`'s full mnemonic to backup_path(), under
        `password`. Raises SeedBackupUnsupportedSeedTypeError for an
        ElectrumSeed, SeedBackupPasswordReusesSeedError per R5b, or
        SeedBackupError for any encryption/write failure. The real backup
        path is never touched until the write is verified good (see this
        module's own docstring). """
    if isinstance(seed, ElectrumSeed):
        raise SeedBackupUnsupportedSeedTypeError("Electrum seeds cannot be restored through this backup format")
    if password_reuses_seed_words(password, seed):
        raise SeedBackupPasswordReusesSeedError("the password must be independent of the seed phrase")

    plaintext = build_backup_plaintext(seed)
    passphrase_bytes = password.encode("utf-8")
    envelope_json = encrypted_blob.encrypt(plaintext, passphrase_bytes)

    path = backup_path()
    tmp_path = path + ".tmp"
    try:
        with open(tmp_path, "w") as f:
            f.write(envelope_json)
            f.flush()
            os.fsync(f.fileno())

        # Verify the file actually written to disk, not just the in-memory
        # envelope string, decrypts back to exactly the same mnemonic --
        # using the SAME in-memory password (no re-entry), so a keyboard-
        # state mismatch between two separate entry screens can never
        # produce a false-negative here (ADV-003).
        with open(tmp_path, "r") as f:
            written_envelope = f.read()
        recovered_plaintext = encrypted_blob.decrypt(written_envelope, passphrase_bytes)
        if json.loads(recovered_plaintext)["mnemonic"] != seed.mnemonic_list:
            raise SeedBackupError("post-write verification mismatch")

        os.replace(tmp_path, path)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def read_backup(password: str) -> RestoredBackup:
    """ Decrypts backup_path() under `password`. Raises
        SeedBackupNotFoundError if no backup exists, SeedBackupFormatError
        for an oversized or malformed file, or SeedBackupDecryptError for
        a wrong password or a corrupted/tampered file (deliberately
        indistinguishable). """
    path = backup_path()
    if not os.path.exists(path):
        raise SeedBackupNotFoundError(f"no backup file at {path}")

    if os.path.getsize(path) > MAX_BACKUP_FILE_BYTES:
        raise SeedBackupFormatError("backup file is larger than any real backup this device produces")

    with open(path, "r") as f:
        envelope_json = f.read()

    try:
        plaintext = encrypted_blob.decrypt(envelope_json, password.encode("utf-8"))
    except encrypted_blob.EncryptedBlobError as e:
        raise SeedBackupDecryptError("wrong password or corrupted file") from e

    parsed = parse_backup_plaintext(plaintext)
    return RestoredBackup(
        mnemonic=parsed["mnemonic"],
        wordlist_language_code=parsed["wordlist_language_code"],
        passphrase_required=parsed["passphrase_required"],
        expected_fingerprint=parsed["expected_fingerprint"],
    )
