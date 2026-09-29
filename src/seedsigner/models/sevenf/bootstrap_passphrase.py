"""
    8-word BIP-39 bootstrap passphrase generation/conversion, matching
    7fchain's real crates/sf-keytree/src/mnemonic.rs's
    generate_bootstrap_passphrase()/passphrase_to_bytes() exactly (confirmed
    field-for-field and bit-for-bit against that real source, including
    real reference vectors extracted directly from it -- see this module's
    own test file).

    NOT a seed phrase and not BIP-39-checksummed: 8 words, each
    independently drawn (with replacement) from the standard BIP-39 English
    wordlist, used only as the encryption passphrase for one Root-to-Deputy
    child-seed export blob (7f-signing-support-deputy-ca-seed-export). Pure
    envelope/encoding logic, not derivation or canonical bytes, so doing it
    in Python here doesn't violate D12 (same reasoning already applied to
    genesis_config.py's review-line formatting and cert_request.py's
    envelope parsing).

    Reuses embit's own BIP-39 English wordlist (embit.bip39.WORDLIST,
    already a dependency of this project) rather than embedding a second
    copy of the same 2048 words.
"""
import secrets

from embit.bip39 import WORDLIST

assert len(WORDLIST) == 2048, "expected the standard 2048-word BIP-39 English wordlist"

BOOTSTRAP_PASSPHRASE_WORD_COUNT = 8
BOOTSTRAP_PASSPHRASE_ENTROPY_LEN = 11  # 8 words * 11 bits / 8 = 88 bits = 11 bytes


def generate_bootstrap_passphrase() -> list[str]:
    """ 8 words, each independently drawn (with replacement, no BIP-39
        checksum) from the standard wordlist -- confirmed against 7fchain's
        real generate_bootstrap_passphrase() (88 bits of entropy, 11
        bits/word). Uses Python's `secrets` module (a CSPRNG) rather than
        this device's own dice-entropy pipeline: this passphrase protects a
        single ephemeral export blob for one ceremony step, not long-lived
        key material, so the stricter operator-witnessed dice-entropy bar
        this project applies to actual keys doesn't apply here. """
    return [secrets.choice(WORDLIST) for _ in range(BOOTSTRAP_PASSPHRASE_WORD_COUNT)]


def passphrase_to_bytes(words: list[str]) -> bytes:
    """ Convert an 8-word bootstrap passphrase to 11 bytes of entropy,
        matching 7fchain's real passphrase_to_bytes() bit-packing exactly:
        each word's 11-bit wordlist index, concatenated most-significant-
        bit-first into 88 bits, packed MSB-first into 11 bytes. Raises
        ValueError if the count isn't 8 or any word isn't in the wordlist
        -- refuses rather than guesses, since this is what stands between a
        typo and silently deriving the wrong encryption key. """
    if len(words) != BOOTSTRAP_PASSPHRASE_WORD_COUNT:
        raise ValueError(f"bootstrap passphrase must be {BOOTSTRAP_PASSPHRASE_WORD_COUNT} words, got {len(words)}")

    bits = []
    for word in words:
        try:
            index = WORDLIST.index(word)
        except ValueError:
            raise ValueError(f"{word!r} is not in the BIP-39 wordlist") from None
        bits.extend((index >> bit) & 1 for bit in range(10, -1, -1))

    entropy = bytearray(BOOTSTRAP_PASSPHRASE_ENTROPY_LEN)
    for i, bit in enumerate(bits):
        if bit:
            entropy[i // 8] |= 1 << (7 - (i % 8))
    return bytes(entropy)
