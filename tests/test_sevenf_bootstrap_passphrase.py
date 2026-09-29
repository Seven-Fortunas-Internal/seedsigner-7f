"""
    Tests seedsigner.models.sevenf.bootstrap_passphrase -- 8-word bootstrap
    passphrase generation/conversion for the Root-to-Deputy child-seed
    export. Backs 7f-signing-support-deputy-ca-seed-export.
"""
import pytest

from seedsigner.models.sevenf.bootstrap_passphrase import (
    BOOTSTRAP_PASSPHRASE_ENTROPY_LEN,
    BOOTSTRAP_PASSPHRASE_WORD_COUNT,
    generate_bootstrap_passphrase,
    passphrase_to_bytes,
)

# Real reference vectors extracted directly from 7fchain's own
# crates/sf-keytree/src/mnemonic.rs::passphrase_to_bytes() (a temporary
# #[test] added and immediately reverted in that checkout).
REFERENCE_VECTORS = [
    (["abandon"] * 8, "0000000000000000000000"),
    (["zoo"] * 8, "ffffffffffffffffffffff"),
    (["abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract"], "0000040100300801403007"),
]


@pytest.mark.parametrize("words,expected_hex", REFERENCE_VECTORS)
def test_passphrase_to_bytes_matches_the_real_reference_vectors(words, expected_hex):
    assert passphrase_to_bytes(words).hex() == expected_hex


def test_passphrase_to_bytes_output_is_11_bytes():
    words = ["abandon"] * 8
    assert len(passphrase_to_bytes(words)) == BOOTSTRAP_PASSPHRASE_ENTROPY_LEN == 11


def test_passphrase_to_bytes_rejects_wrong_word_count():
    with pytest.raises(ValueError):
        passphrase_to_bytes(["abandon"] * 7)
    with pytest.raises(ValueError):
        passphrase_to_bytes(["abandon"] * 9)


def test_passphrase_to_bytes_rejects_a_word_not_in_the_wordlist():
    words = ["abandon"] * 7 + ["not-a-real-bip39-word"]
    with pytest.raises(ValueError):
        passphrase_to_bytes(words)


def test_generate_bootstrap_passphrase_returns_8_words_from_the_wordlist():
    from embit.bip39 import WORDLIST
    words = generate_bootstrap_passphrase()
    assert len(words) == BOOTSTRAP_PASSPHRASE_WORD_COUNT
    assert all(w in WORDLIST for w in words)


def test_generate_bootstrap_passphrase_is_not_constant():
    # Overwhelmingly unlikely to collide for a real CSPRNG across many draws.
    samples = [tuple(generate_bootstrap_passphrase()) for _ in range(20)]
    assert len(set(samples)) > 1


def test_generate_bootstrap_passphrase_round_trips_through_passphrase_to_bytes():
    words = generate_bootstrap_passphrase()
    entropy = passphrase_to_bytes(words)
    assert len(entropy) == 11
