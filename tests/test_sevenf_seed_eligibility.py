"""
    Story port-root-phrase-24-words (K2, with plan-stage review H-1, H-3, M-4):
    7fchain derives Root and dev-fund keys only from a 24-word BIP-39 phrase
    (sf-keytree phrase_file.rs ROOT_WORD_COUNT = 24, mnemonic.rs master_seed),
    with an optional BIP-39 passphrase. A SevenFSeed exists only for such a
    seed, and every 7F derivation and signing call takes one. CA keys carry no
    address (sf-wallet-gov derive-vk prints none for them).
"""
import hashlib
import unicodedata

import pytest

from seedsigner.models.seed import ElectrumSeed, Seed
from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.models.sevenf.review_format import ski
from seedsigner.models.sevenf.root_ceremony import (
    NotA7FPhraseError,
    SevenFSeed,
    derive_devfund_key,
    derive_root_ceremony_keys,
    seed_for_7f,
    sign_with_devfund,
    sign_with_root_ca,
)

ABANDON_ART = ["abandon"] * 23 + ["art"]
TWELVE = ["abandon"] * 11 + ["about"]
EIGHTEEN = ["abandon"] * 17 + ["agent"]
ELECTRUM = "regular reject rare profit once math fringe chase until ketchup century escape".split()


def test_a_24_word_bip39_seed_is_a_7f_seed():
    s = seed_for_7f(Seed(ABANDON_ART))
    assert isinstance(s, SevenFSeed)
    vk = derive_root_ceremony_keys(s, ChainKind.TESTNET, index=0).root_ca.public_key
    assert ski(vk.hex()) == "591c511984a2d73c6bee1f4dc149d48f7f97fc55"     # sf-wallet-gov, index 0


@pytest.mark.parametrize("seed", [Seed(TWELVE), Seed(EIGHTEEN), ElectrumSeed(ELECTRUM)], ids=["12", "18", "electrum"])
def test_other_seeds_are_refused(seed):
    with pytest.raises(NotA7FPhraseError):
        seed_for_7f(seed)


def test_an_electrum_subclass_is_refused_even_if_it_were_24_words():
    """ M-4: ElectrumSeed is a Seed subclass whose seed bytes are not BIP-39
        (salt b"electrum"); refused by type, not only by length. """
    class _Fake24(ElectrumSeed):
        def _generate_seed(self):
            self.seed_bytes = b"\x00" * 64
    with pytest.raises(NotA7FPhraseError):
        seed_for_7f(_Fake24(ABANDON_ART))


def test_a_sevenf_seed_cannot_be_made_from_raw_bytes():
    with pytest.raises(TypeError):
        SevenFSeed(b"\x00" * 64)


@pytest.mark.parametrize("call", [
    lambda b: derive_root_ceremony_keys(b, ChainKind.TESTNET, index=0),
    lambda b: derive_devfund_key(b, ChainKind.TESTNET, index=0),
    lambda b: sign_with_root_ca(b, ChainKind.TESTNET, b"m", confirmed=True, index=0),
    lambda b: sign_with_devfund(b, ChainKind.TESTNET, b"m", confirmed=True, index=0),
])
def test_7f_derivation_and_signing_take_only_a_sevenf_seed(call):
    with pytest.raises(TypeError):
        call(Seed(ABANDON_ART).seed_bytes)
    with pytest.raises(TypeError):
        call(Seed(ABANDON_ART))


def test_a_bip39_passphrase_is_allowed_and_normalised_as_bip39():
    """ L-4: 7fchain accepts a BIP-39 passphrase (NFKD, salt "mnemonic" +
        passphrase); the seed bytes are the standard ones. """
    passphrase = "Ñandú ﬁ"
    s = seed_for_7f(Seed(ABANDON_ART, passphrase=passphrase))
    words = unicodedata.normalize("NFKD", " ".join(ABANDON_ART))
    want = hashlib.pbkdf2_hmac("sha512", words.encode(), ("mnemonic" + unicodedata.normalize("NFKD", passphrase)).encode(), 2048)
    assert s.seed_bytes == want


def test_ca_keys_carry_no_address():
    """ H-3: sf-wallet-gov prints no address for a CA key ("would invite
        someone to pay it"); neither does the device. """
    s = seed_for_7f(Seed(ABANDON_ART))
    assert not hasattr(derive_root_ceremony_keys(s, ChainKind.TESTNET, index=0).root_ca, "address")
    assert not hasattr(derive_devfund_key(s, ChainKind.TESTNET, index=0), "address")


def test_the_seed_label_names_only_7f_seeds():
    from seedsigner.models.sevenf.seed_label import NOT_7F, sevenf_seed_label
    assert sevenf_seed_label(Seed(ABANDON_ART)) == "591c5119"
    assert sevenf_seed_label(Seed(TWELVE)) == NOT_7F


def test_the_plugin_does_not_sign_or_derive_outside_the_7f_views():
    """ H-1: SevenFPlugin.sign/derive_address took raw seed bytes and no view
        uses them; they refuse rather than bypass the 7F gates. """
    from seedsigner.chains.sevenf.plugin import SevenFPlugin
    plugin = SevenFPlugin()
    raw = Seed(ABANDON_ART).seed_bytes
    with pytest.raises(NotImplementedError):
        plugin.sign(raw, "root/testnet/0/ml-dsa/v1", b"{}")
    with pytest.raises(NotImplementedError):
        plugin.derive_address(raw, "root/testnet/0/ml-dsa/v1")


def test_only_the_english_wordlist_is_7f():
    """ 7fchain's mnemonic.rs parses with bip39 2.2.2 default features, which
        enable English only (sf-keytree master_seed / parse_normalized). """
    from seedsigner.models.settings_definition import SettingsConstants
    seed = Seed(ABANDON_ART)
    seed._wordlist_language_code = "es"
    with pytest.raises(NotA7FPhraseError):
        seed_for_7f(seed)
    assert SettingsConstants.WORDLIST_LANGUAGE__ENGLISH == Seed(ABANDON_ART).wordlist_language_code
