"""
    The 7F seed label: the first 8 hex of the seed's testnet Root subject key
    id (Jorge, 2026-10-07), shown in 7F mode wherever stock SeedSigner shows
    the BIP-32 fingerprint (HASH160 of the secp256k1 master key, unrelated to
    any 7F key).
"""
from embit.bip39 import mnemonic_to_seed

from seedsigner.models.sevenf import seed_label as sl

ABANDON_ART = " ".join(["abandon"] * 23 + ["art"])


def test_label_is_the_first_8_hex_of_the_testnet_root_ski():
    # ski 591c511984a2d73c6bee1f4dc149d48f7f97fc55 from real sf-wallet-gov
    assert sl.sevenf_seed_label(mnemonic_to_seed(ABANDON_ART, password="")) == "591c5119"


def test_a_passphrase_changes_the_label():
    assert sl.sevenf_seed_label(mnemonic_to_seed(ABANDON_ART, password="x")) != "591c5119"


def test_label_is_cached_per_seed(monkeypatch):
    seed = mnemonic_to_seed(ABANDON_ART, password="cache-test")
    first = sl.sevenf_seed_label(seed)
    monkeypatch.setattr(sl, "derive_root_ceremony_keys", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("re-derived")))
    assert sl.sevenf_seed_label(seed) == first
