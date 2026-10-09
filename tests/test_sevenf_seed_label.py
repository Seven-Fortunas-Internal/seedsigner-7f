"""
    The 7F seed label: the first 8 hex of the seed's testnet Root subject key
    id (Jorge, 2026-10-07), shown in 7F mode wherever stock SeedSigner shows
    the BIP-32 fingerprint. A device convention, not a 7fchain identifier; a
    seed 7fchain would not derive from is labelled NOT_7F.
"""
from seedsigner.models.seed import Seed
from seedsigner.models.sevenf import seed_label as sl

ABANDON_ART = ["abandon"] * 23 + ["art"]


def test_label_is_the_first_8_hex_of_the_testnet_root_ski():
    # ski 591c511984a2d73c6bee1f4dc149d48f7f97fc55 from real sf-wallet-gov
    assert sl.sevenf_seed_label(Seed(ABANDON_ART)) == "591c5119"


def test_a_passphrase_changes_the_label():
    assert sl.sevenf_seed_label(Seed(ABANDON_ART, passphrase="x")) not in ("591c5119", sl.NOT_7F)


def test_a_12_word_seed_is_not_7f():
    assert sl.sevenf_seed_label(Seed(["abandon"] * 11 + ["about"])) == sl.NOT_7F


def test_label_is_cached_per_seed(monkeypatch):
    seed = Seed(ABANDON_ART, passphrase="cache-test")
    first = sl.sevenf_seed_label(seed)
    monkeypatch.setattr(sl, "derive_root_ceremony_keys", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("re-derived")))
    assert sl.sevenf_seed_label(seed) == first
