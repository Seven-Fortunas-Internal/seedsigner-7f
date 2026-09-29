"""
    Root-to-Deputy child-seed export: derive the purpose seed at
    `m/deputy-ca/l1/<chain_kind>/0` from this seed's own master seed,
    generate a fresh 8-word bootstrap passphrase, and encrypt the result
    into the exact KeyDatabase-shaped blob 7fchain's real
    `sf-deputy init --import` expects. Backs
    7f-signing-support-deputy-ca-seed-export.

    Confirmed against 7fchain's real crates/sf-keytree/src/bin/{sf-root,
    sf-deputy}.rs (`cmd_export`/`cmd_init`) and crates/sf-keytree/src/
    database.rs -- the plaintext JSON shape, the path, and the encryption
    primitive are all real, ported formats, not invented here (see
    encrypted_blob.py and bootstrap_passphrase.py for the two pieces this
    module composes).

    THE FIRST DEVICE FEATURE THAT EXPORTS SECRET SEED MATERIAL off the
    airgapped device -- sanctioned by D4a (a derived LEAF seed, never the
    master; derivation is one-way, so a stolen leaf never exposes the
    seed this device was set up from). Every caller-facing view built on
    this module must show an explicit no-blind-export confirmation before
    calling build_export(), and must treat the returned bootstrap words and
    envelope as needing to travel to the Deputy machine via DIFFERENT
    channels (standard secret-splitting hygiene for exactly this handoff).
"""
import json
import time

from seedsigner.models.sevenf import bootstrap_passphrase, encrypted_blob, mldsa
from seedsigner.models.sevenf.constants import ChainKind


def deputy_ca_purpose_path(chain_kind: ChainKind) -> str:
    """ Confirmed against 7fchain's real sf-root.rs/sf-deputy.rs:
        `m/deputy-ca/l1/<chain_kind>/0`. """
    return f"m/deputy-ca/l1/{chain_kind.path_segment}/0"


def build_export(seed_bytes: bytes, chain_kind: ChainKind) -> tuple[list[str], str]:
    """ Derive the deputy-ca purpose seed for `chain_kind` from `seed_bytes`,
        generate a fresh 8-word bootstrap passphrase, and encrypt
        {"version":1,"created_at":...,"entries":[{"path":...,"seed_hex":...,
        "created_at":...,"status":"active"}]} under it -- the exact
        KeyDatabase JSON shape `sf-deputy init --import` expects. Returns
        (bootstrap_words, envelope_json). Raises mldsa.MlDsaError or
        ValueError on any derivation failure. Slow (~4 seconds, the real,
        measured Argon2id cost) -- callers must show a progress indicator
        (gui.screens.screen.LoadingScreenThread), not call this on the
        render thread unshielded. """
    path = deputy_ca_purpose_path(chain_kind)
    purpose_seed = mldsa.derive_purpose_seed(seed_bytes, path)

    now = int(time.time())
    plaintext = json.dumps({
        "version": 1,
        "created_at": now,
        "entries": [{
            "path": path,
            "seed_hex": purpose_seed.hex(),
            "created_at": now,
            "status": "active",
        }],
    }).encode("utf-8")

    words = bootstrap_passphrase.generate_bootstrap_passphrase()
    passphrase_bytes = bootstrap_passphrase.passphrase_to_bytes(words)
    envelope = encrypted_blob.encrypt(plaintext, passphrase_bytes)
    return words, envelope
