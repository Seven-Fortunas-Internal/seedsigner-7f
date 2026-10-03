"""
    Root-to-Deputy child-seed export: derive a seed at
    `deputy/<chain_kind>/0/ml-dsa/v1` from this seed's own master seed,
    generate a fresh 8-word bootstrap passphrase, and encrypt the result
    into the KeyDatabase-shaped blob `sf-deputy init --import` used to
    expect. Backs 7f-signing-support-deputy-ca-seed-export.

    ** CONFIRMED NON-FUNCTIONAL AGAINST THE REAL CEREMONY, 2026-10-03 **
    (R27 sync-check finding, M-8/C8): the receiving-side mechanism this
    module targets is gone on 7fchain's side. `crates/sf-keytree/src/
    database.rs` (the `KeyDatabase` type `sf-deputy init --import` read)
    was deleted 2026-10-02. The real ceremony no longer hands a seed down
    at all -- per Patrick's internal-docs commit `d2a1477` (C8), "the
    Deputy derives its own key, on its own holder's own airgapped
    seed-signer, from that holder's own 24 words... it is not derived from
    any Root's seed." A Deputy now issues a CSR (see cert_request.py)
    instead of importing a handed-down seed.

    This module is kept MECHANICALLY COMPILING against the re-ported
    single-grammar FFI (mldsa.derive_seed_raw, renamed from
    derive_purpose_seed) as part of that re-port, NOT redesigned to match
    the real C8 ceremony -- that redesign (or removal) is deliberately out
    of this re-port's scope and is tracked as its own story,
    7f-signing-support-deputy-seed-export-obsolete, in
    _delivery/backlog.yaml. Any caller-facing view built on this module
    should be treated as exporting toward a format the real ceremony no
    longer accepts, pending that story's resolution.

    Confirmed against 7fchain's real crates/sf-keytree/src/bin/{sf-root,
    sf-deputy}.rs (`cmd_export`/`cmd_init`, as they existed before M-8) and
    the now-deleted crates/sf-keytree/src/database.rs -- the plaintext
    JSON shape and the encryption primitive are real, ported formats, not
    invented here (see encrypted_blob.py and bootstrap_passphrase.py for
    the two pieces this module composes).

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


def deputy_path(chain_kind: ChainKind) -> str:
    """ `deputy/<chain_kind>/0/ml-dsa/v1` -- the single-grammar path for
        the Deputy role (RE-PORTED 2026-10-03, R27). See this module's own
        docstring: this path still derives a real seed, but the format
        that seed was historically exported INTO is confirmed obsolete. """
    return f"deputy/{chain_kind.path_segment}/0/ml-dsa/v1"


def build_export(seed_bytes: bytes, chain_kind: ChainKind) -> tuple[list[str], str]:
    """ Derive the deputy seed for `chain_kind` from `seed_bytes`,
        generate a fresh 8-word bootstrap passphrase, and encrypt
        {"version":1,"created_at":...,"entries":[{"path":...,"seed_hex":...,
        "created_at":...,"status":"active"}]} under it -- the KeyDatabase
        JSON shape `sf-deputy init --import` used to expect before that
        mechanism was deleted on 7fchain's side (see this module's own
        docstring -- CONFIRMED NON-FUNCTIONAL against the real ceremony).
        Returns (bootstrap_words, envelope_json). Raises mldsa.MlDsaError
        or ValueError on any derivation failure. Slow (~4 seconds, the
        real, measured Argon2id cost) -- callers must show a progress
        indicator (gui.screens.screen.LoadingScreenThread), not call this
        on the render thread unshielded. """
    path = deputy_path(chain_kind)
    seed = mldsa.derive_seed_raw(seed_bytes, path)

    now = int(time.time())
    plaintext = json.dumps({
        "version": 1,
        "created_at": now,
        "entries": [{
            "path": path,
            "seed_hex": seed.hex(),
            "created_at": now,
            "status": "active",
        }],
    }).encode("utf-8")

    words = bootstrap_passphrase.generate_bootstrap_passphrase()
    passphrase_bytes = bootstrap_passphrase.passphrase_to_bytes(words)
    envelope = encrypted_blob.encrypt(plaintext, passphrase_bytes)
    return words, envelope
