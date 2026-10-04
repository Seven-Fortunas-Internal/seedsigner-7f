"""
    Shared review-field formatting helpers for the 7F ceremony flows --
    extracted 2026-10-04 (7f-review-shared-helpers-deduplication, found by
    the Python-code-quality and modularity dimensions of the full-project
    adversarial review): format_timestamp() used to be copy-pasted
    byte-for-byte across genesis_config.py and devfund_config.py with no
    stated rationale (unlike build_root_sig_json's own deliberately-
    documented duplication to avoid a cross-module "concept ownership"
    dependency -- this is plain formatting utility, not derivation or
    canonical-bytes logic, so no such rationale applies here), and
    cert_request.py was already importing both helpers from genesis_config.py
    as a third-module cross-import. All three artifact modules (genesis,
    devfund, cert_request) now import from here instead.
"""
import hashlib
from datetime import datetime, timezone


def format_timestamp(timestamp: int) -> str:
    """ Shows both the raw signed value (exactly what's inside the bytes
        being signed -- an operator cross-checking against the coordinator's
        own display must see the identical number) and its UTC
        interpretation, so the operator can actually evaluate whether the
        date is sane -- a bare Unix epoch integer isn't independently
        reviewable by a human. Found live 2026-09-27 (7F hardware
        walkthrough). `timestamp` is coordinator-supplied, unvalidated data
        (u64, so it can be far outside any real calendar date) -- refuse to
        let an out-of-range value crash the whole review screen; show the
        raw value alone with a clear note instead ("refuse rather than
        guess" for the interpretation, not for the raw value itself, which
        is always shown). """
    try:
        utc_str = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, OverflowError, ValueError):
        return f"{timestamp} (not a valid calendar date)"
    return f"{timestamp}\n({utc_str})"


def root_id(vk_hex: str) -> str:
    """ Ports 7fchain's crates/sf-core/src/genesis_config.rs::root_id()
        exactly: `hex::encode(&Sha256::digest(&vk)[..10])` -- SHA-256 of the
        raw key, truncated to 10 bytes, hex-encoded (20 characters).
        Re-confirmed directly against that real, current source 2026-09-30
        after finding this function's PREVIOUS implementation here
        (`vk_hex[:20].lower()`, a bare string truncation with no hashing at
        all) computed a value with zero relationship to the real one --
        found via a 7fchain sync, not by this module's own test suite,
        since that suite's own fixture values encoded the same wrong
        assumption rather than a real reference vector. Used to name a
        signature file the same way sf-root.rs's own outbox does
        (`<id>.genesis`, `<id>.rootcert`, `<id>.deputy`) and to show the
        operator a verifiable identity fingerprint on the review screen
        before signing (D11) -- both uses depend on this matching the real
        function exactly, not just being *a* fingerprint. """
    vk = bytes.fromhex(vk_hex)
    return hashlib.sha256(vk).digest()[:10].hex()
