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


def ski(vk_hex: str) -> str:
    """ The Subject Key Identifier: SHA-256 of the raw key truncated to 20
        bytes, hex-encoded (40 characters) -- RFC 7093 method 1, ported from
        7fchain's shared-crypto x509::key_id(). Since 7fchain ce04ae9/416f576
        (2026-10-07) it is the ONE key id a person reads: sf-wallet-gov prints
        it as "subject key id", an issued certificate carries it (so
        `openssl x509 -text` reads it back), and every governance file is named
        by it (`<ski>.vk`, `<ski>.genesis`, `<ski>.devfund`, `root-<ski>.pem`).
        The coordinator pairs a keyless signature with its `.vk` by that stem.
        Replaces the 20-hex sf-core root_id() this module used to port, which
        is now internal to 7fchain (ledger, CSR common name) and shown to no
        one. """
    vk = bytes.fromhex(vk_hex)
    return hashlib.sha256(vk).digest()[:20].hex()


def format_ski_for_display(ski_hex: str) -> str:
    """ The ski in groups of four for the 240px screen: 40 unbroken hex
        characters can't line-wrap and ran off both edges, while ten groups
        wrap into two lines and are easier to read aloud and compare. Display
        only -- filenames and anything copied use the plain ski. """
    return " ".join(ski_hex[i:i + 4] for i in range(0, len(ski_hex), 4))
