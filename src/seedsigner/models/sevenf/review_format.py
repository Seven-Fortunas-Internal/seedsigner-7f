"""
    Shared review-field formatting helpers for the 7F ceremony flows
    (7f-review-shared-helpers-deduplication): plain formatting utilities,
    not derivation or canonical-bytes logic, used by all three artifact
    modules (genesis, devfund, cert_request).
"""
import hashlib
import json
import unicodedata
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
        7fchain still shows the 20-hex sf-core root_id() in some error
        messages (sign_ops.rs) and in a CSR common name (main.rs create-csr);
        this device names keys by subject key id only. """
    vk = bytes.fromhex(vk_hex)
    return hashlib.sha256(vk).digest()[:20].hex()


def pin(vk_hex: str) -> str:
    """ The pin: SHA-256 of the raw key, all 32 bytes hex-encoded (64
        characters) -- 7fchain's shared-crypto x509::vk_pin(). It is the
        trust anchor sign-root-cert prints as "root pin" and a federation
        member reports over a second channel (ceremony-federation-member.md
        Step 4). The ski is its first 40 characters. """
    return hashlib.sha256(bytes.fromhex(vk_hex)).hexdigest()


def group_hex_for_display(hex_str: str) -> str:
    """ Hex in groups of four for the 240px screen: a 40-char ski or 64-char
        pin can't line-wrap unbroken and ran off both edges, while groups
        wrap cleanly and are easier to read aloud and compare. Display only
        -- filenames and anything copied use the plain hex. """
    return " ".join(hex_str[i:i + 4] for i in range(0, len(hex_str), 4))


def canonical_digest(canonical_bytes: bytes) -> str:
    """ sf-wallet-gov's "canonical digest": SHA-256 of the exact bytes being
        signed, first 16 bytes, hex -- the value Roots and the coordinator can
        compare by voice to confirm they are signing the same definition.
        Grouped for the screen. """
    return group_hex_for_display(hashlib.sha256(canonical_bytes).hexdigest()[:32])


def visible_text(s: str) -> str:
    """ Coordinator-supplied free text as it must be shown before signing:
        newlines, tabs, bidi overrides and every other control/format/
        surrogate/unassigned character become a visible escape (\\n, \\t,
        \\uXXXX), so no signed character can be hidden or reorder what the
        operator reads (security review 2026-10-08). """
    out = []
    for ch in s:
        if ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif unicodedata.category(ch)[0] in "CZ" and ch != " ":
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return "".join(out)


def _refuse_constant(name: str):
    raise ValueError(f"non-standard JSON literal {name}")


class JsonObject(dict):
    """ A parsed JSON object that remembers which keys appeared more than once. """
    duplicates: frozenset = frozenset()


def _record_duplicate_keys(pairs: list) -> JsonObject:
    seen, duplicates = set(), set()
    for key, _ in pairs:
        (duplicates if key in seen else seen).add(key)
    obj = JsonObject(pairs)
    obj.duplicates = frozenset(duplicates)
    return obj


def refuse_duplicate_fields(obj, known: frozenset, where: str) -> None:
    """ serde_json's rule for 7fchain's types (no deny_unknown_fields): a
        repeated KNOWN field is an error ("duplicate field `x`"), a repeated
        unknown key is ignored. Checked against sf-core's own GenesisConfig and
        DevFundConfig (tests/test_sevenf_device_limits.py). Raises ValueError. """
    repeated = sorted(getattr(obj, "duplicates", frozenset()) & known)
    if repeated:
        raise ValueError(f"duplicate field `{repeated[0]}` in {where}")


def strict_json_loads(text: str):
    """ json.loads refusing what serde_json refuses for any type (NaN/Infinity
        literals; integers past Python's digit limit), and recording repeated
        keys per object for refuse_duplicate_fields(), since whether a repeat
        is an error depends on the type reading that object. Callers catch
        (ValueError, RecursionError). """
    return json.loads(text, parse_constant=_refuse_constant, object_pairs_hook=_record_duplicate_keys)
