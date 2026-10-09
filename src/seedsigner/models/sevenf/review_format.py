"""
    Shared review-field formatting helpers for the 7F ceremony flows
    (7f-review-shared-helpers-deduplication): plain formatting utilities,
    not derivation or canonical-bytes logic, used by all three artifact
    modules (genesis, devfund, cert_request).
"""
import hashlib
import unicodedata
from datetime import datetime, timedelta, timezone


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
    d = utc_datetime(timestamp)
    if d is None:
        return f"{timestamp} (not a valid calendar date)"
    return f"{timestamp}\n({d:%Y-%m-%d %H:%M:%S} UTC)"


_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# The warning beside a coordinator-supplied timestamp that is no calendar date.
# sf-wallet-gov signs any non-zero timestamp (sign_ops.rs), so this warns only.
NOT_A_CALENDAR_DATE = "Not a calendar date. Ask the coordinator before signing."


def utc_datetime(timestamp: int) -> datetime | None:
    """ The UTC date of a Unix timestamp, or None past datetime's range (year
        9999). Computed as epoch + seconds, never through the platform's time_t:
        the device is 32-bit, where datetime.fromtimestamp() stops at
        2038-01-19 and a 20-year certificate ends in the 2040s (found on the
        dev unit, 2026-10-08). """
    try:
        return _EPOCH + timedelta(seconds=timestamp)
    except OverflowError:
        return None


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


def _shown_as_is(ch: str) -> bool:
    """ Printable ASCII, and the Latin letters and signs of Latin-1 and Latin
        Extended-A/B, which the device's font draws and nothing else imitates. """
    code = ord(ch)
    if 0x21 <= code <= 0x7E:
        return ch != "\\"
    return 0xA1 <= code <= 0x24F and unicodedata.category(ch)[0] not in "CMZ"


def _escape(ch: str) -> str:
    code = ord(ch)
    return f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}"


def visible_text(s: str) -> str:
    """ Coordinator-supplied free text as it must be shown before signing, so
        that two different texts never look the same on the device (security
        and adversarial reviews 2026-10-08):
        - a newline or tab is \\n or \\t, and a backslash is \\\\ (so a typed
          "\\u0301" can't pass for an escaped one);
        - a space shows as a space only between two other characters: the
          screen collapses a run of spaces and drops them at a line's ends, so
          the others are \\u0020;
        - anything but printable ASCII and Latin letters is \\uXXXX: combining
          marks, bidi and other controls, look-alike letters from other scripts
          (Cyrillic "\\u0430" for "a"), and characters the font draws as the
          same box. """
    out = []
    for i, ch in enumerate(s):
        if ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\\":
            out.append("\\\\")
        elif ch == " ":
            shown = 0 < i < len(s) - 1 and s[i - 1] != " "    # the first of a run, not at an end
            out.append(" " if shown else "\\u0020")
        elif _shown_as_is(ch):
            out.append(ch)
        else:
            out.append(_escape(ch))
    return "".join(out)
