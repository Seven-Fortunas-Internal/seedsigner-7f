"""
    Derivation-path lexicon validator (R8/D9). Ported field-for-field from
    7fchain's own `crates/sf-keytree/src/path.rs` -- the real, authoritative
    source D9 assigns lexicon ownership to (Patrick's side), not guessed or
    independently invented (D12).

    Not wired into any live flow today: every 7F path this device ever
    builds is constructed internally by known-good functions
    (root_ca_purpose_path(), devfund_purpose_path(), etc. in constants.py),
    never taken as a raw string from scanned/external input. This exists so
    the validator itself is ready the day something does need it, and so
    "reject a malformed derivation path even though none reaches the device
    today" (R8's own framing) has a real implementation instead of a filed
    gap. See 7f-signing-support-path-lexicon-validator in
    _delivery/backlog.yaml.

    Deliberately kept in sync with path.rs by direct comparison, not by a
    shared source -- re-diff against that file if it changes. Same
    discipline derive.rs's own module docstring already documents for this
    codebase's other 7fchain ports.
"""
from seedsigner.models.sevenf.constants import ChainKind, Layer

MAX_SEGMENT_LEN = 32

RESERVED_CATEGORIES = (
    "root-ca", "deputy-ca", "centcom-ca", "intermediate-ca",
    "stablecoin", "giftcard", "utilitytoken", "7fchain",
)

# Mirrors sf_core::genesis_config::ChainKind lowercase strings -- reuses
# this codebase's own ChainKind enum as the single source of truth rather
# than a second hardcoded string list.
VALID_CHAIN_KINDS = tuple(ck.path_segment for ck in ChainKind)

VALID_LAYERS = tuple(layer.name.lower() for layer in Layer)

RESERVED_ROLES = (
    "ml-dsa", "falcon", "bip32", "minter", "master-minter",
    "pauser", "blacklister", "admin", "owner", "deployer",
)

# (name, category, description) -- for validation hints only, not enforced.
KNOWN_TOKENS = (
    ("7fusd", "stablecoin", "7F US Dollar stablecoin"),
    ("gtq", "stablecoin", "Guatemalan Quetzal stablecoin"),
    ("intercorp", "giftcard", "Intercorp remittance token"),
    ("interbank", "utilitytoken", "Interbank utility token"),
)


class PathLexiconError(Exception):
    """ Raised for any derivation path that fails lexicon validation --
        wrong character set, unknown category/role/chain_kind, wrong
        segment count for its category, or a non-numeric index. """


def is_reserved_category(category: str) -> bool:
    return category in RESERVED_CATEGORIES


def is_reserved_role(role: str) -> bool:
    return role in RESERVED_ROLES


_ASCII_LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
_ASCII_DIGITS = "0123456789"


def _validate_segment(segment: str) -> None:
    """ [a-z0-9-] STRICTLY ASCII -- matches Rust's `is_ascii_lowercase()`/
        `is_ascii_digit()` exactly. Python's str.islower()/isdigit() are
        NOT ascii-only (e.g. 'à'.islower() and '²'.isdigit() are both True),
        so checking against them directly would silently accept
        Unicode-lookalike segments the real reference rejects -- caught by
        cross-checking this port against the actual Rust semantics, not
        just against a passing test suite. """
    if not segment:
        raise PathLexiconError("path segment cannot be empty")
    if len(segment) > MAX_SEGMENT_LEN:
        raise PathLexiconError(f"path segment '{segment}' exceeds {MAX_SEGMENT_LEN} characters")
    if not all(c in _ASCII_LOWERCASE or c in _ASCII_DIGITS or c == "-" for c in segment):
        raise PathLexiconError(f"path segment '{segment}' contains invalid characters (allowed: a-z, 0-9, -)")


def _validate_chain_kind(seg: str) -> None:
    if seg not in VALID_CHAIN_KINDS:
        raise PathLexiconError(f"chain_kind segment must be one of {list(VALID_CHAIN_KINDS)}, got '{seg}'")


def _validate_layer(seg: str) -> None:
    if seg not in VALID_LAYERS:
        raise PathLexiconError(f"layer segment must be one of {list(VALID_LAYERS)}, got '{seg}'")


def _validate_index(seg: str, label: str) -> None:
    # ASCII-only for the same reason _validate_segment is (str.isdigit()
    # accepts non-ASCII digit characters, e.g. Arabic-Indic '٣').
    if not seg or not all(c in _ASCII_DIGITS for c in seg):
        raise PathLexiconError(f"{label} index must be numeric, got '{seg}'")


def _layered_simple(category: str, segments: list[str]) -> None:
    """ L1-only categories that still carry the layer marker for path-shape
        symmetry: m/<cat>/l1/<chain_kind>/<index> (4 segments). """
    if len(segments) != 4:
        raise PathLexiconError(f"{category} path must be m/{category}/l1/<chain_kind>/<index>")
    _validate_layer(segments[1])
    if segments[1] != "l1":
        raise PathLexiconError(f"{category} is L1-only; got layer '{segments[1]}'")
    _validate_chain_kind(segments[2])
    _validate_index(segments[3], category)


def _layered_l1_or_l2(category: str, segments: list[str]) -> None:
    """ Categories that live in both layers (deputy-ca, centcom-ca,
        intermediate-ca):
          L1: m/<cat>/l1/<chain_kind>/<index>               -- 4 segments
          L2: m/<cat>/l2/<chain_kind>/<l2_chain_id>/<index> -- 5 segments
    """
    if len(segments) < 4:
        raise PathLexiconError(
            f"{category} path must be m/{category}/l1/<chain_kind>/<index> "
            f"or m/{category}/l2/<chain_kind>/<l2_chain_id>/<index>"
        )
    _validate_layer(segments[1])
    _validate_chain_kind(segments[2])
    if segments[1] == "l1":
        if len(segments) != 4:
            raise PathLexiconError(f"{category} L1 path must be m/{category}/l1/<chain_kind>/<index>")
        _validate_index(segments[3], category)
    else:  # "l2", the only other value _validate_layer allows
        if len(segments) != 5:
            raise PathLexiconError(
                f"{category} L2 path must be m/{category}/l2/<chain_kind>/<l2_chain_id>/<index>"
            )
        _validate_index(segments[3], "l2_chain_id")
        _validate_index(segments[4], category)


def validate_purpose_path(path: str) -> None:
    """ Validate a purpose path (Level 1). Raises PathLexiconError on any
        violation; returns None on success.

        Examples: "m/root-ca/l1/testnet/0", "m/deputy-ca/l2/testnet/42/0",
        "m/stablecoin/7fusd/0", "m/7fchain/l1/testnet/devfund/0". """
    if not path.startswith("m/"):
        raise PathLexiconError("purpose path must start with 'm/'")

    segments = path[2:].split("/")
    if not segments or segments == [""]:
        raise PathLexiconError("purpose path must have at least one segment after 'm/'")

    for seg in segments:
        _validate_segment(seg)

    category = segments[0]

    if category == "root-ca":
        _layered_simple(category, segments)
    elif category in ("deputy-ca", "centcom-ca", "intermediate-ca"):
        _layered_l1_or_l2(category, segments)
    elif category in ("stablecoin", "giftcard", "utilitytoken"):
        if len(segments) != 3:
            raise PathLexiconError(f"{category} path must be m/{category}/<name>/<index>")
        _validate_index(segments[2], category)
    elif category == "7fchain":
        if len(segments) < 4:
            raise PathLexiconError("7fchain path must be m/7fchain/<l1|l2>/<chain_kind>/...")
        _validate_layer(segments[1])
        _validate_chain_kind(segments[2])
        if segments[1] == "l1":
            if len(segments) != 5:
                raise PathLexiconError("7fchain L1 path must be m/7fchain/l1/<chain_kind>/<purpose>/<index>")
            _validate_index(segments[4], "7fchain")
        else:  # "l2"
            role = segments[3]
            if role == "sequencer":
                if len(segments) != 6:
                    raise PathLexiconError(
                        "7fchain L2 sequencer path must be "
                        "m/7fchain/l2/<chain_kind>/sequencer/<l2_chain_id>/<index>"
                    )
                _validate_index(segments[4], "l2_chain_id")
                _validate_index(segments[5], "7fchain")
            elif role in ("verifier", "rechecker", "federation"):
                if len(segments) != 5:
                    raise PathLexiconError(
                        "7fchain L2 verifier/rechecker/federation path must be "
                        "m/7fchain/l2/<chain_kind>/<role>/<index>"
                    )
                _validate_index(segments[4], "7fchain")
            else:
                raise PathLexiconError(
                    f"7fchain L2 role must be sequencer|verifier|rechecker|federation, got '{role}'"
                )
    else:
        raise PathLexiconError(f"unknown category '{category}'. Reserved categories: {list(RESERVED_CATEGORIES)}")


def validate_role_path(path: str) -> None:
    """ Validate a role path (Level 2). Raises PathLexiconError on any
        violation; returns None on success.

        Examples: "ml-dsa/0", "falcon/0", "minter/0", "admin/0". """
    segments = path.split("/")
    if len(segments) != 2:
        raise PathLexiconError("role path must be <role>/<index>")
    _validate_segment(segments[0])
    _validate_index(segments[1], "role")
