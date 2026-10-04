"""
    Derivation-path lexicon validator (R8/D9). Ported field-for-field from
    7fchain's own `crates/sf-keytree/src/path.rs` -- the real, authoritative
    source D9 assigns lexicon ownership to (Patrick's side), not guessed or
    independently invented (D12).

    RE-PORTED 2026-10-03 (R27): 7fchain collapsed its two-level
    `purpose_path`/`role_path` grammar into one combined path:

        <role>/<chain-kind>/[<chain-id>/]<index>/<algorithm>/v<N>[/<leaf>]

    -- see firmware/mldsa7f/src/derive.rs's doc comment for why the split
    retired. This file is a line-for-line re-port of the real `path.rs`'s
    `Role`/`Algorithm`/`Leaf` enums and its `parse()`/`validate()`, not an
    independent redesign.

    WIRED IN 2026-10-03 (7f-signing-support-path-validation-not-enforced):
    mldsa.py's derive_pubkey()/derive_and_sign() call validate() on every
    `path` before it reaches the FFI -- the actual boundary every real and
    future Python caller on this device passes through (this architecture
    is Python-orchestrated; nothing calls Rust's derive_seed directly
    except through that ctypes bridge). Every 7F path this device builds is
    still constructed internally by known-good functions (constants.py's
    `root_path()`), never taken as a raw string from scanned/external
    input -- so this validator is defense-in-depth against a future
    caller-/scan-supplied path, not a response to a live attack surface
    today. See 7f-signing-support-path-lexicon-validator and
    7f-signing-support-path-validation-not-enforced in
    _delivery/backlog.yaml.

    Deliberately kept in sync with path.rs by direct comparison, not by a
    shared source -- re-diff against that file if it changes. Same
    discipline derive.rs's own module docstring already documents for this
    codebase's other 7fchain ports.
"""
from enum import Enum

from seedsigner.models.sevenf.constants import ChainKind

MAX_SEGMENT_LEN = 32


class Role(Enum):
    """ What a key is for -- the first segment of every path. Mirrors
        `path.rs`'s `Role` enum exactly, including its two feeder
        properties (`is_chain_bound`, `allows_leaf`) used by the parser. """
    ROOT = "root"
    MINER = "miner"
    WALLET = "wallet"
    DEPUTY = "deputy"
    CENTCOM = "centcom"
    # Registrar is three roles, not one -- one registrar cannot serve all
    # three (Patrick, 2026-10-01). Added 2026-10-03 (7fchain commit
    # 8c69e23); all L1, none chain-bound (a registrar's chain scope lives
    # in its certificate's id-sf-l2-chain-id-ranges grant, not its
    # derivation path), none allows a leaf -- same as Deputy/CentCom, no
    # change needed to is_l2/is_chain_bound/allows_leaf below.
    MINER_REGISTRAR = "miner-registrar"
    L2_VERIFIER_REGISTRAR = "l2-verifier-registrar"
    L2_SEQUENCER_REGISTRAR = "l2-sequencer-registrar"
    L2_WALLET = "l2-wallet"
    SEQUENCER = "sequencer"
    MASTER_MINTER = "master-minter"
    GUARDIAN = "guardian"
    VERIFIER = "verifier"
    RECHECKER = "rechecker"
    FEDERATION = "federation"

    @property
    def is_l2(self) -> bool:
        """ `path.rs::Role::layer()` -- no role spans layers, so the path
            itself carries no layer segment; this is why `wallet` and
            `l2-wallet` are two roles rather than one role plus a layer. """
        return self in (
            Role.L2_WALLET, Role.SEQUENCER, Role.MASTER_MINTER,
            Role.GUARDIAN, Role.VERIFIER, Role.RECHECKER, Role.FEDERATION,
        )

    @property
    def is_chain_bound(self) -> bool:
        """ `path.rs::Role::is_chain_bound()` -- whether the path carries a
            `<chain-id>` segment: a chain-bound role names one specific L2;
            the others serve every chain on the network. """
        return self in (Role.L2_WALLET, Role.SEQUENCER, Role.MASTER_MINTER, Role.GUARDIAN)

    @property
    def allows_leaf(self) -> bool:
        """ `path.rs::Role::allows_leaf()` -- only `miner` has two keys
            under one path (R-L5: consensus pairs a hot key and a
            block-reward key, since coinbase output 0 must pay the address
            the certificate authorises). """
        return self is Role.MINER


class Algorithm(Enum):
    """ Mirrors `path.rs`'s `Algorithm` enum. `FALCON` is never derived any
        more -- kept only so addresses still decode for tooling/interop. """
    ML_DSA = "ml-dsa"
    FALCON = "falcon"


class Leaf(Enum):
    """ Mirrors `path.rs`'s `Leaf` enum -- only valid under `Role.MINER`. """
    HOT = "hot"
    BLOCK_REWARD = "block-reward"


class PathLexiconError(Exception):
    """ Raised for any derivation path that fails lexicon validation --
        wrong character set, unknown role/algorithm/chain_kind, wrong
        segment count for its role, or a non-numeric index/chain-id. """


_ASCII_LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
_ASCII_DIGITS = "0123456789"

# Mirrors sf_crypto::address::ChainKind's lowercase strings -- reuses this
# codebase's own ChainKind enum as the single source of truth rather than a
# second hardcoded string list.
_VALID_CHAIN_KINDS = {ck.path_segment: ck for ck in ChainKind}


def _validate_segment(segment: str) -> None:
    """ [a-z0-9-] STRICTLY ASCII -- matches Rust's `is_ascii_lowercase()`/
        `is_ascii_digit()` exactly. Python's str.islower()/isdigit() are
        NOT ascii-only (e.g. 'à'.islower() and '²'.isdigit() are both True),
        so checking against them directly would silently accept
        Unicode-lookalike segments the real reference rejects -- caught by
        cross-checking this port against the actual Rust semantics, not
        just against a passing test suite. """
    if not segment:
        raise PathLexiconError("path segment must not be empty")
    if len(segment) > MAX_SEGMENT_LEN:
        raise PathLexiconError(f"path segment '{segment}' exceeds {MAX_SEGMENT_LEN} characters")
    if not all(c in _ASCII_LOWERCASE or c in _ASCII_DIGITS or c == "-" for c in segment):
        raise PathLexiconError(f"path segment '{segment}' must be lowercase a-z, 0-9 or '-'")


def _parse_u32(seg: str, label: str) -> int:
    # ASCII-only for the same reason _validate_segment is (str.isdigit()
    # accepts non-ASCII digit characters, e.g. Arabic-Indic '٣').
    if not seg or not all(c in _ASCII_DIGITS for c in seg):
        raise PathLexiconError(f"{label} must be a u32, got '{seg}'")
    value = int(seg)
    if value > 0xFFFFFFFF:
        raise PathLexiconError(f"{label} must be a u32, got '{seg}'")
    return value


def _parse_version(seg: str) -> int:
    """ The version is mandatory -- `path.rs::parse_version()`: an
        algorithm migration changes the keys a role derives, so the
        version belongs in the path that names them. An optional segment
        would mean two spellings of one key, which is exactly how three
        spellings diverged before this rule existed.

        FIXED 2026-10-03: was missing the u32 upper-bound check `_parse_u32`
        has, so `v4294967296` silently parsed instead of being rejected --
        found by direct adversarial execution against the real
        `path.rs::parse_version()` (which calls `digits.parse::<u32>()`,
        erroring on overflow), not by inspection alone. """
    if not (len(seg) >= 2 and seg[0] == "v" and all(c in _ASCII_DIGITS for c in seg[1:])):
        raise PathLexiconError(f"version segment must be v<N>, got '{seg}'")
    value = int(seg[1:])
    if value > 0xFFFFFFFF:
        raise PathLexiconError(f"version segment must be v<N>, got '{seg}'")
    return value


def parse(path: str) -> dict:
    """ Parse and validate a derivation path, 1:1 with `path.rs::parse()`.
        Raises PathLexiconError on any violation. Returns a dict with keys
        role, chain_kind, chain_id, index, algorithm, version, leaf --
        mirroring `DerivationPath`'s fields (a dict rather than a dataclass
        since this validator has no building counterpart to round-trip
        against; `constants.root_path()` is this device's only builder and
        covers it with a pinned-output test instead). """
    if not path:
        raise PathLexiconError("derivation path must not be empty")
    if path.startswith("m/"):
        raise PathLexiconError(
            "derivation path must not start with 'm/' -- there is one grammar now, "
            f"and every path is absolute from the master seed (got '{path}')"
        )

    segments = path.split("/")
    for seg in segments:
        _validate_segment(seg)

    role_seg = segments[0]
    try:
        role = Role(role_seg)
    except ValueError:
        names = [r.value for r in Role]
        raise PathLexiconError(f"'{role_seg}' is not a known role (one of {names})")

    min_len, max_len = (6, 7) if role.is_chain_bound else (5, 6)
    if not (min_len <= len(segments) <= max_len):
        chain_id_part = "<chain-id>/" if role.is_chain_bound else ""
        leaf_part = "/<leaf>" if role.allows_leaf else ""
        raise PathLexiconError(
            f"{role.value} path must be {role.value}/<chain-kind>/{chain_id_part}<index>/"
            f"<algorithm>/v<N>{leaf_part}, got '{path}' "
            f"({len(segments)} segments, expected {min_len} or {max_len})"
        )

    chain_kind_seg = segments[1]
    if chain_kind_seg not in _VALID_CHAIN_KINDS:
        raise PathLexiconError(
            f"chain_kind segment must be one of {list(_VALID_CHAIN_KINDS)}, got '{chain_kind_seg}'"
        )
    chain_kind = _VALID_CHAIN_KINDS[chain_kind_seg]

    # L2 has no devnet -- the one check that cannot be bypassed, because
    # every derivation comes through here.
    if role.is_l2 and chain_kind == ChainKind.DEVNET:
        raise PathLexiconError(f"L2 has no devnet -- '{role.value}' cannot be derived on devnet")

    i = 2
    chain_id = None
    if role.is_chain_bound:
        chain_id = _parse_u32(segments[i], "chain-id")
        i += 1

    index = _parse_u32(segments[i], "index")
    i += 1

    algorithm_seg = segments[i]
    try:
        algorithm = Algorithm(algorithm_seg)
    except ValueError:
        names = [a.value for a in Algorithm]
        raise PathLexiconError(f"'{algorithm_seg}' is not a known algorithm (one of {names})")
    i += 1

    version = _parse_version(segments[i])
    i += 1

    leaf = None
    if i < len(segments):
        leaf_seg = segments[i]
        try:
            leaf = Leaf(leaf_seg)
        except ValueError:
            names = [l.value for l in Leaf]
            raise PathLexiconError(f"'{leaf_seg}' is not a known leaf label (one of {names})")
        if not role.allows_leaf:
            raise PathLexiconError(
                f"'{leaf.value}' is a leaf label, which only 'miner' may carry -- "
                f"'{role.value}' has one key, so a label there would name nothing"
            )

    return {
        "role": role,
        "chain_kind": chain_kind,
        "chain_id": chain_id,
        "index": index,
        "algorithm": algorithm,
        "version": version,
        "leaf": leaf,
    }


def validate(path: str) -> None:
    """ Validate a path without keeping the parse. """
    parse(path)
