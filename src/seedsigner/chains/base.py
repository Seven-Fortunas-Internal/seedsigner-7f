"""
    Multi-chain SeedSigner -- chain-plugin interface.

    Design doc: docs/multi-chain/README.md in the diy-seedsigner repo. Informed by a
    survey of 7 existing multi-chain hardware/cold wallets (AirGap, Keystone3, Trezor,
    Ledger, GridPlus, BitBox02, OneKey) -- every one of them splits a chain-agnostic
    core from per-chain modules with a registry locating the right one by chain ID.
    This module is that split's chain-agnostic contract.

    Every ChainPlugin method that touches what gets shown to the operator before
    signing exists to serve one non-negotiable rule, carried over from the 7F work and
    sharpened by anti-scam research (docs/multi-chain/research/anti-scam-ux.md):
    self-validation. A decoder (hand-written or a future ERC-7730 descriptor) only
    ever produces *proposed* display labels -- parse_sign_request() must independently
    recompute the fields that matter from the raw payload bytes, never just relay
    externally-supplied metadata. review_fields() is the concrete "no blind signing"
    mechanism: every field the operator needs to judge gets its own place in the list,
    including hard-stop warnings (e.g. an unlimited token approval) that a chain
    module must flag explicitly, not bury.
"""
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

# Re-exported, not defined here, as of 2026-10-03
# (7f-signing-support-models-chains-import-cycle fix) -- see
# models/review.py's own docstring for why: models/sevenf/* needs
# ReviewField without pulling in this package's __init__-time plugin
# registration. Every existing `from seedsigner.chains.base import
# ReviewField` call site (this re-export included) is unaffected.
from seedsigner.models.review import ReviewField


@dataclass
class Address:
    """A derived receive/signing address for some chain."""
    path: str
    address: str
    network_name: str


@dataclass
class ParsedRequest:
    """
        Generic container a plugin's parse_sign_request() fills in. Plugins are free
        to carry extra chain-specific fields beyond this base set (Python dataclasses
        don't support that directly -- plugins typically return their own dataclass
        that satisfies this shape via duck typing, not literal inheritance).
    """
    operation: str
    network_name: str
    derivation_path: str
    review_fields: list[ReviewField] = field(default_factory=list)


@dataclass
class Signature:
    signature_bytes: bytes
    public_key: bytes = b""


@runtime_checkable
class ChainPlugin(Protocol):
    """
        One implementation per chain family (Bitcoin, EVM, Tron, ...), registered in
        ChainRegistry keyed by chain_id. See chains/_template/ for a stub
        implementation to copy when adding a new chain.

        @runtime_checkable (added 2026-10-05, multi-chain-chainregistry-no-security-review):
        ChainRegistry.register() checks `isinstance(plugin, ChainPlugin)` before
        accepting a plugin, so a structurally incomplete implementation (e.g. a new
        chain's class missing encode_response() because its author's test flow never
        reached QR export) fails loudly at import/boot time instead of raising
        AttributeError deep into a live signing flow -- the worst possible place to
        discover it. This only checks that every listed method/attribute NAME exists,
        not its signature or behavior.

        Python version note (code-review finding, 2026-10-05): CPython hardened
        isinstance() against runtime-checkable Protocols in 3.12 (a pre-3.12
        object faking attribute presence via a catch-all __getattr__, e.g.
        unittest.mock.Mock(), could spuriously pass this check on 3.10/3.11, where
        3.12 correctly rejects it). This project's CI matrix includes 3.10
        (pyproject.toml's requires-python floor) and was verified against this
        exact check only on 3.12 -- not a live risk today since every real
        register() call site passes a hardcoded real plugin instance, never a
        mock, but don't assume this isinstance check is equally strict on every
        supported Python version if a future caller ever passes a duck-typed
        stand-in. Also: issubclass() raises TypeError on this Protocol (it has
        non-method members) -- use isinstance() only.

        Every method below that takes a `path: str` MUST validate that the path
        belongs to this plugin's own chain namespace before deriving a key or
        signing -- do this unconditionally, not only when the path's origin looks
        untrusted. This is not a style preference: EvmPlugin.sign() needed exactly
        this check (see its own validate_derivation_path() docstring) after
        adversarial review found that a scanned eth-sign-request's attacker-
        controlled derivation path could otherwise name ANY BIP-32 path on the same
        seed -- including a path used for a different chain -- turning sign() into a
        general-purpose signing oracle over the whole seed rather than one scoped to
        this chain. derive_address() needs the identical check for the identical
        reason; it is not exempt just because today's only attacker-reachable caller
        happens to wrap it in a broad try/except for an unrelated reason (a UI hint
        that must not crash on a malformed path) -- that caller's own exception
        handler is not a substitute for this plugin validating its own input.
    """
    chain_id: str          # e.g. "btc", "evm", "tron" -- short, stable, used as the registry key
    display_name: str      # e.g. "Ethereum / EVM" -- shown in the chain-selector menu

    def derive_address(self, seed_bytes: bytes, path: str) -> Address:
        """Derive a receive/signing address for this chain at the given path.
        Must validate that `path` belongs to this chain's own namespace -- see the
        class docstring's "every method... MUST validate" paragraph."""
        ...

    def parse_sign_request(self, payload: bytes) -> ParsedRequest:
        """
            Decode a raw sign-request payload into a structured, self-validated
            ParsedRequest. Must not trust any externally-supplied "friendly" label
            without independently recomputing it from the actual payload bytes --
            see the module docstring.
        """
        ...

    def review_fields(self, parsed: ParsedRequest) -> list[ReviewField]:
        """
            The no-blind-signing field list for this request, in display order.
            Usually just `parsed.review_fields`, but kept as its own method so a
            plugin can add request-type-specific ordering/filtering without changing
            how parsing works.
        """
        ...

    def sign(self, seed_bytes: bytes, path: str, payload: bytes) -> Signature:
        """Sign the payload. The secret key must never leave this call's scope.
        Must validate that `path` belongs to this chain's own namespace -- see the
        class docstring's "every method... MUST validate" paragraph."""
        ...

    def encode_response(self, signature: Signature) -> bytes:
        """Encode a signature for QR export."""
        ...
