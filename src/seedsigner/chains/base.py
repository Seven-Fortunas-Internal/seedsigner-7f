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
from typing import Protocol


@dataclass
class Address:
    """A derived receive/signing address for some chain."""
    path: str
    address: str
    network_name: str


@dataclass
class ReviewField:
    """
        One field on a paged no-blind-signing review screen. `is_warning` marks a
        hard-stop item (e.g. an unlimited approval) that review UI should render
        distinctly from an ordinary informational field, not just another line item.
    """
    label: str
    value: str
    is_warning: bool = False
    warning_detail: str = ""


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


class ChainPlugin(Protocol):
    """
        One implementation per chain family (Bitcoin, EVM, Tron, ...), registered in
        ChainRegistry keyed by chain_id. See chains/_template/ for a stub
        implementation to copy when adding a new chain.
    """
    chain_id: str          # e.g. "btc", "evm", "tron" -- short, stable, used as the registry key
    display_name: str      # e.g. "Ethereum / EVM" -- shown in the chain-selector menu

    def derive_address(self, seed_bytes: bytes, path: str) -> Address:
        """Derive a receive/signing address for this chain at the given path."""
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
        """Sign the payload. The secret key must never leave this call's scope."""
        ...

    def encode_response(self, signature: Signature) -> bytes:
        """Encode a signature for QR export."""
        ...
