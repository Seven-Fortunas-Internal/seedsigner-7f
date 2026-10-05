"""
    Template ChainPlugin -- copy this directory to chains/<new_chain>/, rename the
    class, fill in every method below, and register it in chains/__init__.py's
    _register_builtin_plugins(). Keeps each new chain additive (a new directory) and
    its review surface small and consistent, rather than a refactor of shared code --
    see docs/multi-chain/README.md's "Architecture: chain-plugin model".

    Not itself registered -- this module is a copy source, not a usable plugin.

    READ THIS BEFORE FILLING IN derive_address() OR sign() (added 2026-10-05,
    multi-chain-chainregistry-no-security-review): both methods take a bare `path:
    str` with no built-in guarantee it belongs to YOUR chain's namespace. You must
    validate that yourself, in both methods, unconditionally -- not only when the
    path's origin looks untrusted. EvmPlugin needed exactly this after adversarial
    review found that a scanned eth-sign-request's attacker-controlled derivation
    path could otherwise name ANY BIP-32 path on the same seed, including a path
    used for a DIFFERENT chain -- turning sign() into a general-purpose signing
    oracle over the whole seed instead of one scoped to EVM. See
    chains/evm/plugin.py's validate_derivation_path() for a concrete pattern to
    follow (a strict regex on your chain's own purpose/coin-type/account shape,
    called from both derive_address() and sign() before touching seed_bytes). Also
    register your plugin with ChainRegistry.register() -- it now raises if your
    class doesn't implement every method/attribute here, or if your chain_id
    collides with an already-registered one, so an incomplete implementation fails
    at import time rather than deep inside a live signing flow.
"""
from seedsigner.chains.base import Address, ParsedRequest, Signature


class TemplatePlugin:
    chain_id = "template"
    display_name = "Template (not a real chain)"

    def derive_address(self, seed_bytes: bytes, path: str) -> Address:
        raise NotImplementedError  # validate path is in YOUR namespace first -- see module docstring

    def parse_sign_request(self, payload: bytes) -> ParsedRequest:
        raise NotImplementedError

    def review_fields(self, parsed: ParsedRequest) -> list:
        raise NotImplementedError

    def sign(self, seed_bytes: bytes, path: str, payload: bytes) -> Signature:
        raise NotImplementedError  # validate path is in YOUR namespace first -- see module docstring

    def encode_response(self, signature: Signature) -> bytes:
        raise NotImplementedError
