"""
    Template ChainPlugin -- copy this directory to chains/<new_chain>/, rename the
    class, fill in every method below, and register it in chains/__init__.py's
    _register_builtin_plugins(). Keeps each new chain additive (a new directory) and
    its review surface small and consistent, rather than a refactor of shared code --
    see docs/multi-chain/README.md's "Architecture: chain-plugin model".

    Not itself registered -- this module is a copy source, not a usable plugin.
"""
from seedsigner.chains.base import Address, ParsedRequest, Signature


class TemplatePlugin:
    chain_id = "template"
    display_name = "Template (not a real chain)"

    def derive_address(self, seed_bytes: bytes, path: str) -> Address:
        raise NotImplementedError

    def parse_sign_request(self, payload: bytes) -> ParsedRequest:
        raise NotImplementedError

    def review_fields(self, parsed: ParsedRequest) -> list:
        raise NotImplementedError

    def sign(self, seed_bytes: bytes, path: str, payload: bytes) -> Signature:
        raise NotImplementedError

    def encode_response(self, signature: Signature) -> bytes:
        raise NotImplementedError
