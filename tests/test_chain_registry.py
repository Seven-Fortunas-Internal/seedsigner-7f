"""
    Tests for ChainRegistry itself (seedsigner.chains.__init__) as a mechanism --
    the one shared cross-chain trust boundary every plugin (Bitcoin excluded; see
    below) registers against. Filed 2026-10-05 after a security review
    (multi-chain-chainregistry-no-security-review) found this boundary had zero
    dedicated test coverage -- only "does get() return something" smoke tests
    existed (test_flows_evm.py, test_sevenf_plugin.py).

    Bitcoin is NOT a ChainPlugin and never registers here -- it's handled entirely
    by pre-existing legacy SeedSigner code gated by literal Controller.active_chain_id
    string comparisons, a separate system this registry doesn't touch.
"""
import pytest

from seedsigner.chains import ChainRegistry
from seedsigner.chains.base import Address, ParsedRequest, Signature


@pytest.fixture(autouse=True)
def _restore_chain_registry():
    """ ChainRegistry._plugins is a class-level singleton dict shared across the
        whole test session -- registering a test double in it would leak into
        every other test file. Snapshot and restore around each test here. """
    original = dict(ChainRegistry._plugins)
    yield
    ChainRegistry._plugins.clear()
    ChainRegistry._plugins.update(original)


class _CompletePlugin:
    """ Implements every ChainPlugin method/attribute -- a valid registration. """
    chain_id = "test-complete"
    display_name = "Test Complete"

    def derive_address(self, seed_bytes: bytes, path: str) -> Address:
        return Address(path=path, address="0xtest", network_name="")

    def parse_sign_request(self, payload: bytes) -> ParsedRequest:
        return ParsedRequest(operation="test", network_name="", derivation_path="m/0")

    def review_fields(self, parsed: ParsedRequest) -> list:
        return []

    def sign(self, seed_bytes: bytes, path: str, payload: bytes) -> Signature:
        return Signature(signature_bytes=b"")

    def encode_response(self, signature: Signature) -> bytes:
        return b""


class _IncompletePlugin:
    """ Missing encode_response() entirely -- exactly the "author's test flow never
        reached QR export" scenario the security review named. """
    chain_id = "test-incomplete"
    display_name = "Test Incomplete"

    def derive_address(self, seed_bytes: bytes, path: str) -> Address:
        return Address(path=path, address="0xtest", network_name="")

    def parse_sign_request(self, payload: bytes) -> ParsedRequest:
        return ParsedRequest(operation="test", network_name="", derivation_path="m/0")

    def review_fields(self, parsed: ParsedRequest) -> list:
        return []

    def sign(self, seed_bytes: bytes, path: str, payload: bytes) -> Signature:
        return Signature(signature_bytes=b"")


def test_register_accepts_a_structurally_complete_plugin():
    ChainRegistry.register(_CompletePlugin())
    assert ChainRegistry.get("test-complete").chain_id == "test-complete"


def test_register_refuses_a_structurally_incomplete_plugin():
    with pytest.raises(TypeError, match="does not implement the full ChainPlugin contract"):
        ChainRegistry.register(_IncompletePlugin())
    with pytest.raises(KeyError):
        ChainRegistry.get("test-incomplete")


def test_register_refuses_a_duplicate_chain_id():
    ChainRegistry.register(_CompletePlugin())
    with pytest.raises(ValueError, match="already registered"):
        ChainRegistry.register(_CompletePlugin())


def test_get_raises_on_an_unregistered_chain_id():
    with pytest.raises(KeyError):
        ChainRegistry.get("not-a-real-chain")


def test_chain_registry_has_evm_and_sevenf_plugins_registered():
    # The real, current registration set -- Bitcoin is deliberately absent (see
    # module docstring); this is the baseline all() should reflect before any test
    # double is added.
    chain_ids = {p.chain_id for p in ChainRegistry.all()}
    assert {"evm", "sevenf"} <= chain_ids
