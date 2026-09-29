"""
    Tests seedsigner.models.sevenf.devfund_config -- the ctypes bridge to
    firmware/mldsa7f's devfund-config canonical-bytes build/parse functions.
    Backs 7f-signing-support-devfund-config-signing.

    Requires firmware/mldsa7f's compiled library (see test_sevenf_mldsa.py's
    own docstring for the search order); skips cleanly if it's missing.
"""
import pytest

from seedsigner.chains.base import ReviewField
from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf.constants import ChainKind
from seedsigner.models.sevenf.devfund_config import (
    DevFundConfigError,
    build_canonical_bytes,
    build_root_sig_json,
    parse_canonical_bytes,
    review_fields,
)


def _lib_available() -> bool:
    try:
        mldsa._lib_handle()
        return True
    except FileNotFoundError:
        return False


pytestmark = pytest.mark.skipif(
    not _lib_available(),
    reason="firmware/mldsa7f not built -- run `cargo build --release` in firmware/mldsa7f/ first",
)


def test_round_trip():
    bytes_ = build_canonical_bytes(ChainKind.TESTNET, "t1devfundexampleaddress", 12_345, 1_790_555_198)
    fields = parse_canonical_bytes(bytes_)
    assert fields.network == ChainKind.TESTNET
    assert fields.devfund_address == "t1devfundexampleaddress"
    assert fields.effective_block == 12_345
    assert fields.timestamp == 1_790_555_198


@pytest.mark.parametrize("network", [ChainKind.MAINNET, ChainKind.TESTNET, ChainKind.DEVNET])
def test_round_trip_all_networks(network):
    bytes_ = build_canonical_bytes(network, "d1anotherexampleaddress", 0, 1_790_555_198)
    fields = parse_canonical_bytes(bytes_)
    assert fields.network == network


def test_matches_the_real_reference_vector():
    """ Cross-checks this Python bridge against the exact same real
        reference vector firmware/mldsa7f/src/devfund_config.rs's own test
        module pins (extracted directly from sf-core's real
        devfund_config_canonical_bytes(), not guessed) -- confirms the
        ctypes marshalling itself, not just that Python and Rust agree with
        each other in isolation. """
    bytes_ = build_canonical_bytes(
        ChainKind.TESTNET, "t1devfundexampleaddressxxxxxxxxxxxxxxxxxxx", 12_345, 1_790_555_198,
    )
    expected_hex = "64657666756e642d636f6e66696701746573746e6574743164657666756e646578616d706c6561646472657373787878787878787878787878787878787878780000000000003039000000006ab9b43e"
    assert bytes_.hex() == expected_hex
    assert len(bytes_) == 80


def test_parse_rejects_garbage():
    with pytest.raises(DevFundConfigError):
        parse_canonical_bytes(b"not a devfund config at all")


def test_review_fields_covers_every_signed_field():
    fields = parse_canonical_bytes(
        build_canonical_bytes(ChainKind.TESTNET, "t1devfundexampleaddress", 12_345, 1_790_555_198)
    )
    result = review_fields(fields)
    assert all(isinstance(f, ReviewField) for f in result)
    labels = [f.label for f in result]
    assert labels == ["Network", "Devfund address", "Effective block", "Timestamp"]
    values = {f.label: f.value for f in result}
    assert values["Network"] == "testnet"
    assert values["Devfund address"] == "t1devfundexampleaddress"
    assert values["Effective block"] == "12345"


def test_build_root_sig_json_matches_the_shared_rootsig_shape():
    """ Same {signer_vk, sig} shape genesis_config.py's own
        build_root_sig_json() produces -- confirmed against sf-core's real
        DevFundConfig.signatures doc comment ("Same shape and same rules as
        GenesisConfig::signatures"), not independently invented. """
    sig_json = build_root_sig_json(b"\xab" * 1952, b"\xcd" * 3309)
    assert sig_json == {"signer_vk": "", "sig": "cd" * 3309}

    sig_json_with_vk = build_root_sig_json(b"\xab" * 1952, b"\xcd" * 3309, with_vk=True)
    assert sig_json_with_vk["signer_vk"] == "ab" * 1952
