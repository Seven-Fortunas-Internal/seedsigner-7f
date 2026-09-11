"""
    Cross-verifies chains/evm/ur_types.py against literal UR strings from the real
    reference implementation ERC-4527 itself names as authoritative
    (KeystoneHQ/keystone-sdk-base's `ur-registry-eth` test suite) -- not just internal
    round-trip self-consistency. If these ever stop matching, either this module has
    a real interop bug or the reference vectors moved; either way it needs eyes on it,
    not a silent test update.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from seedsigner.helpers.ur2.ur import UR
from seedsigner.helpers.ur2.ur_decoder import URDecoder
from seedsigner.helpers.ur2.ur_encoder import UREncoder
from seedsigner.chains.evm.ur_types import EthSignRequest, EthSignature, DATA_TYPE_TRANSACTION


# From KeystoneHQ/keystone-sdk-base packages/ur-registry-eth/__tests__/EthSignRequest.test.ts
# ("test should genereate eth-sign-reqeust"):
#   signData:        f849808609184e72a00082271094000000000000000000000000000000000000000080a47f7465737432000000000000000000000000000000000000000000000000000000600057808080
#   dataType:        DataType.transaction (1)
#   chainId:         1
#   derivationPath:  M/44'/1'/1'/0/1, xfp 12345678
#   requestId:       9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d
#   origin:          "metamask"
REFERENCE_SIGN_REQUEST_UR = "ur:eth-sign-request/oladtpdagdndcawmgtfrkigrpmndutdnbtkgfssbjnaohdgryagalalnascsgljpnbaelfdibemwaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaelaoxlbjyihjkjyeyaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaehnaehglalalaaxadaaadahtaaddyoeadlecsdwykadykadykaewkadwkaocybgeehfksatisjnihjyhsjnhsjkjetlnndant"
REFERENCE_SIGN_REQUEST_SIGN_DATA = bytes.fromhex("f849808609184e72a00082271094000000000000000000000000000000000000000080a47f7465737432000000000000000000000000000000000000000000000000000000600057808080")
REFERENCE_SIGN_REQUEST_ID = bytes.fromhex("9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d")

# From EthSignature.test.ts:
#   signature: 65 real bytes (r,s,v), requestId same UUID as above, origin "keystone"
REFERENCE_SIGNATURE_UR = "ur:eth-signature/otadtpdagdndcawmgtfrkigrpmndutdnbtkgfssbjnaohdfptywtosrftahprdctrkbegylogdghjkbafhflamfwlohghtpsseaozorsimnybbtnnbiynlckenbtfmeeamsabnaeoxasjkwswfkekiieckhpecckssptndzelnwfecylbwaxisjeihkkjkjyjljtihdwlkamiy"
REFERENCE_SIGNATURE_BYTES = bytes.fromhex("d4f0a7bcd95bba1fbb1051885054730e3f47064288575aacc102fbbf6a9a14daa066991e360d3e3406c20c00a40973eff37c7d641e5b351ec4a99bfe86f335f713")
REFERENCE_SIGNATURE_ID = bytes.fromhex("9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d")


def _decode_ur(ur_string: str) -> UR:
    decoder = URDecoder()
    decoder.receive_part(ur_string)
    assert decoder.is_complete()
    return decoder.result


def test_decodes_real_reference_eth_sign_request():
    """ The direction that actually matters in production: a real MetaMask/Keystone
        -produced request, decoded field-for-field. """
    ur = _decode_ur(REFERENCE_SIGN_REQUEST_UR)
    assert ur.type == "eth-sign-request"

    req = EthSignRequest.from_cbor(ur.cbor)
    assert req.sign_data == REFERENCE_SIGN_REQUEST_SIGN_DATA
    assert req.data_type == DATA_TYPE_TRANSACTION
    assert req.chain_id == 1
    assert req.derivation_path == "m/44'/1'/1'/0/1"
    assert req.request_id == REFERENCE_SIGN_REQUEST_ID
    assert req.address is None
    assert req.origin == "metamask"


def test_decodes_real_reference_eth_signature():
    ur = _decode_ur(REFERENCE_SIGNATURE_UR)
    assert ur.type == "eth-signature"

    sig = EthSignature.from_cbor(ur.cbor)
    assert sig.request_id == REFERENCE_SIGNATURE_ID
    assert sig.signature == REFERENCE_SIGNATURE_BYTES
    assert len(sig.signature) == 65
    assert sig.origin == "keystone"


def test_encodes_eth_signature_byte_identical_to_reference():
    """ The direction that actually matters in production the other way: our device
        is the one producing eth-signature. Confirms our encoder is byte-identical
        to the real reference implementation's output for the same inputs -- not
        just "decodes back to itself", which could pass even with a
        real-world-incompatible encoding. """
    sig = EthSignature(request_id=REFERENCE_SIGNATURE_ID, signature=REFERENCE_SIGNATURE_BYTES, origin="keystone")
    cbor = bytes(sig.to_cbor())

    reference_ur = _decode_ur(REFERENCE_SIGNATURE_UR)
    assert cbor == reference_ur.cbor

    # And the full UR-encoded string matches too, not just the CBOR body.
    qr_ur = UR("eth-signature", cbor)
    encoder = UREncoder(ur=qr_ur, max_fragment_len=200)
    assert encoder.next_part().upper() == REFERENCE_SIGNATURE_UR.upper()


def test_eth_sign_request_round_trips_through_our_own_encoder():
    """ eth-sign-request is only ever decoded in production (we never send one), but
        round-tripping our own encoder->decoder confirms to_data_item/from_data_item
        are each other's true inverse, not just that decode happens to work on
        someone else's bytes. """
    req = EthSignRequest(
        sign_data=b"\x02\x01\x02\x03",
        data_type=4,
        chain_id=10,
        derivation_path="m/44'/60'/0'/0/1",
        request_id=b"\x01" * 16,
        address=bytes.fromhex("be7c7f2a6ac45ff26cb8324728910af34c2cd21f"),
        origin="rabby",
    )
    decoded = EthSignRequest.from_cbor(req.to_cbor())

    assert decoded.sign_data == req.sign_data
    assert decoded.data_type == req.data_type
    assert decoded.chain_id == req.chain_id
    assert decoded.derivation_path == req.derivation_path
    assert decoded.request_id == req.request_id
    assert decoded.address == req.address
    assert decoded.origin == req.origin


def test_eth_sign_request_optional_fields_omitted_when_absent():
    """ request-id/address/origin are all optional per the spec -- confirms omitting
        them doesn't crash and decodes back as None, not some sentinel/default. """
    req = EthSignRequest(sign_data=b"\x02", data_type=4, chain_id=10, derivation_path="m/44'/60'/0'/0/0")
    decoded = EthSignRequest.from_cbor(req.to_cbor())

    assert decoded.request_id is None
    assert decoded.address is None
    assert decoded.origin is None
