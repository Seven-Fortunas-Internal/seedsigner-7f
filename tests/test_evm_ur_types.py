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
from seedsigner.chains.evm.ur_types import EthSignRequest, EthSignature, DATA_TYPE_TRANSACTION, build_account_hdkey_cbor


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

# From KeystoneHQ/Keystone-developer-hub's research/ethereum-qr-data-protocol.md
# ("Crypto-HDKey Example"): a real Keystone-produced account-level (M/44'/60'/0')
# extended public key, master fingerprint cfc23f3f. This is the "Connect" QR shape
# build_account_hdkey_cbor() targets -- only key/chain_code/origin are set, no
# use_info/parent_fingerprint/depth (see chains/evm/ur_types.py's module docstring).
REFERENCE_ACCOUNT_HDKEY_CBOR = bytes.fromhex("A303582103DA1A04CC1509CD716E215F1C8A3D1530A6B4EFDACB04D1641EAA117342EFA4B1045820FDCA62CADED4C32CD914A3CEF84529504BC534C721997E196BE421162F3EB81D06D90130A20186182CF5183CF500F5021ACFC23F3F")
REFERENCE_ACCOUNT_HDKEY_PUBKEY = bytes.fromhex("03da1a04cc1509cd716e215f1c8a3d1530a6b4efdacb04d1641eaa117342efa4b1")
REFERENCE_ACCOUNT_HDKEY_CHAIN_CODE = bytes.fromhex("fdca62caded4c32cd914a3cef84529504bc534c721997e196be421162f3eb81d")
REFERENCE_ACCOUNT_HDKEY_FINGERPRINT = bytes.fromhex("cfc23f3f")


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


def test_decodes_real_reference_account_hdkey():
    """ Confirms `urtypes.crypto.HDKey` (generic, not homegrown here) parses a real
        Keystone-produced ETH account-hdkey correctly, and -- the part that actually
        matters for interop -- that the real example sets only key/chain_code/origin,
        nothing else. This is the target shape build_account_hdkey_cbor() below must
        match; if a real requester ever starts expecting more, this test is the one
        that should catch the mismatch. """
    from urtypes.crypto import HDKey as UrHDKey

    hd = UrHDKey.from_cbor(REFERENCE_ACCOUNT_HDKEY_CBOR)

    assert hd.key == REFERENCE_ACCOUNT_HDKEY_PUBKEY
    assert hd.chain_code == REFERENCE_ACCOUNT_HDKEY_CHAIN_CODE
    assert [(c.index, c.hardened) for c in hd.origin.components] == [(44, True), (60, True), (0, True)]
    assert hd.origin.source_fingerprint == REFERENCE_ACCOUNT_HDKEY_FINGERPRINT
    assert hd.origin.depth is None
    assert hd.use_info is None
    assert hd.parent_fingerprint is None


def test_build_account_hdkey_cbor_matches_real_shape_and_embit_directly():
    """ Two things at once, both required for real interop: (1) our own encoder's
        output has the exact same field shape as the real reference example above
        (no extra/missing top-level keys), and (2) the key/chain_code/fingerprint it
        produces for a given seed are cross-verified against embit's own BIP-32
        derivation directly, not just "decodes back to itself". """
    from embit.bip32 import HDKey as Bip32HDKey
    from urtypes.crypto import HDKey as UrHDKey

    seed_bytes = b"\x07" * 64
    cbor = build_account_hdkey_cbor(seed_bytes, account=0)
    hd = UrHDKey.from_cbor(cbor)

    root = Bip32HDKey.from_seed(seed_bytes)
    account_pub = root.derive("m/44'/60'/0'").to_public()

    assert hd.key == account_pub.sec()
    assert hd.chain_code == account_pub.chain_code
    assert hd.origin.source_fingerprint == root.my_fingerprint
    assert [(c.index, c.hardened) for c in hd.origin.components] == [(44, True), (60, True), (0, True)]
    # Same absent-field shape as the real reference vector -- not this codebase's
    # own fuller Bitcoin UrXpubQrEncoder shape (which also sets parent_fingerprint).
    assert hd.origin.depth is None
    assert hd.use_info is None
    assert hd.parent_fingerprint is None


def test_build_account_hdkey_cbor_uses_the_requested_account():
    """ A non-zero account must actually change the derivation path and the
        resulting key -- not just be accepted and ignored. """
    from urtypes.crypto import HDKey as UrHDKey

    seed_bytes = b"\x09" * 64
    account_0 = UrHDKey.from_cbor(build_account_hdkey_cbor(seed_bytes, account=0))
    account_1 = UrHDKey.from_cbor(build_account_hdkey_cbor(seed_bytes, account=1))

    assert [(c.index, c.hardened) for c in account_1.origin.components] == [(44, True), (60, True), (1, True)]
    assert account_0.key != account_1.key
