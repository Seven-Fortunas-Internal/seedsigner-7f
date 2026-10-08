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
    DevfundRecipient,
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


def test_round_trip_address():
    recipient = DevfundRecipient(DevfundRecipient.ADDRESS, "t1devfundexampleaddress")
    bytes_ = build_canonical_bytes(ChainKind.TESTNET, recipient, 12_345, 1_790_555_198)
    fields = parse_canonical_bytes(bytes_)
    assert fields.network == ChainKind.TESTNET
    assert fields.recipient == recipient
    assert fields.effective_block == 12_345
    assert fields.timestamp == 1_790_555_198


def test_round_trip_multisig():
    recipient = DevfundRecipient(DevfundRecipient.MULTISIG, "ab" * 64)
    bytes_ = build_canonical_bytes(ChainKind.TESTNET, recipient, 12_345, 1_790_555_198)
    fields = parse_canonical_bytes(bytes_)
    assert fields.recipient == recipient


@pytest.mark.parametrize("network", [ChainKind.MAINNET, ChainKind.TESTNET, ChainKind.DEVNET])
def test_round_trip_all_networks(network):
    recipient = DevfundRecipient(DevfundRecipient.ADDRESS, "d1anotherexampleaddress")
    bytes_ = build_canonical_bytes(network, recipient, 0, 1_790_555_198)
    fields = parse_canonical_bytes(bytes_)
    assert fields.network == network


def test_matches_the_real_reference_vector_address():
    """ Cross-checks this Python bridge against the exact same real
        reference vector firmware/mldsa7f/src/devfund_config.rs's own test
        module pins (extracted directly from sf-core's real
        devfund_config_canonical_bytes(), not guessed) -- confirms the
        ctypes marshalling itself, not just that Python and Rust agree with
        each other in isolation. """
    recipient = DevfundRecipient(DevfundRecipient.ADDRESS, "t1devfundexampleaddressxxxxxxxxxxxxxxxxxxx")
    bytes_ = build_canonical_bytes(ChainKind.TESTNET, recipient, 12_345, 1_790_555_198)
    expected_hex = "64657666756e642d636f6e666967020007746573746e657401002a743164657666756e646578616d706c6561646472657373787878787878787878787878787878787878780000000000003039000000006ab9b43e"
    assert bytes_.hex() == expected_hex


def test_matches_the_real_reference_vector_multisig():
    recipient = DevfundRecipient(DevfundRecipient.MULTISIG, "ab" * 64)
    bytes_ = build_canonical_bytes(ChainKind.TESTNET, recipient, 12_345, 1_790_555_198)
    expected_hex = "64657666756e642d636f6e666967020007746573746e657402008061626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261620000000000003039000000006ab9b43e"
    assert bytes_.hex() == expected_hex


def test_parse_rejects_garbage():
    with pytest.raises(DevFundConfigError):
        parse_canonical_bytes(b"not a devfund config at all")


def test_parse_rejects_garbage_with_an_actionable_message():
    """ Regression test for 7f-review-parse-failure-messages-not-
        actionable: this used to render as a bare "mldsa7f devfund-config
        parse_canonical_bytes failed with code 3" shown straight to the
        operator, unlike genesis_config.py's own field-level
        differentiation. """
    with pytest.raises(DevFundConfigError) as exc_info:
        parse_canonical_bytes(b"not a devfund config at all")
    message = str(exc_info.value)
    assert "ERR_PARSE_FAILED" in message
    assert "domain tag" in message
    assert "failed with code" not in message  # the old bare-code phrasing


def test_parse_rejects_the_retired_v1_shape():
    """ The exact bytes this bridge used to produce before the v2 re-port --
        must now be refused, not silently misparsed under the new layout. """
    v1_bytes = (
        b"devfund-config" + bytes([1]) + b"testnet" + b"t1devfundexampleaddress"
        + (12_345).to_bytes(8, "big") + (1_790_555_198).to_bytes(8, "big")
    )
    with pytest.raises(DevFundConfigError):
        parse_canonical_bytes(v1_bytes)


def test_review_fields_covers_every_signed_field():
    recipient = DevfundRecipient(DevfundRecipient.ADDRESS, "t1devfundexampleaddress")
    fields = parse_canonical_bytes(
        build_canonical_bytes(ChainKind.TESTNET, recipient, 12_345, 1_790_555_198)
    )
    result = review_fields(fields)
    assert all(isinstance(f, ReviewField) for f in result)
    labels = [f.label for f in result]
    # + the canonical digest sf-wallet-gov prints (not a signed field itself)
    assert labels == ["Chain", "Recipient kind", "Recipient", "Effective block", "Timestamp", "Canonical digest"]
    values = {f.label: f.value for f in result}
    assert values["Chain"] == "testnet"
    assert values["Recipient kind"] == "Address"
    assert values["Recipient"] == "t1devfundexampleaddress"
    assert values["Effective block"] == "12345"


def test_review_fields_shows_multisig_kind():
    recipient = DevfundRecipient(DevfundRecipient.MULTISIG, "ab" * 64)
    fields = parse_canonical_bytes(
        build_canonical_bytes(ChainKind.TESTNET, recipient, 12_345, 1_790_555_198)
    )
    values = {f.label: f.value for f in review_fields(fields)}
    assert values["Recipient kind"] == "Multisig"
    assert values["Recipient"].replace(" ", "") == "ab" * 64  # shown grouped in fours so it wraps


def test_build_root_sig_json_matches_the_shared_rootsig_shape():
    """ Same {signer_vk, sig} shape genesis_config.py's own
        build_root_sig_json() produces -- confirmed against sf-core's real
        DevFundConfig.signatures doc comment ("Same shape and same rules as
        GenesisConfig::signatures"), not independently invented. """
    sig_json = build_root_sig_json(b"\xab" * 1952, b"\xcd" * 3309)
    assert sig_json == {"signer_vk": "", "sig": "cd" * 3309}

    sig_json_with_vk = build_root_sig_json(b"\xab" * 1952, b"\xcd" * 3309, with_vk=True)
    assert sig_json_with_vk["signer_vk"] == "ab" * 1952


# ─── parse_devfund_config_json: the coordinator's real artifact ──────────

# Byte-for-byte what `sf-root-coordinator prepare-devfund --chain-kind testnet
# --threshold 6 --vk ...x9` wrote at 7fchain 416f576 (2026-10-07 end-to-end
# run). `sf-wallet-gov sign-devfund` on this exact file printed
# `canonical digest 4216a1c800e3309b28b372c4fa3c290b` (SHA-256 of the signed
# bytes, first 16 bytes).
REAL_DEVFUND_UNSIGNED_JSON = b"""{
  "version": 2,
  "network": "testnet",
  "recipient": {
    "kind": "multisig",
    "commitment": "11dab78bc023fa02f2d60db1e5deb9e702836ff2b609d30e74b1b808983d361a7a83b8583bae657e7aabe3fd3be4f01ca64caea839faa207c7a7da4253a41ddc"
  },
  "effective_block": 0,
  "timestamp": 1791425505,
  "signatures": []
}"""
REAL_DEVFUND_DIGEST = "4216a1c800e3309b28b372c4fa3c290b"


def _json(**overrides) -> bytes:
    import json
    obj = json.loads(REAL_DEVFUND_UNSIGNED_JSON)
    for key, value in overrides.items():
        if value is _DROP:
            obj.pop(key, None)
        else:
            obj[key] = value
    return json.dumps(obj).encode()


_DROP = object()


def _real_address() -> str:
    from seedsigner.models.sevenf.root_ceremony import derive_root_ceremony_keys
    return derive_root_ceremony_keys(b"\x2a" * 64, ChainKind.TESTNET, index=0).root_ca.address


def test_parses_the_real_coordinator_file():
    from seedsigner.models.sevenf.devfund_config import parse_devfund_config_json
    fields = parse_devfund_config_json(REAL_DEVFUND_UNSIGNED_JSON)
    assert fields.network == ChainKind.TESTNET
    assert fields.recipient.tag == DevfundRecipient.MULTISIG
    assert fields.recipient.payload.startswith("11dab78bc023fa02")
    assert fields.effective_block == 0
    assert fields.timestamp == 1791425505


def test_canonical_bytes_from_the_real_file_match_sf_wallet_gov_digest():
    """ The bytes this device signs are exactly the bytes sf-wallet-gov signs
        for the same file -- pinned to the digest it printed, not recomputed by
        the code under test. """
    import hashlib
    from seedsigner.models.sevenf.devfund_config import parse_devfund_config_json
    f = parse_devfund_config_json(REAL_DEVFUND_UNSIGNED_JSON)
    canonical = build_canonical_bytes(f.network, f.recipient, f.effective_block, f.timestamp)
    assert hashlib.sha256(canonical).hexdigest()[:32] == REAL_DEVFUND_DIGEST


def test_accepts_a_valid_address_recipient_including_a_trailing_comment():
    """ sf-core clean_address(): a trailing `# comment` is tolerated and stripped
        before decoding, but stays part of what the Roots sign. """
    from seedsigner.models.sevenf.devfund_config import parse_devfund_config_json
    address = _real_address()
    for payload in (address, f"{address}  # dev fund, rotation 0"):
        fields = parse_devfund_config_json(_json(recipient={"kind": "address", "address": payload}))
        assert fields.recipient.tag == DevfundRecipient.ADDRESS
        assert fields.recipient.payload == payload


@pytest.mark.parametrize("overrides, needle", [
    (dict(version=1), "version"),
    (dict(version="2"), "version"),
    (dict(version=True), "version"),
    (dict(network="Testnet"), "network"),
    (dict(network=""), "network"),
    (dict(network=_DROP), "network"),
    (dict(recipient=_DROP), "recipient"),
    (dict(recipient="11dab78b"), "recipient"),
    (dict(recipient={"kind": "treasury", "commitment": "00" * 64}), "kind"),
    (dict(recipient={"kind": "multisig"}), "commitment"),
    (dict(recipient={"kind": "multisig", "commitment": "ab" * 63}), "128"),
    (dict(recipient={"kind": "multisig", "commitment": "zz" * 64}), "hex"),
    (dict(recipient={"kind": "address"}), "address"),
    (dict(recipient={"kind": "address", "address": "t1notarealaddress"}), "address"),
    (dict(recipient={"kind": "address", "address": "# only a comment"}), "address"),
    (dict(effective_block=-1), "effective_block"),
    (dict(effective_block=2**64), "effective_block"),
    (dict(effective_block=True), "effective_block"),
    (dict(timestamp=0), "timestamp"),
    (dict(timestamp="1791425505"), "timestamp"),
    (dict(signatures={}), "signatures"),
    (dict(signatures=[{"sig": "00"}]), "signatures"),
])
def test_refuses_what_sign_devfund_refuses(overrides, needle):
    """ Mirrors sf-wallet-gov validate_devfund() + DevfundRecipient::validate()
        + serde's own shape checks: refuse rather than sign. """
    from seedsigner.models.sevenf.devfund_config import DevFundConfigJsonError, parse_devfund_config_json
    with pytest.raises(DevFundConfigJsonError) as e:
        parse_devfund_config_json(_json(**overrides))
    assert needle in str(e.value)


def test_refuses_a_flipped_address_checksum():
    from seedsigner.models.sevenf.devfund_config import DevFundConfigJsonError, parse_devfund_config_json
    address = _real_address()
    flipped = address[:-1] + ("q" if address[-1] != "q" else "p")
    with pytest.raises(DevFundConfigJsonError, match="address"):
        parse_devfund_config_json(_json(recipient={"kind": "address", "address": flipped}))


@pytest.mark.parametrize("payload, needle", [
    (b"\xff\xfe", "UTF-8"),
    (b"not json", "JSON"),
    (b"[]", "object"),
    (b"[" * 100_000, "JSON"),
    (b'{"version": 1, "network": "testnet", "devfund_address": "t1abc", "effective_block": 0, "timestamp": 1}', "version-1"),
])
def test_refuses_malformed_payloads_cleanly(payload, needle):
    from seedsigner.models.sevenf.devfund_config import DevFundConfigJsonError, parse_devfund_config_json
    with pytest.raises(DevFundConfigJsonError) as e:
        parse_devfund_config_json(payload)
    assert needle in str(e.value)


def test_canonical_bytes_are_refused_with_a_clear_message():
    """ The old scan input (raw canonical bytes) is not what the coordinator
        sends; refuse it rather than guess. """
    from seedsigner.models.sevenf.devfund_config import DevFundConfigJsonError, parse_devfund_config_json
    f_canonical = build_canonical_bytes(ChainKind.TESTNET, DevfundRecipient(DevfundRecipient.MULTISIG, "ab" * 64), 0, 1)
    with pytest.raises(DevFundConfigJsonError):
        parse_devfund_config_json(f_canonical)


def test_an_outdated_library_refuses_an_address_recipient_cleanly(monkeypatch):
    """ A library built before mldsa7f_address_validate existed must produce a
        clean refusal, not an AttributeError reaching the operator. """
    from seedsigner.models.sevenf import devfund_config as dc

    def missing(*a, **kw):
        raise AttributeError("undefined symbol: mldsa7f_address_validate")

    monkeypatch.setattr(dc, "register_argtypes", missing)
    with pytest.raises(dc.DevFundConfigJsonError, match="too old"):
        dc.parse_devfund_config_json(_json(recipient={"kind": "address", "address": _real_address()}))


@pytest.mark.parametrize("commitment", [
    "11 " + "ab" * 62 + " ",          # spaces: Python bytes.fromhex skips them, Rust hex::decode refuses
    "ab" * 63 + "a\n",                # trailing newline
    "ab" * 63 + "a١",            # a non-ASCII digit
])
def test_refuses_a_commitment_rust_hex_decode_refuses(commitment):
    from seedsigner.models.sevenf.devfund_config import DevFundConfigJsonError, parse_devfund_config_json
    assert len(commitment) == 128
    with pytest.raises(DevFundConfigJsonError, match="hex"):
        parse_devfund_config_json(_json(recipient={"kind": "multisig", "commitment": commitment}))


def test_accepts_an_uppercase_hex_commitment():
    """ hex::decode accepts uppercase; the payload is signed as written. """
    from seedsigner.models.sevenf.devfund_config import parse_devfund_config_json
    upper = "AB" * 64
    assert parse_devfund_config_json(_json(recipient={"kind": "multisig", "commitment": upper})).recipient.payload == upper


def test_refuses_an_address_with_control_characters():
    """ Python str.strip() also strips \\x1c-\\x1f; Rust str::trim does not, so
        sf-core would hand them to Address::decode and refuse. """
    from seedsigner.models.sevenf.devfund_config import DevFundConfigJsonError, parse_devfund_config_json
    with pytest.raises(DevFundConfigJsonError, match="address"):
        parse_devfund_config_json(_json(recipient={"kind": "address", "address": "\x1c" + _real_address()}))


@pytest.mark.parametrize("payload", [
    REAL_DEVFUND_UNSIGNED_JSON.replace(b'"signatures": []', b'"signatures": [], "x": NaN'),
    REAL_DEVFUND_UNSIGNED_JSON.replace(b'"timestamp": 1791425505', b'"timestamp": 1, "timestamp": 1791425505'),
])
def test_refuses_json_serde_json_refuses(payload):
    """ serde_json refuses NaN/Infinity literals and duplicate struct keys;
        Python's json module accepts both by default. """
    from seedsigner.models.sevenf.devfund_config import DevFundConfigJsonError, parse_devfund_config_json
    with pytest.raises(DevFundConfigJsonError):
        parse_devfund_config_json(payload)
