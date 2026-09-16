"""
    Cross-verifies chains/evm/rlp_codec.py (our hand-rolled RLP encoder/decoder,
    replacing the third-party `rlp` package as a runtime dependency -- see that
    module's docstring for why) against `rlp` itself, kept as a test-only
    dependency specifically for this. Also covers the classic RLP spec test
    vectors and malformed/non-canonical inputs a fuzzer or attacker might try,
    since a wrong decode here could mean signing a different hash than what was
    reviewed (docs/multi-chain/README.md's self-validation principle) -- this is
    the codebase's most safety-critical piece of hand-rolled parsing.
"""
import rlp as reference_rlp
import pytest
from hypothesis import given, settings, strategies as st

from seedsigner.chains.evm.rlp_codec import RlpDecodingError, _MAX_DEPTH, rlp_decode, rlp_encode


# --- Cross-verification against the reference `rlp` package ---

ENCODE_CASES = [
    b"",
    b"\x00",
    b"\x7f",
    b"\x80",
    b"dog",
    b"a" * 55,
    b"a" * 56,
    b"a" * 1000,
    [],
    [b"cat", b"dog"],
    [[], [[]], [[], [[]]]],  # the classic RLP spec example
    [b"\x00" * 32, b"\x01" * 32, [], b""],  # shape of an actual EIP-1559 field list
]


@pytest.mark.parametrize("item", ENCODE_CASES)
def test_encode_matches_reference(item):
    assert rlp_encode(item) == reference_rlp.encode(item)


@pytest.mark.parametrize("item", ENCODE_CASES)
def test_decode_matches_reference(item):
    encoded = reference_rlp.encode(item)
    assert rlp_decode(encoded) == reference_rlp.decode(encoded)


@pytest.mark.parametrize("item", ENCODE_CASES)
def test_round_trip(item):
    assert rlp_decode(rlp_encode(item)) == item


# --- Known RLP spec test vectors (ethereum.org's own worked examples) ---

def test_known_vector_empty_string():
    assert rlp_encode(b"") == bytes([0x80])


def test_known_vector_dog():
    assert rlp_encode(b"dog") == bytes([0x83]) + b"dog"


def test_known_vector_cat_dog_list():
    assert rlp_encode([b"cat", b"dog"]) == bytes([0xC8, 0x83]) + b"cat" + bytes([0x83]) + b"dog"


def test_known_vector_empty_list():
    assert rlp_encode([]) == bytes([0xC0])


def test_known_vector_nested_empty_lists():
    # [ [], [[]], [ [], [[]] ] ]
    assert rlp_encode([[], [[]], [[], [[]]]]) == bytes.fromhex("c7c0c1c0c3c0c1c0")


def test_known_vector_single_byte_under_0x80_is_its_own_encoding():
    assert rlp_encode(b"\x00") == b"\x00"
    assert rlp_encode(b"\x7f") == b"\x7f"


def test_known_vector_single_byte_0x80_or_above_gets_length_prefix():
    assert rlp_encode(b"\x80") == bytes([0x81, 0x80])


# --- Malformed / non-canonical input: must refuse, never guess ---

def test_decode_rejects_empty_input():
    with pytest.raises(RlpDecodingError):
        rlp_decode(b"")


def test_decode_rejects_truncated_short_string():
    with pytest.raises(RlpDecodingError):
        rlp_decode(bytes([0x83]) + b"ca")  # claims 3 bytes, only 2 present


def test_decode_rejects_truncated_long_string():
    with pytest.raises(RlpDecodingError):
        rlp_decode(bytes([0xB8, 56]) + b"a" * 10)  # claims 56 bytes, only 10 present


def test_decode_rejects_truncated_list():
    with pytest.raises(RlpDecodingError):
        rlp_decode(bytes([0xC5]) + b"ab")  # claims 5-byte payload, only 2 present


def test_decode_rejects_trailing_bytes_in_strict_mode():
    encoded = reference_rlp.encode(b"dog")
    with pytest.raises(RlpDecodingError):
        rlp_decode(encoded + b"\xff", strict=True)


def test_decode_rejects_noncanonical_single_byte_as_short_string():
    # 0x00 encoded as [0x81, 0x00] instead of its own canonical [0x00] -- a classic
    # RLP non-canonicality attack (could let an attacker craft two different byte
    # sequences that decode to the same value, undermining the "hash the raw bytes"
    # self-validation guarantee if not rejected).
    with pytest.raises(RlpDecodingError):
        rlp_decode(bytes([0x81, 0x00]))


def test_decode_rejects_noncanonical_long_form_for_short_string():
    # A 3-byte string ("cat") encoded with the long-form (>=56) prefix machinery
    # instead of the canonical short-form prefix.
    malformed = bytes([0xB8, 0x03]) + b"cat"
    with pytest.raises(RlpDecodingError):
        rlp_decode(malformed)


def test_decode_rejects_noncanonical_long_form_for_short_list():
    malformed = bytes([0xF8, 0x00])  # long-form list prefix claiming 0-length payload
    with pytest.raises(RlpDecodingError):
        rlp_decode(malformed)


def test_decode_rejects_leading_zero_in_length_of_length():
    # Length-of-length byte(s) with a leading zero byte is non-canonical (multiple
    # byte sequences could then encode the same length).
    malformed = bytes([0xB9, 0x00, 0x38]) + b"a" * 56  # length encoded as 0x0038 instead of 0x38
    with pytest.raises(RlpDecodingError):
        rlp_decode(malformed)


def test_encode_rejects_unsupported_type():
    with pytest.raises(TypeError):
        rlp_encode(42)


def test_decode_rejects_deeply_nested_list_instead_of_recursion_error():
    """Nesting an empty list hundreds of levels deep can exhaust Python's recursion
    limit (RecursionError -- a RuntimeError, not caught by
    MalformedTransactionError/RlpDecodingError callers) if decode depth isn't
    bounded. 100 is comfortably past _MAX_DEPTH (16) while staying well short of
    where rlp_encode's own recursion would need the same guard to build this
    fixture (encode-side depth isn't attacker-controlled, since it only ever
    encodes this codebase's own fixed-shape data -- lower priority, not fixed here)."""
    nested_list = []
    for _ in range(100):
        nested_list = [nested_list]
    payload = rlp_encode(nested_list)

    with pytest.raises(RlpDecodingError, match="Nesting too deep"):
        rlp_decode(payload)


def test_decode_accepts_realistic_eip1559_access_list_nesting():
    """A real access-list entry is [address, [storage_key, ...]] inside the access
    list inside the top-level field list -- 3 levels deep. Confirms the depth limit
    doesn't reject legitimate, real-shaped transactions."""
    address = b"\x11" * 20
    storage_key = b"\x22" * 32
    access_list_entry = [address, [storage_key]]
    top_level_fields = [b"\x01", [access_list_entry]]

    encoded = rlp_encode(top_level_fields)
    assert rlp_decode(encoded) == top_level_fields


# --- Property-based tests (Hypothesis) -----------------------------------------
#
# The fixed cases/vectors above are the ones this module's own history and the RLP
# spec call out; the properties below generate inputs neither a human nor a fixed
# vector list would think to try, targeting exactly the two things that matter for
# a hand-rolled codec sitting on the signing path: (1) encode/decode is a true
# inverse of the reference `rlp` package on *arbitrary* well-formed input, not just
# the ENCODE_CASES sample, and (2) rlp_decode() never lets an adversarial byte
# string escape as anything other than RlpDecodingError -- no RecursionError,
# IndexError, MemoryError, etc., since decode() runs directly on untrusted,
# attacker-supplied transaction bytes (see module docstring).

def _rlp_items(max_depth: int):
    """Bounded-depth strategy for RlpItem (bytes | list[RlpItem]). Depth is capped
    well under _MAX_DEPTH so these trees exercise legitimate round-trips, not the
    depth-rejection path (already covered by
    test_decode_rejects_deeply_nested_list_instead_of_recursion_error above)."""
    leaf = st.binary(max_size=40)
    if max_depth <= 0:
        return leaf
    return st.one_of(leaf, st.lists(_rlp_items(max_depth - 1), max_size=4))


rlp_item_strategy = _rlp_items(max_depth=min(6, _MAX_DEPTH - 1))


@given(item=rlp_item_strategy)
@settings(max_examples=300)
def test_property_round_trip_arbitrary_items(item):
    """decode(encode(x)) == x for arbitrary bytes/nested-list shapes, not just the
    fixed ENCODE_CASES sample."""
    assert rlp_decode(rlp_encode(item)) == item


@given(item=rlp_item_strategy)
@settings(max_examples=300)
def test_property_encode_matches_reference_on_arbitrary_items(item):
    """Oracle property: our encoder must byte-for-byte match the reference `rlp`
    package on arbitrary generated input, extending the fixed ENCODE_CASES
    cross-verification to the whole input space Hypothesis can reach."""
    assert rlp_encode(item) == reference_rlp.encode(item)


@given(item=rlp_item_strategy)
@settings(max_examples=300)
def test_property_decode_matches_reference_on_arbitrary_items(item):
    encoded = reference_rlp.encode(item)
    assert rlp_decode(encoded) == reference_rlp.decode(encoded)


@given(data=st.binary(max_size=300))
@settings(max_examples=500)
def test_property_decode_never_crashes_on_arbitrary_bytes(data):
    """The core 'never crashes on adversarial input' property for a codec that
    parses untrusted, attacker-supplied signing-request bytes: rlp_decode() on any
    byte string must either succeed or raise RlpDecodingError -- never an
    unhandled RecursionError/IndexError/MemoryError/etc. that would bypass every
    MalformedTransactionError/RlpDecodingError handler upstream (transaction.py,
    plugin.py) and crash the signing flow instead of cleanly refusing to sign."""
    try:
        rlp_decode(data)
    except RlpDecodingError:
        pass


@given(data=st.binary(max_size=300))
@settings(max_examples=500)
def test_property_non_strict_decode_never_crashes_on_arbitrary_bytes(data):
    """Same crash-safety property for strict=False (accepts trailing bytes) -- the
    other mode _decode_one/_decode_list_payload must stay safe under, even though
    this codebase's own call sites always use strict=True."""
    try:
        rlp_decode(data, strict=False)
    except RlpDecodingError:
        pass


@given(item=rlp_item_strategy)
@settings(max_examples=200)
def test_property_reencoding_a_decoded_item_is_idempotent(item):
    """encode(decode(encode(x))) == encode(x): re-serializing a value round-tripped
    through our own decoder always reproduces the same canonical bytes."""
    encoded = rlp_encode(item)
    decoded = rlp_decode(encoded)
    assert rlp_encode(decoded) == encoded
