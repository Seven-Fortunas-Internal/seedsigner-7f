"""
    Minimal RLP (Recursive Length Prefix) encode/decode -- just enough to build and
    parse an EIP-1559 transaction's field list (chains/evm/transaction.py), nothing
    more general. Replaces the third-party `rlp` PyPI package as a *runtime*
    dependency: `rlp` itself is pure Python, but its transitive dependency chain
    (eth-utils -> cytoolz, a C extension; eth-typing -> pydantic -> pydantic-core, a
    Rust extension) would require authoring several new cross-compiled Buildroot
    packages to ship on real SeedSigner OS hardware, for a library we only use this
    narrowly. A small, self-contained codec is both less work to ship and a smaller
    trusted dependency surface for security-critical signing code -- worth it even
    though it means maintaining ~50 lines of encoding logic ourselves.

    `rlp` stays a test-only dependency (tests/requirements.txt) for cross-verifying
    this module against the reference implementation -- see test_evm_rlp_codec.py.

    Spec: https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
    Only byte strings and lists of encodable items are supported (no integers, no
    sedes) -- callers convert ints to minimal big-endian bytes themselves (see
    chains/evm/transaction.py's/plugin.py's `_uint` helpers), matching how this
    codebase already called the `rlp` package.
"""
from typing import Union

RlpItem = Union[bytes, list["RlpItem"]]

# A real EIP-1559 unsigned tx nests at most ~3 deep (field list -> access list ->
# one entry's [address, storage_keys]). 16 is generous headroom for that while still
# tightly bounding a malicious deeply-nested payload -- without this, a few KB of
# attacker-controlled input can exhaust Python's recursion limit (RecursionError,
# a RuntimeError -- not caught by any MalformedTransactionError/RlpDecodingError
# handler) instead of cleanly refusing to decode. Found by a code-review pass.
_MAX_DEPTH = 16


class RlpDecodingError(ValueError):
    pass


def _encode_length(length: int, offset: int) -> bytes:
    if length < 56:
        return bytes([offset + length])
    length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(length_bytes)]) + length_bytes


def rlp_encode(item: RlpItem) -> bytes:
    if isinstance(item, (bytes, bytearray)):
        data = bytes(item)
        if len(data) == 1 and data[0] < 0x80:
            return data
        return _encode_length(len(data), 0x80) + data

    if isinstance(item, list):
        payload = b"".join(rlp_encode(child) for child in item)
        return _encode_length(len(payload), 0xC0) + payload

    raise TypeError(f"rlp_encode only supports bytes and lists, got {type(item).__name__}")


def _decode_length(data: bytes, offset: int) -> tuple[int, int]:
    """Returns (length_of_length_bytes, actual_length) for a long-form prefix at
    data[0], where data[0] - offset - 55 is the number of following bytes that
    encode the real length."""
    length_of_length = data[0] - offset - 55
    if len(data) < 1 + length_of_length:
        raise RlpDecodingError("Truncated length-of-length prefix")
    length_bytes = data[1:1 + length_of_length]
    if length_bytes and length_bytes[0] == 0:
        raise RlpDecodingError("Non-canonical RLP: length-of-length has a leading zero byte")
    return length_of_length, int.from_bytes(length_bytes, "big")


def _decode_one(data: bytes, depth: int) -> tuple[RlpItem, bytes]:
    """Decodes exactly one RLP item from the front of `data`, returning
    (decoded_item, remaining_bytes). `depth` counts list nesting so far -- see
    _MAX_DEPTH."""
    if depth > _MAX_DEPTH:
        raise RlpDecodingError(f"Nesting too deep (> {_MAX_DEPTH} levels)")

    if not data:
        raise RlpDecodingError("Unexpected end of input")

    prefix = data[0]

    if prefix < 0x80:
        return bytes([prefix]), data[1:]

    if prefix < 0xB8:
        length = prefix - 0x80
        if len(data) < 1 + length:
            raise RlpDecodingError("Truncated short byte-string")
        value = data[1:1 + length]
        if length == 1 and value[0] < 0x80:
            raise RlpDecodingError("Non-canonical RLP: single byte < 0x80 encoded as a string")
        return value, data[1 + length:]

    if prefix < 0xC0:
        length_of_length, length = _decode_length(data, 0x80)
        start = 1 + length_of_length
        if length < 56:
            raise RlpDecodingError("Non-canonical RLP: long-form used for a short string")
        if len(data) < start + length:
            raise RlpDecodingError("Truncated long byte-string")
        return data[start:start + length], data[start + length:]

    if prefix < 0xF8:
        length = prefix - 0xC0
        if len(data) < 1 + length:
            raise RlpDecodingError("Truncated short list")
        payload, remainder = data[1:1 + length], data[1 + length:]
        return _decode_list_payload(payload, depth + 1), remainder

    length_of_length, length = _decode_length(data, 0xC0)
    start = 1 + length_of_length
    if length < 56:
        raise RlpDecodingError("Non-canonical RLP: long-form used for a short list")
    if len(data) < start + length:
        raise RlpDecodingError("Truncated long list")
    payload, remainder = data[start:start + length], data[start + length:]
    return _decode_list_payload(payload, depth + 1), remainder


def _decode_list_payload(payload: bytes, depth: int) -> list:
    items = []
    while payload:
        item, payload = _decode_one(payload, depth)
        items.append(item)
    return items


def rlp_decode(data: bytes, strict: bool = True) -> RlpItem:
    """strict=True (the only mode this codebase uses -- matches every call site's
    existing `rlp.decode(data, strict=True)`): raise if there are trailing bytes
    after the single top-level item, instead of silently ignoring them."""
    item, remainder = _decode_one(bytes(data), depth=0)
    if strict and remainder:
        raise RlpDecodingError(f"{len(remainder)} trailing byte(s) after the decoded item")
    return item
