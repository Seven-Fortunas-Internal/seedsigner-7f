"""
    Narrow, self-validating ERC-20 calldata decoder -- rollout Phase 4. Deliberately
    NOT a general-purpose ABI decoder: recognizes exactly the two function selectors
    this device knows how to fully explain to the operator (transfer, approve), each
    with exactly the fixed (address, uint256) calldata layout those functions use, and
    refuses -- returns None, caller falls back to raw-calldata display -- for anything
    else, rather than guessing. A narrow, exact-shape decoder is a smaller attack
    surface than a general one that might successfully "decode" an attacker-crafted or
    malformed layout in some unintended way (docs/multi-chain/README.md's
    self-validation principle).
"""
from .crypto import address_bytes_to_checksum

# Verified against keccak256(b"transfer(address,uint256)")[:4] etc. in
# tests/test_evm_erc20.py -- not just transcribed from memory.
SELECTOR_TRANSFER = bytes.fromhex("a9059cbb")
SELECTOR_APPROVE = bytes.fromhex("095ea7b3")

_SELECTOR_TO_FUNCTION = {
    SELECTOR_TRANSFER: "transfer",
    SELECTOR_APPROVE: "approve",
}

UINT256_MAX = 2**256 - 1


class Erc20Call:
    __slots__ = ("function", "recipient_or_spender", "amount")

    def __init__(self, function: str, recipient_or_spender: str, amount: int):
        self.function = function                    # "transfer" | "approve"
        self.recipient_or_spender = recipient_or_spender  # EIP-55 checksum address
        self.amount = amount                         # raw token units (not decimals-adjusted)

    @property
    def is_unlimited_approval(self) -> bool:
        return self.function == "approve" and self.amount == UINT256_MAX


def decode_erc20_call(data: bytes) -> Erc20Call | None:
    """Returns None if `data` doesn't match a recognized selector + exact layout --
    callers must fall back to an "unrecognized contract call" display, never guess
    at a wider or narrower interpretation."""
    if len(data) != 4 + 32 + 32:
        return None

    function = _SELECTOR_TO_FUNCTION.get(data[:4])
    if function is None:
        return None

    address_word, amount_word = data[4:36], data[36:68]
    # The address is right-aligned in its 32-byte word; a nonzero high 12 bytes
    # doesn't match ABI's standard zero-padding for a 20-byte value and is refused
    # rather than silently masked off (could otherwise hide a crafted high word).
    if any(address_word[:12]):
        return None

    address = address_bytes_to_checksum(address_word[12:])
    amount = int.from_bytes(amount_word, "big")
    return Erc20Call(function, address, amount)
