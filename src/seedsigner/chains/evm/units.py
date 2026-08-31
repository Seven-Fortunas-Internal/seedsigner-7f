"""
    Integer-only amount formatting -- rollout Phase 4. No floating point anywhere:
    a float can't exactly represent most base-10 fractions in base-2, and this is
    exactly the kind of silent precision loss the no-blind-signing principle exists to
    prevent (an operator must see the *real* amount, not a rounded approximation).
"""


def format_units(amount: int, decimals: int) -> str:
    """amount is in the smallest unit (wei for ETH, raw token units for an ERC-20).
    decimals is a protocol/token constant (18 for ETH, always; a token's own decimals
    for ERC-20 -- see constants.KNOWN_TOKENS), not something read from the payload."""
    if amount < 0:
        raise ValueError("amount must not be negative")
    if decimals == 0:
        return str(amount)

    divisor = 10 ** decimals
    whole, remainder = divmod(amount, divisor)
    if remainder == 0:
        return str(whole)

    fraction = str(remainder).rjust(decimals, "0").rstrip("0")
    return f"{whole}.{fraction}"
