"""
    Real EIP-1559 (type-0x02) transaction decode + signing-hash -- rollout Phase 4.

    Self-validation first (docs/multi-chain/README.md): the signing hash is always
    computed from the exact raw bytes this device received over the QR/UR transport,
    never from a re-encoding of the fields decoded below -- so decode and hash can
    never silently disagree with each other, and a malformed field can never produce
    a "valid-looking" signature over something other than what was actually received.

    Wire shape (EIP-2718/2930/1559), unsigned form:
        0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
                     gas_limit, to, value, data, access_list])
    This device only ever produces (r, s, y_parity) -- see EvmPlugin.sign() -- and
    never assembles the final signed transaction itself; that's the companion tool's
    job (keeps the on-device signing primitive narrow, per the wallet-survey finding
    in docs/multi-chain/README.md).
"""
import rlp

from .crypto import address_bytes_to_checksum, keccak256

TX_TYPE_EIP1559 = 0x02
_UNSIGNED_FIELD_COUNT = 9


class MalformedTransactionError(ValueError):
    """Raised for anything that doesn't match the expected wire shape exactly --
    callers must refuse to sign, never guess at a best-effort interpretation."""


def _decode_uint(field: bytes) -> int:
    return int.from_bytes(field, "big") if field else 0


class UnsignedEip1559Transaction:
    def __init__(self, raw_unsigned_payload: bytes):
        if not raw_unsigned_payload:
            raise MalformedTransactionError("Empty payload")
        if raw_unsigned_payload[0] != TX_TYPE_EIP1559:
            raise MalformedTransactionError(
                f"Expected EIP-1559 (type 0x02) transaction, got type byte "
                f"0x{raw_unsigned_payload[0]:02x}")

        self.raw_unsigned_payload = raw_unsigned_payload

        try:
            fields = rlp.decode(raw_unsigned_payload[1:], strict=True)
        except Exception as e:
            raise MalformedTransactionError(f"RLP decode failed: {e}") from e

        if not isinstance(fields, list) or len(fields) != _UNSIGNED_FIELD_COUNT:
            raise MalformedTransactionError(
                f"Expected {_UNSIGNED_FIELD_COUNT} unsigned-tx fields, got "
                f"{len(fields) if isinstance(fields, list) else type(fields).__name__}")

        (chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit,
         to, value, data, access_list) = fields

        if len(to) != 20:
            raise MalformedTransactionError(f"'to' must be 20 bytes, got {len(to)}")

        self.chain_id = _decode_uint(chain_id)
        self.nonce = _decode_uint(nonce)
        self.max_priority_fee_per_gas = _decode_uint(max_priority_fee_per_gas)
        self.max_fee_per_gas = _decode_uint(max_fee_per_gas)
        self.gas_limit = _decode_uint(gas_limit)
        self.to = bytes(to)
        self.value = _decode_uint(value)
        self.data = bytes(data)
        # A non-empty access list is unusual for a plain transfer/ERC-20 call and
        # isn't interpreted further here -- surfaced as a count so a reviewer at
        # least sees it's non-default, rather than it being silently dropped.
        self.access_list_entry_count = len(access_list)

    @property
    def to_checksum_address(self) -> str:
        return address_bytes_to_checksum(self.to)

    def signing_hash(self) -> bytes:
        return keccak256(self.raw_unsigned_payload)
