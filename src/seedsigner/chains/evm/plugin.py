"""
    EVM chain plugin. Rollout Phase 2-4 (see docs/multi-chain/evm-test-plan.md):

    - Address derivation is real (chains/evm/crypto.py): BIP-32/secp256k1 HD
      derivation, Keccak-256/EIP-55 checksum addresses.
    - Real on-chain transactions (a plain ETH transfer, or an ERC-20 transfer/approve
      call) are now fully real too: parse_sign_request() decodes actual EIP-1559 RLP
      transaction bytes (chains/evm/transaction.py) and ERC-20 calldata
      (chains/evm/erc20.py), and sign() computes the real signing hash from those same
      raw bytes and signs it for real (chains/evm/crypto.py). Self-validation
      throughout: every displayed field and the signing hash both come from the raw
      payload bytes directly, never from each other or from a separately-supplied
      label (docs/multi-chain/README.md).
    - `permit` (EIP-712 off-chain signature) is still Phase 1 -- hand-built JSON, fake
      signature. Deferred deliberately: unlike an on-chain tx, a permit's EIP-712
      domain (token name/version/verifying-contract) is supplied out-of-band by
      whatever built the request, and an airgapped device has no live way to confirm
      it matches the real token contract -- that's a genuine self-validation gap, not
      just unfinished plumbing, and needs its own design pass before real signing.
    - "First-time address" is still a static per-request flag, not real seen-before
      memory -- deferred; would need either a chain-agnostic kernel component or a
      privacy call on what SeedSigner's amnesiac-by-design model should persist.

    The demo scenarios below still map 1:1 to docs/multi-chain/research/anti-scam-ux.md's
    findings (permit/approval-phishing majority of documented large thefts) -- transfer
    and approve_unlimited are now real RLP-encoded EIP-1559 transactions with example
    field values; permit stays the Phase 1 JSON mock.
"""
import json
import os

from seedsigner.chains.base import Address, ParsedRequest, ReviewField, Signature

from .constants import KNOWN_TOKENS, NETWORKS_BY_CHAIN_ID, NETWORKS_BY_ID
from .crypto import derive_private_key, private_key_to_checksum_address, sign_hash_recoverable
from .erc20 import UINT256_MAX, decode_erc20_call
from .transaction import TX_TYPE_EIP1559, MalformedTransactionError, UnsignedEip1559Transaction
from .units import format_units

# Standard Ethereum BIP-44 path: m/44'/60'/{account}'/0/{index}.
DERIVATION_PATH_TEMPLATE = "m/44'/60'/{account}'/0/{index}"

_DEMO_TO_ADDRESS = "0x4A3F9c8e1b2D7A6F5e0C9b8A7D6e5f4c3B2a1908"
_DEMO_USDC_OPTIMISM_SEPOLIA = "0x5fd84259d66Cd46123540766Be93DFE6D43130D7"
_DEMO_APPROVE_SPENDER = "0x7F1A2e3d4C5B6a7988776655443322112233eEDC"


def _rlp_encode_unsigned_tx(chain_id, nonce, max_priority_fee, max_fee, gas_limit, to_hex, value, data) -> bytes:
    """Builds a real, well-formed unsigned EIP-1559 payload for the demo scenarios --
    same wire format a real companion tool would produce, so the demo menu exercises
    the exact same decode/sign path a real scan would (see module docstring)."""
    import rlp as _rlp

    def _uint(n: int) -> bytes:
        return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""

    fields = [
        _uint(chain_id), _uint(nonce), _uint(max_priority_fee), _uint(max_fee),
        _uint(gas_limit), bytes.fromhex(to_hex[2:]), _uint(value), data, [],
    ]
    return bytes([TX_TYPE_EIP1559]) + _rlp.encode(fields)


def _erc20_calldata(selector: bytes, address_hex: str, amount: int) -> bytes:
    return selector + b"\x00" * 12 + bytes.fromhex(address_hex[2:]) + amount.to_bytes(32, "big")


# Demo sign-request payloads. transfer/approve_unlimited/usdc_transfer are real
# RLP-encoded EIP-1559 transactions (fake field values, real wire format); permit is
# still Phase 1 JSON -- see module docstring for why. Each hardcodes nonce=0 or 1,
# meaning it's only signable once per fresh (never-transacted) account -- see
# docs/multi-chain/evm-hardware-walkthrough.md for how these get used for real.
DEMO_SCENARIOS: dict[str, bytes] = {
    "transfer": _rlp_encode_unsigned_tx(
        chain_id=11155420, nonce=0, max_priority_fee=1_000_000_000, max_fee=2_000_000_000,
        gas_limit=21_000, to_hex=_DEMO_TO_ADDRESS, value=50_000_000_000_000_000, data=b"",
    ),
    "approve_unlimited": _rlp_encode_unsigned_tx(
        chain_id=11155420, nonce=1, max_priority_fee=1_000_000_000, max_fee=2_000_000_000,
        gas_limit=60_000, to_hex=_DEMO_USDC_OPTIMISM_SEPOLIA, value=0,
        data=_erc20_calldata(bytes.fromhex("095ea7b3"), _DEMO_APPROVE_SPENDER, UINT256_MAX),
    ),
    "usdc_transfer": _rlp_encode_unsigned_tx(
        # nonce=0 -- a real ERC-20 token send, meant to be run on its own fresh
        # account (see the walkthrough doc) rather than needing to follow "transfer"
        # in a fixed sequence. It does NOT reuse "transfer"'s nonce-0 account: both
        # scenarios independently assume nonce 0, so running this on an account
        # that already ran "transfer" (now at nonce 1) will fail loudly with a
        # nonce-too-low RPC error, not silently misbehave.
        chain_id=11155420, nonce=0, max_priority_fee=1_000_000_000, max_fee=2_000_000_000,
        gas_limit=60_000, to_hex=_DEMO_USDC_OPTIMISM_SEPOLIA, value=0,
        data=_erc20_calldata(bytes.fromhex("a9059cbb"), _DEMO_TO_ADDRESS, 1_000_000),  # 1.0 USDC (6 decimals)
    ),
    "permit": json.dumps({
        "operation": "permit",
        "network_id": "optimism-sepolia",
        "token_symbol": "USDC",
        "counterparty": "0x99887766554433221100ffeeddccbbaa9988776",
        "amount": "1,000,000 USDC",
        "deadline": "2026-09-05 12:00 UTC",
        "is_first_time_address": True,
        "derivation_path": DERIVATION_PATH_TEMPLATE.format(account=0, index=0),
    }).encode(),
}


class EvmPlugin:
    chain_id = "evm"
    display_name = "Ethereum / EVM"

    def derive_address(self, seed_bytes: bytes, path: str) -> Address:
        # seed_bytes already has any BIP-39 passphrase mixed in (Seed.seed_bytes) --
        # honored as-is, the standard behavior for EVM (see crypto.py's module
        # docstring for why this differs from the paused 7F work's refusal).
        private_key = derive_private_key(seed_bytes, path)
        return Address(
            path=path,
            address=private_key_to_checksum_address(private_key),
            network_name="",  # caller (view layer) knows which network was selected
        )

    def parse_sign_request(self, payload: bytes) -> ParsedRequest:
        # The leading type byte distinguishes a real transaction from the still-mocked
        # permit JSON -- not a heuristic guess: 0x02 is EIP-1559's own real wire-format
        # type tag (EIP-2718), and JSON payloads always start with '{' (0x7b).
        if payload[:1] == bytes([TX_TYPE_EIP1559]):
            return self._parse_transaction(payload)
        return self._parse_permit_demo(payload)

    def _parse_transaction(self, payload: bytes) -> ParsedRequest:
        try:
            tx = UnsignedEip1559Transaction(payload)
        except MalformedTransactionError as e:
            raise ValueError(f"Cannot sign: {e}") from e

        # ParsedRequest.derivation_path is left "" below -- a real transaction carries
        # no such field; which account to sign with is the wallet's own choice, made
        # by the caller before/independent of parsing (views/evm_views.py). Only the
        # still-JSON permit demo below still threads a path through the payload.
        network = NETWORKS_BY_CHAIN_ID.get(tx.chain_id)
        # Self-validation: the network shown is recomputed from the tx's own chain_id
        # field, never a separately-claimed label -- an unrecognized chain_id is
        # surfaced as a warning, not silently hidden behind a blank/guessed name.
        network_name = network.display_name if network else f"Unrecognized chain (id {tx.chain_id})"
        fields: list[ReviewField] = [ReviewField(
            "Network", network_name,
            is_warning=network is None,
            warning_detail="" if network else
                "This transaction claims a chain ID this device doesn't recognize. "
                "Do not sign unless you expect this network.",
        )]

        if tx.access_list_entry_count:
            # Not normal for a plain transfer/ERC-20 call -- surfaced rather than
            # silently accepted (an access list mainly affects gas metering/address
            # pre-warming, not fund movement on its own, so this is a lower-severity
            # flag than the amount/address fields above).
            fields.append(ReviewField(
                "Access list", f"{tx.access_list_entry_count} entries",
                is_warning=True,
                warning_detail="This transaction declares an access list, which is "
                                "unusual for a plain transfer or token call. Confirm "
                                "this is expected before signing.",
            ))

        if not tx.data:
            fields.append(ReviewField("Operation", "Transfer"))
            fields.append(ReviewField("Amount", f"{format_units(tx.value, 18)} ETH"))
            fields.append(ReviewField("To", tx.to_checksum_address))
            # Deferred (see module docstring): a real "seen before" memory. Every
            # address is currently flagged, matching the Phase 1 demo's own
            # (also-static) behavior.
            fields.append(ReviewField(
                "First-time address", "Not seen before on this device",
                is_warning=True,
                warning_detail="Double-check this address carefully -- lookalike "
                                "addresses in transaction history are a documented "
                                "scam pattern.",
            ))
            return ParsedRequest("Transfer", network_name, "", fields)

        call = self._require_recognized_erc20_call(tx)

        token = KNOWN_TOKENS.get((tx.chain_id, tx.to_checksum_address))
        token_label = token.symbol if token else f"Unknown token ({tx.to_checksum_address})"
        token_field = ReviewField(
            "Token", token_label,
            is_warning=token is None,
            warning_detail="" if token else "Unrecognized contract -- verify independently.",
        )

        if tx.value != 0:
            # Self-validation gap this closes: transfer()/approve() calldata carries
            # its own amount, but the tx's own `value` field -- native ETH attached to
            # the SAME signed transaction -- is separate and easy to overlook if only
            # the calldata-derived amount is shown. Not normal for either call; flagged
            # rather than silently signed.
            fields.append(ReviewField(
                "Value (native ETH)", f"{format_units(tx.value, 18)} ETH",
                is_warning=True,
                warning_detail="Sends ETH alongside the token call -- unusual. "
                                "Confirm this is expected.",
            ))

        if call.function == "transfer":
            fields.append(ReviewField("Operation", "Token Transfer"))
            # Always its own field -- for a known token this is just the symbol; for
            # an unknown one it's the contract address, which must be checkable on
            # its own line, not only buried inside a warning sentence (a real
            # overflow bug on this exact screen, caught by screenshot rendering).
            fields.append(token_field)
            fields.append(self._amount_field(call.amount, token))
            fields.append(ReviewField("To", call.recipient_or_spender))
        else:  # "approve"
            fields.append(ReviewField("Operation", "Token Approval"))
            fields.append(token_field)
            fields.append(ReviewField("Spender", call.recipient_or_spender))
            if call.is_unlimited_approval:
                # Anti-scam research: unlimited approvals are the single largest
                # documented loss category -- hard-stop warning, not a footnote.
                fields.append(ReviewField(
                    "Amount", "UNLIMITED",
                    is_warning=True,
                    # Doesn't repeat token_label here -- "Token" is already its own
                    # field, and for an unrecognized contract that label can be a
                    # full address, long enough to overflow this screen (a real bug
                    # caught by screenshot rendering -- see _amount_field's warning).
                    warning_detail="Grants the spender permission to move ALL of "
                                    "this token, forever, until revoked.",
                ))
            else:
                fields.append(self._amount_field(call.amount, token))

        fields.append(ReviewField(
            "First-time address", "Not seen before on this device",
            is_warning=True,
            warning_detail="Double-check this address carefully -- lookalike "
                            "addresses in transaction history are a documented "
                            "scam pattern.",
        ))
        operation = "Token Transfer" if call.function == "transfer" else "Token Approval"
        return ParsedRequest(operation, network_name, "", fields)

    @staticmethod
    def _require_recognized_erc20_call(tx: UnsignedEip1559Transaction):
        """Shared by _parse_transaction() and sign() -- the refusal must be
        structurally guaranteed on both paths, not just on whichever one a caller
        happens to call first. A caller that signed via sign() without going through
        parse_sign_request() first (e.g. a future scan entry point with its own
        review flow) must get the exact same refusal, not a silently-signed
        unrecognized call."""
        call = decode_erc20_call(tx.data)
        if call is None:
            # Blind-signing off by default (docs/multi-chain/README.md): an
            # unrecognized contract call is refused outright in this rollout phase,
            # not shown-with-a-warning. Revisit once there's a real "raw calldata,
            # explicit override" review path.
            raise ValueError(
                "Cannot sign: unrecognized contract call. This device only "
                "understands plain ETH transfers and ERC-20 transfer/approve calls.")
        return call

    @staticmethod
    def _amount_field(raw_amount: int, token) -> ReviewField:
        if token:
            return ReviewField("Amount", f"{format_units(raw_amount, token.decimals)} {token.symbol}")
        # No bundled decimals/symbol for this contract -- show the raw amount rather
        # than guess at a decimals value (docs/multi-chain/README.md: a token's
        # decimals aren't recoverable from calldata alone). The contract address
        # itself is already its own "Token" field -- not repeated here.
        return ReviewField(
            "Amount", f"{raw_amount} (raw units)",
            is_warning=True,
            warning_detail="Unrecognized token -- verify its symbol and decimals "
                            "independently before trusting this amount.",
        )

    def _parse_permit_demo(self, payload: bytes) -> ParsedRequest:
        """Still Phase 1: hand-built JSON, not a real EIP-712 typed-data payload --
        see module docstring for why permit's real implementation is deferred."""
        data = json.loads(payload)
        network_name = NETWORKS_BY_ID[data["network_id"]].display_name

        fields: list[ReviewField] = [
            ReviewField("Operation", "Permit (off-chain signature)"),
            ReviewField("Network", network_name),
            ReviewField("Token", data["token_symbol"]),
            ReviewField("Spender", data["counterparty"]),
            ReviewField("Amount", data["amount"]),
            ReviewField("Deadline", data["deadline"]),
        ]
        # Anti-scam research: permit/Permit2 phishing is an off-chain EIP-712
        # signature, not an on-chain tx -- free for the attacker, drains on their own
        # schedule, and the single biggest documented attack category.
        fields.append(ReviewField(
            "Off-chain signature", "No gas, no on-chain trace",
            is_warning=True,
            warning_detail="This is a signature, not a transaction. The spender "
                            "can execute it whenever they choose -- it costs "
                            "nothing to hold and nothing to use.",
        ))
        if data.get("is_first_time_address"):
            fields.append(ReviewField(
                "First-time address", "Not seen before on this device",
                is_warning=True,
                warning_detail="Double-check this address carefully -- lookalike "
                                "addresses in transaction history are a documented "
                                "scam pattern.",
            ))

        return ParsedRequest("Permit (off-chain signature)", network_name, data["derivation_path"], fields)

    def review_fields(self, parsed: ParsedRequest) -> list[ReviewField]:
        return parsed.review_fields

    def sign(self, seed_bytes: bytes, path: str, payload: bytes) -> Signature:
        if payload[:1] == bytes([TX_TYPE_EIP1559]):
            try:
                tx = UnsignedEip1559Transaction(payload)
            except MalformedTransactionError as e:
                raise ValueError(f"Cannot sign: {e}") from e
            if tx.data:
                # Same refusal parse_sign_request() applies -- enforced here too, not
                # just relied on from the caller, so sign() can never be used to sign
                # an unrecognized contract call that a review screen never showed.
                self._require_recognized_erc20_call(tx)
            private_key = derive_private_key(seed_bytes, path)
            r, s, y_parity = sign_hash_recoverable(private_key, tx.signing_hash())
            return Signature(signature_bytes=r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([y_parity]))

        # permit -- still Phase 1, fake signature (see module docstring).
        return Signature(signature_bytes=os.urandom(65))

    def encode_response(self, signature: Signature) -> bytes:
        return signature.signature_bytes.hex().encode()
