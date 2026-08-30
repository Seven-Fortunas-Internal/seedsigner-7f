"""
    EVM chain plugin -- Phase 1 (UI-walkthrough demo): mocked address derivation and
    signing, real review-field logic. Matches the 7F work's own Phase 1 scope (see
    docs/7f-integration/README.md's "Phased rollout") -- no real BIP-32/secp256k1/
    Keccak-256 derivation yet, no real RLP/ABI transaction parsing yet. That's
    deliberate: this phase exists to get the actual review screens in front of a
    reviewer on real hardware before any backend work is invested, per the
    no-blind-signing principle.

    The three demo sign-request scenarios below aren't arbitrary -- they were chosen
    directly from docs/multi-chain/research/anti-scam-ux.md's findings: permit/
    approval-phishing patterns account for the majority of documented large wallet
    thefts, so the review-field/warning logic here is the real design under test, even
    though the underlying transaction data is fake.
"""
import hashlib
import json
import os

from seedsigner.chains.base import Address, ParsedRequest, ReviewField, Signature

from .constants import NETWORKS_BY_ID

# Standard Ethereum BIP-44 path: m/44'/60'/{account}'/0/{index}. Real for the address
# path shape; the *derivation math* (secp256k1 HD + Keccak-256) is not implemented in
# Phase 1 -- see derive_address() below.
DERIVATION_PATH_TEMPLATE = "m/44'/60'/{account}'/0/{index}"


def _mock_evm_address(seed_bytes: bytes, path: str) -> str:
    """
        Deterministic PLACEHOLDER address for the Phase 1 UI demo only -- NOT a real
        Ethereum address (real derivation is secp256k1 pubkey -> Keccak-256 -> last 20
        bytes -> EIP-55 checksum casing, none of which is implemented yet). Same
        pattern as the 7F work's _mock_sevenf_address: deterministic per (seed, path)
        so re-visiting the same screen shows a stable value, matching what a real
        address would do.
    """
    digest = hashlib.sha256(seed_bytes + path.encode()).hexdigest()
    return "0x" + digest[:40]


# Demo sign-request payloads, pre-serialized as JSON bytes to keep parse_sign_request's
# real signature (bytes in, not a dict) -- swapping in real ABI/RLP decoding later
# shouldn't require changing this method's shape.
DEMO_SCENARIOS: dict[str, bytes] = {
    "transfer": json.dumps({
        "operation": "transfer",
        "network_id": "base",
        "amount": "0.05 ETH",
        "counterparty": "0x4a3f9c8e1b2d7a6f5e0c9b8a7d6e5f4c3b2a1908",
        "is_first_time_address": True,
        "derivation_path": DERIVATION_PATH_TEMPLATE.format(account=0, index=0),
    }).encode(),
    "approve_unlimited": json.dumps({
        "operation": "approve",
        "network_id": "ethereum",
        "token_symbol": "USDC",
        "counterparty": "0x7f1a2e3d4c5b6a798877665544332211ffeeddc",
        "amount": "UNLIMITED",
        "is_first_time_address": True,
        "derivation_path": DERIVATION_PATH_TEMPLATE.format(account=0, index=0),
    }).encode(),
    "permit": json.dumps({
        "operation": "permit",
        "network_id": "optimism",
        "token_symbol": "USDT",
        "counterparty": "0x99887766554433221100ffeeddccbbaa9988776",
        "amount": "1,000,000 USDT",
        "deadline": "2026-09-05 12:00 UTC",
        "is_first_time_address": True,
        "derivation_path": DERIVATION_PATH_TEMPLATE.format(account=0, index=0),
    }).encode(),
}

_OPERATION_DISPLAY_NAMES = {
    "transfer": "Transfer",
    "approve": "Token Approval",
    "permit": "Permit (off-chain signature)",
}


class EvmPlugin:
    chain_id = "evm"
    display_name = "Ethereum / EVM"

    def derive_address(self, seed_bytes: bytes, path: str) -> Address:
        return Address(
            path=path,
            address=_mock_evm_address(seed_bytes, path),
            network_name="",  # caller (view layer) knows which network was selected
        )

    def parse_sign_request(self, payload: bytes) -> ParsedRequest:
        data = json.loads(payload)
        network = NETWORKS_BY_ID[data["network_id"]]
        operation = data["operation"]

        fields: list[ReviewField] = [
            ReviewField("Operation", _OPERATION_DISPLAY_NAMES[operation]),
            ReviewField("Network", f"{network.display_name} (chain {network.chain_id})"),
        ]

        if operation == "transfer":
            fields.append(ReviewField("Amount", data["amount"]))
            fields.append(ReviewField("To", data["counterparty"]))

        elif operation == "approve":
            fields.append(ReviewField("Token", data["token_symbol"]))
            fields.append(ReviewField("Spender", data["counterparty"]))
            if data["amount"] == "UNLIMITED":
                # Anti-scam research: unlimited approvals are the single largest
                # documented loss category (permit/Permit2/approve combined majority
                # of large 2024 thefts, research/anti-scam-ux.md) -- hard-stop
                # warning, not a footnote.
                fields.append(ReviewField(
                    "Amount", "UNLIMITED",
                    is_warning=True,
                    warning_detail="Grants the spender permission to move ALL your "
                                    f"{data['token_symbol']}, forever, until revoked.",
                ))
            else:
                fields.append(ReviewField("Amount", data["amount"]))

        elif operation == "permit":
            fields.append(ReviewField("Token", data["token_symbol"]))
            fields.append(ReviewField("Spender", data["counterparty"]))
            fields.append(ReviewField("Amount", data["amount"]))
            fields.append(ReviewField("Deadline", data["deadline"]))
            # Anti-scam research: permit/Permit2 phishing is an off-chain EIP-712
            # signature, not an on-chain tx -- free for the attacker, drains on their
            # own schedule, and the single biggest documented attack category.
            fields.append(ReviewField(
                "Off-chain signature", "No gas, no on-chain trace",
                is_warning=True,
                warning_detail="This is a signature, not a transaction. The spender "
                                "can execute it whenever they choose -- it costs "
                                "nothing to hold and nothing to use.",
            ))

        if data.get("is_first_time_address"):
            # Best on-device substitute for live threat-intel an airgapped device
            # can't call out to (research/anti-scam-ux.md) -- directly counters
            # address-poisoning and drainer-kit patterns.
            fields.append(ReviewField(
                "First-time address", "Not seen before on this device",
                is_warning=True,
                warning_detail="Double-check this address carefully -- lookalike "
                                "addresses in transaction history are a documented "
                                "scam pattern.",
            ))

        return ParsedRequest(
            operation=_OPERATION_DISPLAY_NAMES[operation],
            network_name=network.display_name,
            derivation_path=data["derivation_path"],
            review_fields=fields,
        )

    def review_fields(self, parsed: ParsedRequest) -> list[ReviewField]:
        return parsed.review_fields

    def sign(self, seed_bytes: bytes, path: str, payload: bytes) -> Signature:
        # FAKE signature -- os.urandom, not real ECDSA. No crypto core exists yet
        # (rollout Phase 2+, matching the 7F work's own phasing).
        return Signature(signature_bytes=os.urandom(65))

    def encode_response(self, signature: Signature) -> bytes:
        return signature.signature_bytes.hex().encode()
